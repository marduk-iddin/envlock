//! Keychain backend. The ONLY platform-specific code in the project:
//! calls into Apple's Security framework on macOS, a stub elsewhere.
//!
//! Items are stored as generic passwords:
//!   service = "envlock-<namespace>", account = "<unix username>".
//!
//! By default no trusted-application list is pre-authorized, but macOS
//! auto-trusts the *creating* binary — so envlock's own later reads of
//! an item it created are silent, no dialog, no "Always Allow" needed.
//! `set --require-passphrase` opts a namespace out of that: it attaches
//! a `SecAccessControl` instead of the legacy ACL, which has no concept
//! of a trusted-app list at all, so every read prompts for Touch ID /
//! device passcode, permanently, with nothing to accidentally click
//! "Always Allow" on.

pub const NOT_FOUND: &str = "__envlock_not_found__";

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::{CFTypeRef, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::passwords::{delete_generic_password, get_generic_password};
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
    use security_framework_sys::base::errSecDuplicateItem;
    use security_framework_sys::item::kSecValueData;
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemUpdate};

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    fn account() -> String {
        std::env::var("USER").unwrap_or_else(|_| "envlock".to_string())
    }

    /// Ok(Some(blob)) — found; Ok(None) — no such item; Err — real error.
    pub fn read(service: &str) -> Result<Option<Vec<u8>>, String> {
        match get_generic_password(service, &account()) {
            Ok(blob) => Ok(Some(blob)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(format!("keychain read failed: {e}")),
        }
    }

    /// Write (create or update) a generic password.
    ///
    /// `require_passphrase` attaches a `SecAccessControl` (Touch ID /
    /// device passcode) to a *new* item — such items have no legacy
    /// trusted-app ACL at all, so every read prompts, with no "Always
    /// Allow" to click. Updating an existing item without the flag never
    /// touches its ACL, so a plain `set` never silently downgrades a
    /// namespace that was hardened earlier.
    pub fn write(service: &str, blob: &[u8], require_passphrase: bool) -> Result<(), String> {
        let mut options = PasswordOptions::new_generic_password(service, &account());
        if require_passphrase {
            options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        }

        let query_len = options.query.len();
        options.query.push((
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(blob).into_CFType(),
        ));
        let params = CFDictionary::from_CFType_pairs(&options.query);

        let mut ret: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemAdd(params.as_concrete_TypeRef(), &mut ret) };
        if status == errSecDuplicateItem {
            let search = CFDictionary::from_CFType_pairs(&options.query[..query_len]);
            let update = CFDictionary::from_CFType_pairs(&options.query[query_len..]);
            let status = unsafe {
                SecItemUpdate(search.as_concrete_TypeRef(), update.as_concrete_TypeRef())
            };
            if status != 0 {
                return Err(format!("keychain write failed: OSStatus {status}"));
            }
        } else if status != 0 {
            return Err(format!("keychain write failed: OSStatus {status}"));
        }
        Ok(())
    }

    pub fn remove(service: &str) -> Result<(), String> {
        match delete_generic_password(service, &account()) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {
                Err(super::NOT_FOUND.to_string())
            }
            Err(e) => Err(format!("keychain delete failed: {e}")),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    // Compiles (and lets tests run) on non-macOS; refuses at runtime.
    const MSG: &str = "this build only supports the macOS Keychain";

    pub fn read(_service: &str) -> Result<Option<Vec<u8>>, String> {
        Err(MSG.to_string())
    }
    pub fn write(_service: &str, _blob: &[u8], _require_passphrase: bool) -> Result<(), String> {
        Err(MSG.to_string())
    }
    pub fn remove(_service: &str) -> Result<(), String> {
        Err(MSG.to_string())
    }
}

pub use imp::{read, remove, write};
