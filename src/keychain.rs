//! Keychain backend. The ONLY platform-specific code in the project:
//! three calls into Apple's Security framework on macOS, a stub elsewhere.
//!
//! Items are stored as generic passwords:
//!   service = "envlock-<namespace>", account = "<unix username>".
//! No trusted-application list is pre-authorized, so the standard
//! Keychain access dialog appears on read (deny "Always Allow"!).

pub const NOT_FOUND: &str = "__envlock_not_found__";

#[cfg(target_os = "macos")]
mod imp {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

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

    pub fn write(service: &str, blob: &[u8]) -> Result<(), String> {
        // set_generic_password creates the item or updates it in place.
        set_generic_password(service, &account(), blob)
            .map_err(|e| format!("keychain write failed: {e}"))
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
    pub fn write(_service: &str, _blob: &[u8]) -> Result<(), String> {
        Err(MSG.to_string())
    }
    pub fn remove(_service: &str) -> Result<(), String> {
        Err(MSG.to_string())
    }
}

pub use imp::{read, remove, write};
