//! Namespace blob (de)serialization.
//!
//! All variables of one namespace are stored as a single JSON object
//! (string -> string) inside ONE Keychain item. One item = one access
//! prompt per `run`, and no need to enumerate Keychain items.

use std::collections::BTreeMap;

pub type Vars = BTreeMap<String, String>;

pub fn parse(blob: &[u8]) -> Result<Vars, String> {
    let value: serde_json::Value = serde_json::from_slice(blob)
        .map_err(|e| format!("stored blob is not valid JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or("stored blob is not a JSON object")?;
    let mut vars = Vars::new();
    for (k, v) in obj {
        let s = v
            .as_str()
            .ok_or_else(|| format!("value of {k} is not a string"))?;
        vars.insert(k.clone(), s.to_string());
    }
    Ok(vars)
}

pub fn serialize(vars: &Vars) -> Vec<u8> {
    // BTreeMap => deterministic key order => stable blob.
    serde_json::to_vec(vars).expect("string map always serializes")
}

/// Env var names: [A-Za-z_][A-Za-z0-9_]* — reject anything else early,
/// so nothing weird ever reaches the child environment.
pub fn valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Namespace names become part of the Keychain service string;
/// keep them boring: [A-Za-z0-9._-]+
pub fn valid_namespace(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

pub fn service_name(namespace: &str) -> String {
    format!("envlock-{namespace}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut vars = Vars::new();
        vars.insert("MONGO_URI".into(), "mongodb://u:p@h/db?x=1&y=2".into());
        vars.insert("API_KEY".into(), "with \"quotes\" and \n newline".into());
        let blob = serialize(&vars);
        assert_eq!(parse(&blob).unwrap(), vars);
    }

    #[test]
    fn parse_rejects_non_object() {
        assert!(parse(b"[1,2]").is_err());
        assert!(parse(b"\"str\"").is_err());
        assert!(parse(b"not json").is_err());
    }

    #[test]
    fn parse_rejects_non_string_values() {
        assert!(parse(br#"{"A": 1}"#).is_err());
        assert!(parse(br#"{"A": null}"#).is_err());
    }

    #[test]
    fn var_names() {
        assert!(valid_var_name("MONGO_URI"));
        assert!(valid_var_name("_x9"));
        assert!(!valid_var_name("9X"));
        assert!(!valid_var_name("A-B"));
        assert!(!valid_var_name(""));
        assert!(!valid_var_name("PATH=1"));
    }

    #[test]
    fn namespaces() {
        assert!(valid_namespace("ddsc"));
        assert!(valid_namespace("prod-db.v2"));
        assert!(!valid_namespace(""));
        assert!(!valid_namespace("a b"));
        assert!(!valid_namespace("a/b"));
    }
}
