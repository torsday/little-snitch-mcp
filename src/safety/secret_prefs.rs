//! Preference redaction: keys whose values must never appear in logs or
//! tool responses in cleartext.
//!
//! Sources: ADR-0005 §SECRET_PREFERENCE_KEYS.

use std::sync::LazyLock;

use regex::Regex;

/// Preference keys that are always redacted, regardless of the regex below.
const EXPLICIT_SECRET_KEYS: &[&str] = &[
    "dnsEncryptionConfigurations",
    "dnsEncryptionEnabledConfigurations",
];

/// Case-insensitive catch-all for future LS additions (ADR-0005).
static SECRET_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(password|secret|token|credential|key)").unwrap());

/// Return `true` if `key` names a preference whose value must be redacted.
pub fn is_secret_key(key: &str) -> bool {
    EXPLICIT_SECRET_KEYS.contains(&key) || SECRET_KEY_RE.is_match(key)
}

/// If `key` is secret, return `"<redacted: KEY>"` as a JSON string value;
/// otherwise return `value` unchanged.
pub fn redact(key: &str, value: serde_json::Value) -> serde_json::Value {
    if is_secret_key(key) {
        serde_json::Value::String(format!("<redacted: {key}>"))
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_keys_are_secret() {
        assert!(is_secret_key("dnsEncryptionConfigurations"));
        assert!(is_secret_key("dnsEncryptionEnabledConfigurations"));
    }

    #[test]
    fn regex_catches_password_variants() {
        assert!(is_secret_key("adminPassword"));
        assert!(is_secret_key("userSecret"));
        assert!(is_secret_key("authToken"));
        assert!(is_secret_key("apiCredential"));
        assert!(is_secret_key("encryptionKey"));
    }

    #[test]
    fn regex_is_case_insensitive() {
        assert!(is_secret_key("PASSWORD"));
        assert!(is_secret_key("MyTokenValue"));
    }

    #[test]
    fn benign_keys_are_not_secret() {
        assert!(!is_secret_key("activeSilentMode"));
        assert!(!is_secret_key("networkFilterEnabled"));
        assert!(!is_secret_key("confirmAutomatically"));
    }

    #[test]
    fn redact_replaces_secret_value() {
        let v = redact("dnsEncryptionConfigurations", serde_json::json!([1, 2, 3]));
        assert_eq!(
            v,
            serde_json::json!("<redacted: dnsEncryptionConfigurations>")
        );
    }

    #[test]
    fn redact_passes_through_benign_value() {
        let v = redact("activeSilentMode", serde_json::json!(false));
        assert_eq!(v, serde_json::json!(false));
    }
}
