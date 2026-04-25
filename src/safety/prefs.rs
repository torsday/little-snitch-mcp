//! Preference write gating.
//!
//! Encodes the **hard-deny** half of the preference write policy from
//! [ADR-0004 §4](../../../docs/adr/0004-safety-permissions-and-confirmation.md):
//! the set of `globalDefaults` keys whose mutation would either disable
//! Little Snitch's network filter outright (`networkFilterEnabled`,
//! `networkFilterControlBits`) or disable LS's own permission gates
//! (the six `allow*` family keys). These are catastrophic to toggle from
//! an LLM-driven flow even with a confirmation token, so the gate is
//! unconditional refusal.
//!
//! The matching **allowlist** half (UI/behavior toggles that *are* safe
//! to write, plus the trichotomous [`is_writable`] dispatch) lands with
//! [#45](https://github.com/torsday/little-snitch-mcp/issues/45). When
//! that lands, [`HARD_DENY_KEYS`] becomes the input to its `HardDeny`
//! arm; nothing here changes.
//!
//! # Where this gate must run
//!
//! Every code path that could produce a `globalDefaults` mutation:
//!
//! 1. The `write_preference` tool (#XX, not yet filed) — refuse before
//!    spawning the CLI.
//! 2. Any `restore-model` payload-construction path that touches
//!    `globalDefaults` — refuse before signing the confirmation token.
//!    See [#44](https://github.com/torsday/little-snitch-mcp/issues/44)
//!    for the patch flow.

use thiserror::Error;

/// Preference keys whose mutation is **always refused**.
///
/// Sources:
/// - The six `allow*` keys (LS's own permission gates) are listed in
///   ADR-0004 §4 ("Hard-deny").
/// - `networkFilterEnabled` and `networkFilterControlBits` are LS's
///   master kill switch — toggling either disables the filter.
///
/// Order is alphabetical for stability; consumers should not rely on
/// it. Membership is the only contract.
pub const HARD_DENY_KEYS: &[&str] = &[
    "allowCommandLineAccess",
    "allowGUIScripting",
    "allowGlobalEditing",
    "allowProfileSwitching",
    "allowRuleAndProfileEditing",
    "allowSettingsEditing",
    "networkFilterEnabled",
    "networkFilterControlBits",
];

/// True if writing `key` to `globalDefaults` would trip a kill-switch
/// guard. Comparison is case-sensitive: LS preference keys are
/// camelCase and an uppercase variant is not the same key.
pub fn is_kill_switch_key(key: &str) -> bool {
    HARD_DENY_KEYS.contains(&key)
}

/// Refusal returned to the caller when a kill-switch write is attempted.
///
/// The `Display` impl is the user-facing message; it deliberately tells
/// the operator to use the LS GUI if the action is intentional, since
/// any intentional kill-switch toggle should leave a human-visible
/// audit trail.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error(
    "refused to write `{key}` in globalDefaults: this would disable Little Snitch's filter; \
     use the LS GUI if intentional"
)]
pub struct KillSwitchRefusal {
    /// The offending preference key.
    pub key: String,
}

impl KillSwitchRefusal {
    /// Construct a refusal for `key`. Caller is responsible for having
    /// already confirmed `is_kill_switch_key(key)`; this is a typed
    /// carrier, not a re-checker.
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

/// Convenience: check `key` and return `Err(KillSwitchRefusal)` if
/// banned, else `Ok(())`. Use at the call site that's about to issue
/// the write — the typed error makes the audit chain obvious.
pub fn refuse_if_kill_switch(key: &str) -> Result<(), KillSwitchRefusal> {
    if is_kill_switch_key(key) {
        Err(KillSwitchRefusal::new(key))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn hard_deny_keys_includes_network_filter_master_switch() {
        assert!(is_kill_switch_key("networkFilterEnabled"));
        assert!(is_kill_switch_key("networkFilterControlBits"));
    }

    #[test]
    fn hard_deny_keys_includes_full_allow_family() {
        for key in [
            "allowCommandLineAccess",
            "allowGUIScripting",
            "allowGlobalEditing",
            "allowProfileSwitching",
            "allowRuleAndProfileEditing",
            "allowSettingsEditing",
        ] {
            assert!(
                is_kill_switch_key(key),
                "{key} must be in HARD_DENY_KEYS per ADR-0004 §4"
            );
        }
    }

    #[test]
    fn hard_deny_keys_has_exactly_eight_entries_with_no_dupes() {
        assert_eq!(HARD_DENY_KEYS.len(), 8);
        let unique: HashSet<&&str> = HARD_DENY_KEYS.iter().collect();
        assert_eq!(unique.len(), HARD_DENY_KEYS.len());
    }

    #[test]
    fn benign_ui_keys_are_not_kill_switches() {
        for key in [
            "dataRateUnitsBitsPerSecond",
            "detailLevelPortAndProtocol",
            "confirmAutomatically",
            "activeSilentMode",
        ] {
            assert!(!is_kill_switch_key(key), "{key} must not be hard-denied");
        }
    }

    #[test]
    fn case_sensitive_match() {
        assert!(is_kill_switch_key("networkFilterEnabled"));
        assert!(!is_kill_switch_key("NetworkFilterEnabled"));
        assert!(!is_kill_switch_key("networkfilterenabled"));
    }

    #[test]
    fn empty_and_unknown_keys_are_not_kill_switches() {
        assert!(!is_kill_switch_key(""));
        assert!(!is_kill_switch_key("notARealPreference"));
    }

    #[test]
    fn refuse_if_kill_switch_passes_through_safe_keys() {
        assert!(refuse_if_kill_switch("activeSilentMode").is_ok());
    }

    #[test]
    fn refuse_if_kill_switch_rejects_kill_switches() {
        let err = refuse_if_kill_switch("networkFilterEnabled").unwrap_err();
        assert_eq!(err.key, "networkFilterEnabled");
    }

    #[test]
    fn refusal_message_names_the_key_and_recommends_gui() {
        let msg = KillSwitchRefusal::new("allowCommandLineAccess").to_string();
        assert!(
            msg.contains("allowCommandLineAccess"),
            "message must name the offending key, got: {msg}"
        );
        assert!(
            msg.contains("disable Little Snitch's filter"),
            "message must explain the consequence, got: {msg}"
        );
        assert!(
            msg.contains("LS GUI"),
            "message must point at the GUI as the intentional path, got: {msg}"
        );
    }
}
