//! Preference write gating.
//!
//! Encodes the full preference write policy from
//! [ADR-0004 §4](../../../docs/adr/0004-safety-permissions-and-confirmation.md):
//!
//! - [`HARD_DENY_KEYS`] — `globalDefaults` keys that are **always refused**:
//!   the network-filter kill switches and LS's own permission gates.
//! - [`ALLOWLIST_KEYS`] — UI/behavior toggles that are **permitted** for
//!   `write_preference`; everything else is not-in-allowlist.
//! - [`is_writable`] — the trichotomous dispatch returning
//!   [`WriteStatus`] (`Allowed | HardDeny | NotInAllowlist`).
//! - [`WriteRefusal`] — structured error carrying the key and reason,
//!   consumed by the `write_preference` tool before spawning the CLI.
//!
//! # Where these gates must run
//!
//! Every code path that could produce a `globalDefaults` mutation:
//!
//! 1. The `write_preference` tool ([#56]) — call `is_writable` and
//!    map non-`Allowed` results to [`WriteRefusal`] before touching the CLI.
//! 2. Any `restore-model` payload-construction path that touches
//!    `globalDefaults` — refuse before signing the confirmation token.
//!    See [#44](https://github.com/torsday/little-snitch-mcp/issues/44).
//!
//! [#56]: https://github.com/torsday/little-snitch-mcp/issues/56

use thiserror::Error;

/// Preference keys whose mutation is **always refused**, regardless of
/// confirmation token or other context.
///
/// Sources:
/// - The six `allow*` keys (LS's own permission gates) per ADR-0004 §4.
/// - `networkFilterEnabled` and `networkFilterControlBits` (LS's master
///   kill switch — toggling either disables the filter entirely).
///
/// Order is alphabetical for stability; consumers must treat membership
/// as the only contract.
pub const HARD_DENY_KEYS: &[&str] = &[
    "allowCommandLineAccess",
    "allowGUIScripting",
    "allowGlobalEditing",
    "allowProfileSwitching",
    "allowRuleAndProfileEditing",
    "allowSettingsEditing",
    "networkFilterControlBits",
    "networkFilterEnabled",
];

/// Preference keys that `write_preference` **may** set or remove.
///
/// This is the v1 list from ADR-0004 §4: UI/behavior toggles with no
/// security impact. Any key absent from this list (and not in
/// [`HARD_DENY_KEYS`]) returns [`WriteStatus::NotInAllowlist`].
///
/// Amending this list requires an ADR-0004 update.
///
/// Order is alphabetical for stability.
pub const ALLOWLIST_KEYS: &[&str] = &[
    "activeSilentMode",
    "autoConfirmationAction",
    "autoConfirmationDelay",
    "confirmAutomatically",
    "customHierarchyLevels",
    "dataRateUnitsBitsPerSecond",
    "defaultRuleLifetimeForCreatingRulesInAlert",
    "detailLevelPortAndProtocol",
    "markNewBlocklistEntriesAsUnapproved",
    "monitorMaxConnectionsInModel",
];

/// Outcome of [`is_writable`] — three-way classification per ADR-0004 §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStatus {
    /// Key is on the allowlist; `write_preference` may proceed.
    Allowed,
    /// Key is in [`HARD_DENY_KEYS`]; refuse unconditionally.
    HardDeny,
    /// Key is neither hard-denied nor explicitly allowed; refuse with
    /// an explanation that points at the allowlist.
    NotInAllowlist,
}

/// Classify `key` according to the preference write policy.
///
/// Comparison is case-sensitive: LS preference keys are camelCase and
/// a case-variant is a different, unknown key.
pub fn is_writable(key: &str) -> WriteStatus {
    if HARD_DENY_KEYS.contains(&key) {
        WriteStatus::HardDeny
    } else if ALLOWLIST_KEYS.contains(&key) {
        WriteStatus::Allowed
    } else {
        WriteStatus::NotInAllowlist
    }
}

/// Structured refusal for a `write_preference` attempt that was blocked
/// by [`is_writable`].
///
/// The `Display` impl is the user-facing message returned in the MCP
/// tool response.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum WriteRefusal {
    /// Key is in [`HARD_DENY_KEYS`]: unconditional refusal.
    #[error(
        "refused to write `{key}` in globalDefaults: this would disable Little Snitch's \
         filter or permission gates; use the LS GUI if intentional"
    )]
    HardDeny {
        /// The offending preference key.
        key: String,
    },
    /// Key is not in [`ALLOWLIST_KEYS`]: refuse with guidance.
    #[error(
        "refused to write `{key}`: not in the preference write allowlist (ADR-0004 §4); \
         amending the allowlist requires an ADR update"
    )]
    NotInAllowlist {
        /// The preference key that was requested.
        key: String,
    },
}

impl WriteRefusal {
    /// Convert a non-`Allowed` [`WriteStatus`] for `key` into a
    /// [`WriteRefusal`]. Panics if called with `WriteStatus::Allowed`.
    pub fn from_status(status: WriteStatus, key: impl Into<String>) -> Self {
        match status {
            WriteStatus::Allowed => panic!("WriteRefusal::from_status called with Allowed"),
            WriteStatus::HardDeny => WriteRefusal::HardDeny { key: key.into() },
            WriteStatus::NotInAllowlist => WriteRefusal::NotInAllowlist { key: key.into() },
        }
    }
}

/// Convenience: check `key` and return `Err(WriteRefusal)` if the write
/// is not permitted, else `Ok(())`. Use at the `write_preference` call
/// site before spawning any CLI command.
pub fn require_writable(key: &str) -> Result<(), WriteRefusal> {
    match is_writable(key) {
        WriteStatus::Allowed => Ok(()),
        status => Err(WriteRefusal::from_status(status, key)),
    }
}

/// True if writing `key` to `globalDefaults` would trip a kill-switch
/// guard. Kept for callers that only need the hard-deny check (e.g.,
/// `restore-model` payload validation, which runs before the allowlist
/// check).
pub fn is_kill_switch_key(key: &str) -> bool {
    HARD_DENY_KEYS.contains(&key)
}

/// Refusal returned to the caller when a kill-switch write is attempted.
///
/// Retained for the `restore-model` path which checks kill-switches
/// independently of the `write_preference` allowlist. New code should
/// prefer [`WriteRefusal`] + [`require_writable`].
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
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

/// Convenience: check `key` and return `Err(KillSwitchRefusal)` if
/// banned, else `Ok(())`.
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

    // ── ALLOWLIST_KEYS ──────────────────────────────────────────────────

    #[test]
    fn allowlist_has_exactly_ten_entries_with_no_dupes() {
        assert_eq!(ALLOWLIST_KEYS.len(), 10);
        let unique: HashSet<&&str> = ALLOWLIST_KEYS.iter().collect();
        assert_eq!(unique.len(), ALLOWLIST_KEYS.len());
    }

    #[test]
    fn allowlist_contains_all_adr_0004_v1_keys() {
        for key in [
            "activeSilentMode",
            "autoConfirmationAction",
            "autoConfirmationDelay",
            "confirmAutomatically",
            "customHierarchyLevels",
            "dataRateUnitsBitsPerSecond",
            "defaultRuleLifetimeForCreatingRulesInAlert",
            "detailLevelPortAndProtocol",
            "markNewBlocklistEntriesAsUnapproved",
            "monitorMaxConnectionsInModel",
        ] {
            assert!(
                ALLOWLIST_KEYS.contains(&key),
                "{key} must be in ALLOWLIST_KEYS per ADR-0004 §4"
            );
        }
    }

    #[test]
    fn allowlist_and_hard_deny_are_disjoint() {
        for key in ALLOWLIST_KEYS {
            assert!(
                !HARD_DENY_KEYS.contains(key),
                "{key} appears in both ALLOWLIST_KEYS and HARD_DENY_KEYS"
            );
        }
    }

    // ── is_writable / WriteStatus ───────────────────────────────────────

    #[test]
    fn allowed_keys_return_allowed() {
        for key in ALLOWLIST_KEYS {
            assert_eq!(
                is_writable(key),
                WriteStatus::Allowed,
                "{key} should be Allowed"
            );
        }
    }

    #[test]
    fn hard_deny_keys_return_hard_deny() {
        for key in HARD_DENY_KEYS {
            assert_eq!(
                is_writable(key),
                WriteStatus::HardDeny,
                "{key} should be HardDeny"
            );
        }
    }

    #[test]
    fn unknown_key_returns_not_in_allowlist() {
        assert_eq!(is_writable("someUnknownPref"), WriteStatus::NotInAllowlist);
        assert_eq!(is_writable(""), WriteStatus::NotInAllowlist);
    }

    #[test]
    fn is_writable_is_case_sensitive() {
        assert_eq!(is_writable("activeSilentMode"), WriteStatus::Allowed);
        assert_eq!(is_writable("ActiveSilentMode"), WriteStatus::NotInAllowlist);
        assert_eq!(is_writable("networkFilterEnabled"), WriteStatus::HardDeny);
        assert_eq!(is_writable("NetworkFilterEnabled"), WriteStatus::NotInAllowlist);
    }

    // ── require_writable / WriteRefusal ────────────────────────────────

    #[test]
    fn require_writable_passes_allowlisted_keys() {
        assert!(require_writable("activeSilentMode").is_ok());
        assert!(require_writable("confirmAutomatically").is_ok());
    }

    #[test]
    fn require_writable_rejects_hard_deny_with_hard_deny_variant() {
        let err = require_writable("networkFilterEnabled").unwrap_err();
        assert!(matches!(err, WriteRefusal::HardDeny { .. }));
        if let WriteRefusal::HardDeny { key } = err {
            assert_eq!(key, "networkFilterEnabled");
        }
    }

    #[test]
    fn require_writable_rejects_unknown_with_not_in_allowlist_variant() {
        let err = require_writable("someFuturePreference").unwrap_err();
        assert!(matches!(err, WriteRefusal::NotInAllowlist { .. }));
        if let WriteRefusal::NotInAllowlist { key } = err {
            assert_eq!(key, "someFuturePreference");
        }
    }

    #[test]
    fn write_refusal_hard_deny_message_names_key_and_cites_gui() {
        let msg = WriteRefusal::HardDeny {
            key: "allowCommandLineAccess".into(),
        }
        .to_string();
        assert!(msg.contains("allowCommandLineAccess"));
        assert!(msg.contains("LS GUI"));
    }

    #[test]
    fn write_refusal_not_in_allowlist_message_names_key_and_cites_adr() {
        let msg = WriteRefusal::NotInAllowlist {
            key: "dnsEncryptionMode".into(),
        }
        .to_string();
        assert!(msg.contains("dnsEncryptionMode"));
        assert!(msg.contains("ADR-0004"));
    }

    // ── HARD_DENY_KEYS (existing tests, preserved) ──────────────────────

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
        assert!(msg.contains("allowCommandLineAccess"));
        assert!(msg.contains("disable Little Snitch's filter"));
        assert!(msg.contains("LS GUI"));
    }
}
