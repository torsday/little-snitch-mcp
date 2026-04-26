//! Serde types for the Little Snitch live-model JSON.
//!
//! This module is the typed view of `littlesnitch export-model` output.
//! Implements the schema empirically reverse-engineered from a live
//! LS 6.3.3 install — see [docs/feasibility-report.md](../../docs/feasibility-report.md)
//! for the full discovery trail and [docs/spikes/2026-04-serde-model.md](../../docs/spikes/2026-04-serde-model.md)
//! for the design rationale captured during this spike.
//!
//! Closes [#2](https://github.com/torsday/little-snitch-mcp/issues/2)
//! (S2 — serde model.rs round-trip).
//!
//! # Forward compatibility
//!
//! Every struct that holds LS-emitted state uses `#[serde(flatten)] extra:
//! HashMap<String, serde_json::Value>` to preserve fields LS may add in
//! future minor releases. This is the spine of safe Track B-surgery:
//! a patched rule round-trips with all unknown fields intact.
//!
//! # Schema versioning
//!
//! `Model::bundle_version` is recorded at export and validated at restore.
//! See [`require_compatible_bundle_version`] for the guard that refuses
//! cross-schema restores.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod patch;
pub mod rule;
pub mod rule_construct;

pub use patch::{
    PatchError, RulePatch, apply_partial, apply_partial_at, canonical_json, canonical_value,
    update_rule, update_rule_at,
};
pub use rule::{Action, Direction, Origin, Priority, RemoteOverlayEntry, Rule, StringOrVec};
pub use rule_construct::{
    ConstructError, NewRuleSpec, ProcessMatcher, Remote, construct, construct_at,
};

/// The full Little Snitch model as emitted by `littlesnitch export-model`.
///
/// Top-level keys come from an actual LS 6.3.3 export. The `extra` field
/// captures anything LS adds in future versions so a round-trip never drops
/// unknown state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Model {
    /// Schema version — record at export, refuse mismatched restore.
    #[serde(rename = "bundleVersion")]
    pub bundle_version: u64,

    /// Factory rule set version (LS-managed).
    #[serde(rename = "factoryRuleSetVersion")]
    pub factory_rule_set_version: u64,

    /// All rules — flat top-level array. May reference a group via [`Rule::group`].
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Rule groups, keyed by group ID. Includes builtin subscriptions
    /// (`kind: "builtinMacOSServices"` etc.) and user-created local groups.
    #[serde(default)]
    pub groups: HashMap<String, Group>,

    /// User-defined profiles, keyed by profile ID. Empty on a fresh install.
    #[serde(default)]
    pub profiles: HashMap<String, serde_json::Value>,

    /// The default pseudo-profile used when no real profile is active.
    #[serde(rename = "noProfilePseudoProfile", default)]
    pub no_profile_pseudo_profile: serde_json::Value,

    /// Global preference defaults (system-wide).
    #[serde(rename = "globalDefaults", default)]
    pub global_defaults: HashMap<String, serde_json::Value>,

    /// Per-user records — `defaults` here is the per-user preference scope.
    #[serde(default)]
    pub users: Vec<User>,

    /// Code-signing requirements keyed by executable path.
    #[serde(rename = "codeRequirements", default)]
    pub code_requirements: HashMap<String, serde_json::Value>,

    /// Map of TEAMID → developer team display name.
    #[serde(rename = "developerTeamNames", default)]
    pub developer_team_names: HashMap<String, String>,

    /// Map of code ID (`TEAMID/identifier`) → most-recently-seen exec path.
    /// LS uses this as a "have I seen this binary before?" cache.
    #[serde(rename = "lastSeenExecutableByCodeIdentifier", default)]
    pub last_seen_executable_by_code_identifier: HashMap<String, String>,

    /// Network triggers (used by automatic profile switching).
    #[serde(rename = "networkTriggers", default)]
    pub network_triggers: Vec<serde_json::Value>,

    /// Statistics block (LS-managed).
    #[serde(rename = "blocklistStatistics", default)]
    pub blocklist_statistics: serde_json::Value,

    /// When the statistics model was created (Cocoa-style timestamp).
    #[serde(
        rename = "statisticsModelCreationDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub statistics_model_creation_date: Option<f64>,

    /// Local overlay: domain entries to disable inside subscribed blocklists.
    /// Append to disable; remove to re-enable. Lowest-blast-radius mutation.
    #[serde(rename = "disabledDomainsInLists", default)]
    pub disabled_domains_in_lists: Vec<RemoteOverlayEntry>,

    /// Local overlay: hostname entries to disable inside subscribed blocklists.
    #[serde(rename = "disabledHostNamesInLists", default)]
    pub disabled_host_names_in_lists: Vec<RemoteOverlayEntry>,

    /// Local overlay: IP-range entries to disable inside subscribed blocklists.
    #[serde(rename = "disabledIPAddressRangesInLists", default)]
    pub disabled_ip_address_ranges_in_lists: Vec<RemoteOverlayEntry>,

    /// Forward-compat: any future top-level fields LS adds.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A rule group (subscription or user-created).
///
/// Builtin subscriptions have `name: None` and a meaningful [`Group::kind`]
/// (e.g., `"builtinMacOSServices"`). User-created local groups have `name`
/// set and a different `kind` (TBD until a fixture is captured).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind_legacy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// Whether the group is currently active (enabled in the GUI / via
    /// `littlesnitch rulegroup -e/-d`).
    #[serde(rename = "isActive", skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,

    #[serde(rename = "updateInterval", skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<f64>,

    #[serde(
        rename = "lastUpdateInvalidDomainsCount",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_update_invalid_domains_count: Option<u64>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A user record from `Model::users`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub uid: u32,
    #[serde(rename = "shortName")]
    pub short_name: String,
    #[serde(rename = "fullName")]
    pub full_name: String,
    #[serde(default)]
    pub defaults: HashMap<String, serde_json::Value>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Refuse to restore a model with a mismatched `bundleVersion`.
///
/// Per ADR-0004 §7. Cross-schema restore is high-risk; the only sanctioned
/// override is an explicit `accept_schema_mismatch` flag at the tool layer.
pub fn require_compatible_bundle_version(
    exported: u64,
    target: u64,
) -> Result<(), BundleVersionMismatch> {
    if exported == target {
        Ok(())
    } else {
        Err(BundleVersionMismatch { exported, target })
    }
}

/// Returned when a `restore-model` payload's `bundleVersion` does not match
/// the live model's at restore time.
#[derive(Debug, thiserror::Error)]
#[error(
    "model schema mismatch: payload bundleVersion={exported}, live bundleVersion={target}; \
     refuse to restore without explicit accept_schema_mismatch override"
)]
pub struct BundleVersionMismatch {
    pub exported: u64,
    pub target: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the `inspect-user-rule.sh` empirical finding: a minimal
    /// user-created rule has exactly 7 fields, dates as ISO-8601 strings,
    /// `remote-domains` as a single string, `origin: "frontend"`.
    #[test]
    fn user_rule_minimal_round_trip() {
        let json = serde_json::json!({
            "action": "ask",
            "creationDate": "2026-04-25T17:34:31Z",
            "modificationDate": "2026-04-25T17:34:31Z",
            "origin": "frontend",
            "process": "/bin/test",
            "remote-domains": "lsmcp-test.invalid",
            "uid": 501
        });

        let rule: Rule = serde_json::from_value(json.clone()).expect("parse");
        let serialized = serde_json::to_value(&rule).expect("serialize");

        // Canonicalize key order via serde_json::Value (BTreeMap-backed) for comparison
        let lhs = canonical(&json);
        let rhs = canonical(&serialized);
        assert_eq!(
            lhs, rhs,
            "round-trip changed value:\nleft={lhs}\nright={rhs}"
        );
    }

    /// Forward-compat: a rule with an unknown field LS might add later
    /// must round-trip with that field preserved.
    #[test]
    fn rule_preserves_unknown_fields() {
        let json = serde_json::json!({
            "action": "allow",
            "process": "any",
            "remote": "local-net",
            "creationDate": "2026-04-25T18:00:00Z",
            "modificationDate": "2026-04-25T18:00:00Z",
            "origin": "frontend",
            "uid": 501,
            // Hypothetical future LS 7.0 field
            "futureFieldFromLS7": { "anything": [1, 2, 3] }
        });

        let rule: Rule = serde_json::from_value(json.clone()).expect("parse");
        assert!(
            rule.extra.contains_key("futureFieldFromLS7"),
            "unknown field must land in `extra`"
        );

        let round_trip = serde_json::to_value(&rule).expect("serialize");
        assert_eq!(canonical(&json), canonical(&round_trip));
    }

    /// A minimal Model round-trips. Schema version preserved.
    #[test]
    fn model_minimal_round_trip() {
        let json = serde_json::json!({
            "bundleVersion": 7172,
            "factoryRuleSetVersion": 424,
            "rules": [],
            "groups": {},
            "profiles": {},
            "noProfilePseudoProfile": { "name": "(default)" },
            "globalDefaults": {},
            "users": [],
            "codeRequirements": {},
            "developerTeamNames": {},
            "lastSeenExecutableByCodeIdentifier": {},
            "networkTriggers": [],
            "blocklistStatistics": {},
            "disabledDomainsInLists": [],
            "disabledHostNamesInLists": [],
            "disabledIPAddressRangesInLists": []
        });

        let model: Model = serde_json::from_value(json.clone()).expect("parse");
        assert_eq!(model.bundle_version, 7172);
        assert_eq!(model.factory_rule_set_version, 424);
        let round_trip = serde_json::to_value(&model).expect("serialize");
        assert_eq!(canonical(&json), canonical(&round_trip));
    }

    #[test]
    fn bundle_version_mismatch_detected() {
        assert!(require_compatible_bundle_version(7172, 7172).is_ok());
        let err = require_compatible_bundle_version(7172, 7300).unwrap_err();
        assert_eq!(err.exported, 7172);
        assert_eq!(err.target, 7300);
    }

    /// Serialize to a string with sorted keys for byte-stable comparison.
    /// Mirrors what LS does on export (alphabetical key order).
    fn canonical(v: &serde_json::Value) -> String {
        // serde_json::to_string with default settings emits keys in
        // BTreeMap order (alphabetical). That matches LS's normalization.
        serde_json::to_string(v).expect("canonicalize")
    }
}
