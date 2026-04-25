//! Model-schema mismatch guard.
//!
//! `little-snitch restore-model` accepts a model JSON whose top-level
//! `bundleVersion` field declares which LS schema the payload was
//! exported against. Restoring a payload whose `bundleVersion` differs
//! from the **live** model's version risks two failure modes:
//!
//! 1. **Silent semantic drift.** A field that meant one thing in the
//!    payload's schema might mean something subtly different (or be
//!    enforced differently) in the running schema. The CLI may accept
//!    the payload without complaint, but the resulting live model is
//!    not what the operator intended.
//! 2. **Backup/restore confusion.** A payload exported from another
//!    machine (different LS version) imported here would replace local
//!    rules with a foreign-schema view of them — easy to do by accident
//!    when restoring from a backup.
//!
//! This module is the gate. It is **pure**: callers extract the two
//! version strings (one from the payload they're about to feed
//! `restore-model -t`, one from a fresh `export-model` of the live
//! state) and pass them in. We make the comparison and return a typed
//! error.
//!
//! # Where this gate must run
//!
//! Every code path that's about to invoke `restore-model -t`. The
//! Terminal-access guard from [`super::cli`] addresses payload-flag
//! safety; this module addresses payload-shape safety. They are
//! independent and both required.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Outcome of a `bundleVersion` check.
#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
#[error(
    "SCHEMA_MISMATCH: refused to restore model — payload bundleVersion `{payload}` differs from \
     live `{live}`. Different schemas may interpret rule fields differently; restore the \
     payload-side LS to `{live}` first, or pass `accept_schema_mismatch: true` after manually \
     verifying the field semantics match."
)]
pub struct SchemaMismatch {
    /// `bundleVersion` of the payload about to be restored.
    pub payload: String,
    /// `bundleVersion` of the currently running LS instance.
    pub live: String,
}

/// Compare a payload's `bundleVersion` against the live model's.
///
/// Returns `Ok(())` when they match, or when they differ but
/// `accept_schema_mismatch == true` (the explicit escape hatch).
/// Returns `Err(SchemaMismatch)` otherwise.
///
/// Comparison is **byte-exact**: LS version strings (`6.3.3`, `6.4.0`,
/// `6.4.0b2`, etc.) are not semver in the strict sense, and partial
/// matching ("major.minor only") would silently allow drift across
/// patch releases that have, historically, changed schema field
/// behaviour. If the operator intends to accept that risk they pass
/// the override flag; we don't guess.
pub fn check_bundle_version(
    payload: &str,
    live: &str,
    accept_schema_mismatch: bool,
) -> Result<(), SchemaMismatch> {
    if payload == live || accept_schema_mismatch {
        Ok(())
    } else {
        Err(SchemaMismatch {
            payload: payload.to_string(),
            live: live.to_string(),
        })
    }
}

/// Extract the top-level `bundleVersion` field from a parsed model JSON.
///
/// Returns `None` if the field is missing or not a string. Callers
/// treat that as a hard parse-time refusal — a model JSON without a
/// `bundleVersion` is malformed and not safe to restore regardless of
/// schema-mismatch policy.
///
/// This is a JSON-level helper deliberately decoupled from the
/// `model::Model` struct that [#2](https://github.com/torsday/little-snitch-mcp/issues/2)
/// is currently building. When the typed model lands, callers can
/// reach for `model.bundle_version` directly; this helper remains
/// useful for opaque-blob inspection (e.g. validating a `.lsrules`
/// patch before fully deserializing it).
pub fn extract_bundle_version(model_json: &Value) -> Option<&str> {
    model_json.get("bundleVersion")?.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matching_versions_pass() {
        assert!(check_bundle_version("6.3.3", "6.3.3", false).is_ok());
    }

    #[test]
    fn mismatched_versions_refused_by_default() {
        let err = check_bundle_version("6.3.3", "6.4.0", false).unwrap_err();
        assert_eq!(err.payload, "6.3.3");
        assert_eq!(err.live, "6.4.0");
    }

    #[test]
    fn mismatched_versions_pass_when_explicitly_accepted() {
        assert!(check_bundle_version("6.3.3", "6.4.0", true).is_ok());
    }

    #[test]
    fn matching_versions_pass_regardless_of_accept_flag() {
        assert!(check_bundle_version("6.3.3", "6.3.3", true).is_ok());
    }

    #[test]
    fn comparison_is_byte_exact_no_partial_match() {
        // 6.3 is not a substring-match of 6.3.3 — partial matching
        // would silently allow patch-level drift.
        let err = check_bundle_version("6.3", "6.3.3", false).unwrap_err();
        assert_eq!(err.payload, "6.3");
        assert_eq!(err.live, "6.3.3");
    }

    #[test]
    fn beta_versions_treated_as_distinct() {
        assert!(check_bundle_version("6.4.0", "6.4.0b2", false).is_err());
        assert!(check_bundle_version("6.4.0b1", "6.4.0b2", false).is_err());
    }

    #[test]
    fn empty_versions_match_each_other_but_not_real_versions() {
        assert!(check_bundle_version("", "", false).is_ok());
        assert!(check_bundle_version("", "6.3.3", false).is_err());
        assert!(check_bundle_version("6.3.3", "", false).is_err());
    }

    #[test]
    fn refusal_message_names_both_versions() {
        let err = check_bundle_version("6.3.3", "6.4.0", false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("6.3.3"),
            "message must name payload version: {msg}"
        );
        assert!(
            msg.contains("6.4.0"),
            "message must name live version: {msg}"
        );
        assert!(
            msg.contains("accept_schema_mismatch"),
            "message must name the escape hatch: {msg}"
        );
        assert!(
            msg.starts_with("SCHEMA_MISMATCH"),
            "stable wire-format tag: {msg}"
        );
    }

    #[test]
    fn extract_bundle_version_reads_top_level_field() {
        let model = json!({
            "bundleVersion": "6.3.3",
            "rules": [],
            "groups": [],
        });
        assert_eq!(extract_bundle_version(&model), Some("6.3.3"));
    }

    #[test]
    fn extract_bundle_version_returns_none_when_missing() {
        let model = json!({ "rules": [], "groups": [] });
        assert_eq!(extract_bundle_version(&model), None);
    }

    #[test]
    fn extract_bundle_version_returns_none_when_not_a_string() {
        let model = json!({ "bundleVersion": 633, "rules": [] });
        assert_eq!(extract_bundle_version(&model), None);
        let model_arr = json!({ "bundleVersion": ["6.3.3"], "rules": [] });
        assert_eq!(extract_bundle_version(&model_arr), None);
    }

    #[test]
    fn fixture_with_hand_bumped_version_round_trip_via_extract_then_check() {
        // Reproduces the AC-required test: take a fixture model, bump
        // its bundleVersion, and confirm the guard refuses.
        let mut fixture = json!({
            "bundleVersion": "6.3.3",
            "rules": [{"action": "deny", "process": "any", "remote-domains": "evil.example"}],
            "groups": [],
        });
        // Operator pulled this fixture from a backup made on a 6.4.0 system.
        fixture["bundleVersion"] = json!("6.4.0");
        let payload_v = extract_bundle_version(&fixture).expect("payload has bundleVersion");
        // Live system is still on 6.3.3.
        let live_v = "6.3.3";

        let err = check_bundle_version(payload_v, live_v, false).unwrap_err();
        assert_eq!(err.payload, "6.4.0");
        assert_eq!(err.live, "6.3.3");

        // Operator confirms intent; the override admits the same payload.
        assert!(check_bundle_version(payload_v, live_v, true).is_ok());
    }
}
