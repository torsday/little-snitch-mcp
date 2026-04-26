//! `update_rule_in_live_model` — apply side of the UpdateRule
//! prepare/apply protocol.
//!
//! Companion to [`super::prepare_live_model_change`]'s `UpdateRule`
//! variant. Verifies the token, runs [`crate::safety::rules::guard`]
//! (refuses without a strong-ack escalation for protected /
//! factory-id / signature-trust / builtin-group rules), applies the
//! patch, and returns the updated model + the patched rule.
//!
//! See [`super::add_rule_to_live_model`] for the architectural
//! rationale on why `now_unix_secs` is a required parameter (timestamp
//! must match prepare time so `modification_date` matches and
//! `diff_sha256` is byte-identical).

use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Model, Rule, RulePatch, apply_partial_at, canonical_value};
use crate::safety::rules::{GuardResult, Intent};
use crate::safety::{Session, Token, TokenError, VerifyContext, guard};

/// Tool input shape.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateRuleInLiveModelArgs {
    /// Rule index in `model.rules` (the same index the prepare side saw).
    pub index: usize,
    /// Patch (JSON object matching [`crate::model::RulePatch`]).
    pub patch: serde_json::Value,
    /// Confirmation token from `prepare_live_model_change`.
    pub token: String,
}

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum UpdateRuleError {
    #[error("rule index {index} out of range (model has {total})")]
    IndexOutOfRange { index: usize, total: usize },
    #[error("rule mutation refused: {reason} (requires live_write_strong acknowledgement)")]
    RequiresStrongAck { reason: String },
    #[error("invalid patch JSON: {0}")]
    BadJson(#[from] serde_json::Error),
    #[error("token verify failed: {0}")]
    Token(#[from] TokenError),
}

/// Pure apply: validate index → guard → token verify → patch → return.
pub fn apply_pure(
    mut current: Model,
    index: usize,
    patch: RulePatch,
    token_str: String,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<(Model, Rule), UpdateRuleError> {
    let total = current.rules.len();
    if index >= total {
        return Err(UpdateRuleError::IndexOutOfRange { index, total });
    }

    // Guard the rule mutation per ADR-0004 §8.
    let group_for_rule = current.rules[index]
        .group
        .as_deref()
        .and_then(|gid| current.groups.get(gid));
    let guard_result = guard(&current.rules[index], Intent::Update, group_for_rule);
    if !guard_result.allowed {
        return Err(UpdateRuleError::RequiresStrongAck {
            reason: guard_result
                .reason
                .unwrap_or_else(|| "rule mutation requires strong acknowledgement".into()),
        });
    }

    // Build the post-patch rule first, so we can compute the same
    // diff the prepare side computed.
    let before = serde_json::to_value(&current.rules[index]).expect("Rule serializes");
    let mut after_rule = current.rules[index].clone();
    apply_partial_at(&mut after_rule, patch, now_unix_secs);
    let after = serde_json::to_value(&after_rule).expect("Rule serializes");

    // Recompute the prepare-side Diff::UpdateRule { index, before, after }
    // canonical hash.
    let diff = serde_json::json!({
        "kind": "update_rule",
        "index": index,
        "before": before,
        "after": after,
    });
    let diff_canon = canonical_value(diff);
    let diff_sha256 = sha256_hex(&serde_json::to_vec(&diff_canon).expect("canonical JSON"));

    // Verify token.
    let bundle_version = current.bundle_version.to_string();
    let token = Token::from(token_str);
    let ctx = VerifyContext {
        tool: "update_rule_in_live_model",
        current_diff_sha256: &diff_sha256,
        current_bundle_version: &bundle_version,
    };
    session.verify_at(&token, &ctx, now_unix_secs)?;

    // Apply.
    current.rules[index] = after_rule.clone();
    Ok((current, after_rule))
}

/// Result shape (for the orchestrator wrapper to compose).
#[derive(Debug, Serialize, JsonSchema)]
pub struct UpdateRuleInLiveModelResult {
    pub rule: serde_json::Value,
    pub backup_path: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Test helper exposing the `GuardResult` shape so suite-level tests
/// can construct expectations without re-implementing the matcher.
#[cfg(test)]
pub(crate) fn _expose_guard_result_shape() -> GuardResult {
    GuardResult {
        allowed: true,
        reason: None,
        requires_strong_ack: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Direction, Group, Origin, Priority, StringOrVec};
    use crate::tools::prepare_live_model_change::{ChangeRequest, prepare_pure};
    use std::collections::HashMap;

    const FIXED_NOW: u64 = 1_777_200_000;

    fn empty_model() -> Model {
        serde_json::from_value(serde_json::json!({
            "bundleVersion": 1,
            "factoryRuleSetVersion": 1,
            "rules": [],
            "groups": {},
            "profiles": {},
            "noProfilePseudoProfile": null,
            "globalDefaults": {},
            "users": [],
            "codeRequirements": {},
            "developerTeamNames": {},
            "lastSeenExecutableByCodeIdentifier": {},
            "networkTriggers": [],
            "blocklistStatistics": null,
            "disabledDomainsInLists": [],
            "disabledHostNamesInLists": [],
            "disabledIPAddressRangesInLists": []
        }))
        .unwrap()
    }

    fn session() -> Arc<Session> {
        Arc::new(Session::from_raw([1u8; 32], [9u8; 32]))
    }

    fn plain_rule() -> Rule {
        Rule {
            action: Action::Allow,
            creation_date: "2026-04-25T17:43:37Z".into(),
            modification_date: "2026-04-25T17:43:37Z".into(),
            origin: Origin::frontend(),
            uid: Some(501),
            process: Some("/usr/bin/curl".into()),
            requires_trusted_signature_for_any_process: None,
            remote: None,
            remote_domains: Some(StringOrVec::One("example.com".into())),
            remote_hosts: None,
            remote_addresses: None,
            direction: Some(Direction::Outgoing),
            priority: Some(Priority::High),
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
            factory_id: None,
            factory_help_text: None,
            protected: None,
            last_used: None,
            use_count: None,
            approved: None,
            hidden: None,
            owner: None,
            extra: HashMap::new(),
        }
    }

    fn model_with_one_rule(r: Rule) -> Model {
        let mut m = empty_model();
        m.rules.push(r);
        m
    }

    #[test]
    fn prepare_then_apply_round_trip_on_plain_rule() {
        let s = session();
        let m = model_with_one_rule(plain_rule());

        let patch_value = serde_json::json!({"action": "deny"});
        let prep = prepare_pure(
            ChangeRequest::UpdateRule {
                index: 0,
                patch: patch_value.clone(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        let typed_patch: RulePatch = serde_json::from_value(patch_value).unwrap();
        let (new_model, after) = apply_pure(m, 0, typed_patch, prep.token, &s, FIXED_NOW).unwrap();

        assert_eq!(after.action, Action::Deny);
        assert_eq!(new_model.rules[0].action, Action::Deny);
        // Other fields preserved (round-trip preservation invariant from #51).
        assert_eq!(new_model.rules[0].process.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn protected_rule_update_refused_with_strong_ack_requirement() {
        let s = session();
        let mut r = plain_rule();
        r.protected = Some(true);
        let m = model_with_one_rule(r);

        // Don't even need a valid token — guard runs first.
        let err = apply_pure(
            m,
            0,
            RulePatch {
                action: Some(Action::Deny),
                ..Default::default()
            },
            "fake-token-not-checked".into(),
            &s,
            FIXED_NOW,
        )
        .unwrap_err();

        match err {
            UpdateRuleError::RequiresStrongAck { reason } => {
                assert!(
                    reason.contains("protected"),
                    "reason should name protected: {reason}"
                );
                assert!(
                    reason.contains("live_write_strong"),
                    "reason should mention live_write_strong escalation: {reason}"
                );
            }
            other => panic!("expected RequiresStrongAck, got {other:?}"),
        }
    }

    #[test]
    fn factory_rule_update_refused() {
        let s = session();
        let mut r = plain_rule();
        r.factory_id = Some("ls-factory-007".into());
        let m = model_with_one_rule(r);

        let err = apply_pure(m, 0, RulePatch::default(), "fake".into(), &s, FIXED_NOW).unwrap_err();
        match err {
            UpdateRuleError::RequiresStrongAck { reason } => {
                assert!(reason.contains("factoryID") || reason.contains("factory_id"));
                assert!(reason.contains("ls-factory-007"));
            }
            other => panic!("expected RequiresStrongAck, got {other:?}"),
        }
    }

    #[test]
    fn rule_in_builtin_group_refused() {
        let s = session();
        let mut r = plain_rule();
        r.group = Some("aaaaa1".into());
        let mut m = model_with_one_rule(r);
        m.groups.insert(
            "aaaaa1".into(),
            Group {
                name: None,
                kind: Some("builtinMacOSServices".into()),
                kind_legacy: None,
                is_active: Some(true),
                update_interval: None,
                last_update_invalid_domains_count: None,
                extra: HashMap::new(),
            },
        );

        let err = apply_pure(m, 0, RulePatch::default(), "fake".into(), &s, FIXED_NOW).unwrap_err();
        match err {
            UpdateRuleError::RequiresStrongAck { reason } => {
                assert!(reason.contains("builtin"), "reason: {reason}");
            }
            other => panic!("expected RequiresStrongAck, got {other:?}"),
        }
    }

    #[test]
    fn out_of_range_index_returns_error() {
        let s = session();
        let m = empty_model();
        let err = apply_pure(m, 5, RulePatch::default(), "fake".into(), &s, FIXED_NOW).unwrap_err();
        match err {
            UpdateRuleError::IndexOutOfRange { index, total } => {
                assert_eq!(index, 5);
                assert_eq!(total, 0);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn replay_rejected() {
        let s = session();
        let m = model_with_one_rule(plain_rule());
        let patch_value = serde_json::json!({"action": "deny"});
        let prep = prepare_pure(
            ChangeRequest::UpdateRule {
                index: 0,
                patch: patch_value.clone(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        let typed_patch: RulePatch = serde_json::from_value(patch_value).unwrap();
        apply_pure(
            m.clone(),
            0,
            typed_patch.clone(),
            prep.token.clone(),
            &s,
            FIXED_NOW,
        )
        .unwrap();
        let err = apply_pure(m, 0, typed_patch, prep.token, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, UpdateRuleError::Token(TokenError::Replay)));
    }
}
