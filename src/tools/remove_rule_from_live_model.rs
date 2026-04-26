//! `remove_rule_from_live_model` — apply side of the RemoveRule
//! prepare/apply protocol.
//!
//! Companion to [`super::prepare_live_model_change`]'s `RemoveRule`
//! variant. Same shape as [`super::update_rule_in_live_model`] but
//! the action is `model.rules.remove(index)` and the diff matches
//! `Diff::RemoveRule { index, rule }`.

use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Model, Rule, canonical_value};
use crate::safety::rules::Intent;
use crate::safety::{Session, Token, TokenError, VerifyContext, guard};

/// Tool input shape.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveRuleFromLiveModelArgs {
    /// Rule index in `model.rules` (the same index the prepare side saw).
    pub index: usize,
    /// Confirmation token from `prepare_live_model_change`.
    pub token: String,
}

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum RemoveRuleError {
    #[error("rule index {index} out of range (model has {total})")]
    IndexOutOfRange { index: usize, total: usize },
    #[error("rule mutation refused: {reason} (requires live_write_strong acknowledgement)")]
    RequiresStrongAck { reason: String },
    #[error("token verify failed: {0}")]
    Token(#[from] TokenError),
}

/// Pure apply: validate index → guard → token verify → remove → return.
pub fn apply_pure(
    mut current: Model,
    index: usize,
    token_str: String,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<(Model, Rule), RemoveRuleError> {
    let total = current.rules.len();
    if index >= total {
        return Err(RemoveRuleError::IndexOutOfRange { index, total });
    }

    // Guard the mutation per ADR-0004 §8.
    let group_for_rule = current.rules[index]
        .group
        .as_deref()
        .and_then(|gid| current.groups.get(gid));
    let guard_result = guard(&current.rules[index], Intent::Remove, group_for_rule);
    if !guard_result.allowed {
        return Err(RemoveRuleError::RequiresStrongAck {
            reason: guard_result
                .reason
                .unwrap_or_else(|| "rule mutation requires strong acknowledgement".into()),
        });
    }

    // Recompute the prepare-side Diff::RemoveRule { index, rule } hash.
    let rule_value = serde_json::to_value(&current.rules[index]).expect("Rule serializes");
    let diff = serde_json::json!({
        "kind": "remove_rule",
        "index": index,
        "rule": rule_value,
    });
    let diff_canon = canonical_value(diff);
    let diff_sha256 = sha256_hex(&serde_json::to_vec(&diff_canon).expect("canonical JSON"));

    // Verify token.
    let bundle_version = current.bundle_version.to_string();
    let token = Token::from(token_str);
    let ctx = VerifyContext {
        tool: "remove_rule_from_live_model",
        current_diff_sha256: &diff_sha256,
        current_bundle_version: &bundle_version,
    };
    session.verify_at(&token, &ctx, now_unix_secs)?;

    // Remove and return the removed rule.
    let removed = current.rules.remove(index);
    Ok((current, removed))
}

/// Result shape (orchestrator wrapper).
#[derive(Debug, Serialize, JsonSchema)]
pub struct RemoveRuleFromLiveModelResult {
    pub removed_rule: serde_json::Value,
    pub backup_path: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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
    fn prepare_then_apply_round_trip_removes_the_rule() {
        let s = session();
        let m = model_with_one_rule(plain_rule());

        let prep = prepare_pure(ChangeRequest::RemoveRule { index: 0 }, &m, &s, FIXED_NOW).unwrap();

        let (new_model, removed) = apply_pure(m, 0, prep.token, &s, FIXED_NOW).unwrap();

        assert_eq!(new_model.rules.len(), 0);
        assert_eq!(removed.process.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn factory_rule_remove_refused() {
        let s = session();
        let mut r = plain_rule();
        r.factory_id = Some("ls-factory-007".into());
        let m = model_with_one_rule(r);
        let err = apply_pure(m, 0, "fake".into(), &s, FIXED_NOW).unwrap_err();
        match err {
            RemoveRuleError::RequiresStrongAck { reason } => {
                assert!(reason.contains("ls-factory-007"));
            }
            other => panic!("expected RequiresStrongAck, got {other:?}"),
        }
    }

    #[test]
    fn protected_rule_remove_refused() {
        let s = session();
        let mut r = plain_rule();
        r.protected = Some(true);
        let m = model_with_one_rule(r);
        let err = apply_pure(m, 0, "fake".into(), &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, RemoveRuleError::RequiresStrongAck { .. }));
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
        let err = apply_pure(m, 0, "fake".into(), &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, RemoveRuleError::RequiresStrongAck { .. }));
    }

    #[test]
    fn out_of_range_index_returns_error() {
        let s = session();
        let m = empty_model();
        let err = apply_pure(m, 0, "fake".into(), &s, FIXED_NOW).unwrap_err();
        match err {
            RemoveRuleError::IndexOutOfRange { index, total } => {
                assert_eq!(index, 0);
                assert_eq!(total, 0);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn diff_drift_when_rule_changed_between_prepare_and_apply() {
        let s = session();
        let r1 = plain_rule();
        let m_at_prepare = model_with_one_rule(r1.clone());
        let prep = prepare_pure(
            ChangeRequest::RemoveRule { index: 0 },
            &m_at_prepare,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        // Apply against a model where the rule was modified by something else.
        let mut r2 = r1;
        r2.notes = Some("modified by another actor".into());
        let m_at_apply = model_with_one_rule(r2);

        let err = apply_pure(m_at_apply, 0, prep.token, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, RemoveRuleError::Token(TokenError::DiffDrift)));
    }
}
