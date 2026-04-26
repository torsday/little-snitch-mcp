//! `add_rule_to_live_model` — apply side of the AddRule prepare/apply
//! protocol.
//!
//! Companion to [`super::prepare_live_model_change`]. The LLM:
//!
//! 1. Calls `prepare_live_model_change` with `AddRule { spec }`,
//!    receives `{token, diff: AddRule { rule }, expires_in_seconds}`.
//! 2. Presents the diff to the user for approval.
//! 3. Calls `add_rule_to_live_model(spec, token)`. This module verifies
//!    the token re-derives the same diff (DIFF_DRIFT if not), appends
//!    the rule to the live model, and round-trips through
//!    `restore-model -t`.
//!
//! # Pure vs. orchestrated
//!
//! [`apply_pure`] is the safety-critical core — token verify + rule
//! construct + diff_sha256 match + append-to-model. Easy to test
//! against fixture models.
//!
//! The orchestrator wraps `apply_pure` with the live LS integration:
//! `LsCli::resolve()` → `export-model` → `apply_pure` → write patched
//! payload → `restore-model -t` → re-export → verify rule appears →
//! return. That layer needs a live LS to be meaningful and is left
//! as a follow-up (the AC's "Test reproduces smoke-3 round-trip via
//! the tool API" requires LS access).
//!
//! # Why the caller passes `now_unix`
//!
//! `construct_at(spec, now)` uses `now` for `creation_date` /
//! `modification_date`. The same spec at apply time + a different
//! `now` produces a different rule + a different `diff_sha256` →
//! spurious DIFF_DRIFT. The caller (orchestrator or test) is
//! responsible for passing `now_unix == token.issued_at_unix` — i.e.
//! reuses the prepare-time timestamp the token was issued under.

use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Model, NewRuleSpec, Rule, canonical_value, construct_at};
use crate::safety::{Session, Token, TokenError, VerifyContext};

/// Tool input shape (what the LLM sends).
///
/// `spec` is accepted as a JSON value (parsed into [`NewRuleSpec`]
/// inside the orchestrator) for the same reason
/// [`prepare_live_model_change`] uses JSON: keeps the JsonSchema
/// MCP input shape decoupled from the typed model.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddRuleToLiveModelArgs {
    /// Rule spec (JSON object matching [`NewRuleSpec`]). Must match
    /// the one passed to `prepare_live_model_change` or `DIFF_DRIFT`.
    pub spec: serde_json::Value,
    /// Confirmation token from `prepare_live_model_change`.
    pub token: String,
}

/// What the orchestrator returns on success.
///
/// `backup_path` is filled by the orchestrator wrapper. The pure apply
/// function returns `(Model, Rule)` and leaves backup wiring to the
/// caller.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AddRuleToLiveModelResult {
    /// The rule that was appended.
    pub rule: serde_json::Value,
    /// Path to the pre-mutation backup written by the orchestrator.
    pub backup_path: String,
}

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum AddRuleError {
    #[error("rule construction refused: {0}")]
    Construction(#[from] crate::model::ConstructError),
    #[error("token verify failed: {0}")]
    Token(#[from] TokenError),
}

/// Pure apply: construct the rule from the spec, recompute the
/// prepare-side `Diff::AddRule` canonical hash, verify the token
/// against it, and append the rule to the model on success.
///
/// `now_unix_secs` MUST equal the prepare-time timestamp the token
/// was issued under (typically the token's `issued_at_unix`); a
/// different value yields a different rule (different `creation_date`)
/// → different `diff_sha256` → spurious DIFF_DRIFT.
pub fn apply_pure(
    mut current: Model,
    spec: NewRuleSpec,
    token_str: String,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<(Model, Rule), AddRuleError> {
    let bundle_version = current.bundle_version.to_string();

    // 1. Construct the rule using the prepare-time timestamp.
    //    construct_at validates ADR-0004 §10 (path-existence, blanket-allow).
    let rule = construct_at(spec, now_unix_secs)?;

    // 2. Re-derive the prepare-side Diff::AddRule and its canonical hash.
    //    Must match exactly what prepare_live_model_change computed, or
    //    the verifier rejects with DIFF_DRIFT.
    let diff = serde_json::json!({
        "kind": "add_rule",
        "rule": serde_json::to_value(&rule).expect("Rule serializes"),
    });
    let diff_canon = canonical_value(diff);
    let diff_sha256 = sha256_hex(&serde_json::to_vec(&diff_canon).expect("canonical JSON"));

    // 3. Verify the token against the recomputed diff + current bundle_version.
    let token = Token::from(token_str);
    let ctx = VerifyContext {
        tool: "add_rule_to_live_model",
        current_diff_sha256: &diff_sha256,
        current_bundle_version: &bundle_version,
    };
    session.verify_at(&token, &ctx, now_unix_secs)?;

    // 4. Append. Rule order is the LS-natural insertion order; LS will
    //    re-sort on its own export but the patched payload is what we
    //    feed restore-model -t.
    current.rules.push(rule.clone());
    Ok((current, rule))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, ProcessMatcher, Remote};
    use crate::tools::prepare_live_model_change::{ChangeRequest, prepare_pure};

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

    fn fixture_spec() -> NewRuleSpec {
        NewRuleSpec {
            action: Action::Deny,
            process: ProcessMatcher::Path("/bin/test".into()),
            remote: Remote::Domains(vec!["evil.invalid".into()]),
            uid: 501,
            direction: None,
            priority: None,
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
        }
    }

    /// End-to-end: prepare → apply round-trips on an empty model.
    #[test]
    fn prepare_then_apply_round_trip() {
        let s = session();
        let m = empty_model();

        // Prepare.
        let prep = prepare_pure(
            ChangeRequest::AddRule {
                spec: serde_json::to_value(fixture_spec()).unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        // Apply.
        let (new_model, added) = apply_pure(m, fixture_spec(), prep.token, &s, FIXED_NOW).unwrap();

        assert_eq!(new_model.rules.len(), 1);
        assert_eq!(new_model.rules[0], added);
        assert_eq!(added.action, Action::Deny);
        assert_eq!(added.process.as_deref(), Some("/bin/test"));
    }

    /// A token issued for a different operation (UpdateRule) must be
    /// rejected by the apply tool.
    #[test]
    fn wrong_tool_token_rejected() {
        let s = session();
        let mut m = empty_model();
        // Need a rule for UpdateRule's index to exist.
        let (m_with_rule, _) = apply_pure(
            m,
            fixture_spec(),
            {
                let prep = prepare_pure(
                    ChangeRequest::AddRule {
                        spec: serde_json::to_value(fixture_spec()).unwrap(),
                    },
                    &empty_model(),
                    &s,
                    FIXED_NOW,
                )
                .unwrap();
                prep.token
            },
            &s,
            FIXED_NOW,
        )
        .unwrap();
        m = m_with_rule;

        // Now prepare an UpdateRule (different tool name in the token).
        let update_token = prepare_pure(
            ChangeRequest::UpdateRule {
                index: 0,
                patch: serde_json::json!({"action": "allow"}),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap()
        .token;

        // Try to use the update token with the add tool.
        let err = apply_pure(m, fixture_spec(), update_token, &s, FIXED_NOW).unwrap_err();
        match err {
            AddRuleError::Token(TokenError::ToolMismatch) => {}
            other => panic!("expected ToolMismatch, got {other:?}"),
        }
    }

    /// A token bound to a different bundleVersion (LS upgraded between
    /// prepare and apply) must be rejected with SCHEMA_DRIFT.
    #[test]
    fn schema_drift_rejected() {
        let s = session();
        let mut m_prepare = empty_model();
        m_prepare.bundle_version = 1;
        let mut m_apply = empty_model();
        m_apply.bundle_version = 2; // LS upgraded

        let prep = prepare_pure(
            ChangeRequest::AddRule {
                spec: serde_json::to_value(fixture_spec()).unwrap(),
            },
            &m_prepare,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        let err = apply_pure(m_apply, fixture_spec(), prep.token, &s, FIXED_NOW).unwrap_err();
        match err {
            AddRuleError::Token(TokenError::SchemaDrift) => {}
            other => panic!("expected SchemaDrift, got {other:?}"),
        }
    }

    /// A token used twice — second consume rejected with REPLAY.
    #[test]
    fn replay_rejected() {
        let s = session();
        let m = empty_model();
        let prep = prepare_pure(
            ChangeRequest::AddRule {
                spec: serde_json::to_value(fixture_spec()).unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        let token = prep.token.clone();
        // First apply succeeds.
        apply_pure(m.clone(), fixture_spec(), token.clone(), &s, FIXED_NOW).unwrap();
        // Second apply with same token must fail.
        let err = apply_pure(m, fixture_spec(), token, &s, FIXED_NOW).unwrap_err();
        match err {
            AddRuleError::Token(TokenError::Replay) => {}
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    /// A spec that produces a different rule than what was prepared
    /// (e.g., changed remote domains between prepare and apply) → DIFF_DRIFT.
    #[test]
    fn diff_drift_when_spec_changed_between_prepare_and_apply() {
        let s = session();
        let m = empty_model();

        let prepared_spec = fixture_spec();
        let prep = prepare_pure(
            ChangeRequest::AddRule {
                spec: serde_json::to_value(&prepared_spec).unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        let mut tampered_spec = fixture_spec();
        tampered_spec.remote = Remote::Domains(vec!["different.invalid".into()]);

        let err = apply_pure(m, tampered_spec, prep.token, &s, FIXED_NOW).unwrap_err();
        match err {
            AddRuleError::Token(TokenError::DiffDrift) => {}
            other => panic!("expected DiffDrift, got {other:?}"),
        }
    }

    /// Different `now` between prepare and apply → DIFF_DRIFT (because
    /// creation_date in the constructed rule differs).
    #[test]
    fn diff_drift_when_apply_now_differs_from_prepare_now() {
        let s = session();
        let m = empty_model();

        let prep = prepare_pure(
            ChangeRequest::AddRule {
                spec: serde_json::to_value(fixture_spec()).unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        // Apply uses a different "now" — diff_sha256 won't match.
        let err = apply_pure(m, fixture_spec(), prep.token, &s, FIXED_NOW + 60).unwrap_err();
        match err {
            AddRuleError::Token(TokenError::Expired)
            | AddRuleError::Token(TokenError::DiffDrift) => {}
            other => panic!(
                "expected Expired or DiffDrift (depending on whether 60s past expiry hits first), \
                 got {other:?}"
            ),
        }
    }

    /// Construction refusal at apply time (e.g., process path doesn't
    /// exist) propagates without consuming the token.
    #[test]
    fn construction_refusal_propagates_and_does_not_consume_token() {
        let s = session();
        let m = empty_model();

        // Build a token for a path-existing rule.
        let prep = prepare_pure(
            ChangeRequest::AddRule {
                spec: serde_json::to_value(fixture_spec()).unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();
        let token = prep.token;

        // Apply with a spec whose process path doesn't exist.
        let mut bad_spec = fixture_spec();
        bad_spec.process = ProcessMatcher::Path("/definitely/not/a/real/path/lsmcp59".into());

        let err = apply_pure(m.clone(), bad_spec, token.clone(), &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, AddRuleError::Construction(_)));

        // Token should NOT have been consumed (construction refused before verify).
        // Confirm by retrying with the right spec — should still succeed.
        let result = apply_pure(m, fixture_spec(), token, &s, FIXED_NOW);
        assert!(
            result.is_ok(),
            "token should not have been consumed: {result:?}"
        );
    }
}
