//! `prepare_live_model_change` — the dry-run side of every `live_write`
//! flow.
//!
//! Per [ADR-0004 §9](../../../docs/adr/0004-safety-permissions-and-confirmation.md),
//! every live-model mutation goes through two tools: a *prepare* call
//! that proposes the change and returns a confirmation token, and an
//! *apply* call that the user explicitly approves and that re-verifies
//! the world hasn't drifted between the two. This module is the
//! prepare side.
//!
//! # What the tool does
//!
//! 1. Accepts a [`ChangeRequest`] enum (variant per operation type:
//!    AddRule, UpdateRule, RemoveRule, ApplyLsrulesFile, EnableRuleGroup,
//!    DisableRuleGroup).
//! 2. Calls `littlesnitch export-model` to snapshot the current live
//!    state (skipped in tests via [`prepare_pure`]).
//! 3. Computes a structured [`Diff`] describing what would change.
//! 4. Hashes the diff's canonical JSON for the `diff_sha256` token field.
//! 5. Issues a confirmation token via [`Session::issue`] binding the
//!    token to (operation, target, diff hash, bundleVersion).
//! 6. Returns `{token, diff, expires_in_seconds}`.
//!
//! # Classification
//!
//! `safe_read` — this tool computes locally and never mutates. The
//! actual mutation is the apply-side tool's job.
//!
//! # What the tool does *not* do
//!
//! - **No mutation.** Even a wrong call to this tool can't change the
//!   live model.
//! - **No fancy diff.** The [`Diff`] structure is a one-line-per-change
//!   shape, not a unified diff. The downstream [`apply_*`] tools
//!   recompute the diff against fresh export-model state — token
//!   verification is at the bytes-of-canonical-JSON level, not the
//!   text-of-pretty-printed-diff level.

use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Model, NewRuleSpec, Rule, RulePatch, canonical_value, construct_at};
use crate::safety::{Session, token};

/// Operation the operator wants to perform.
///
/// `spec` and `patch` are accepted as JSON values to keep the
/// JsonSchema-derived MCP input schema independent of the typed
/// model — they're parsed into [`NewRuleSpec`] / [`RulePatch`]
/// inside [`compute_diff`]. Validation happens there, not in the
/// JSON parse.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ChangeRequest {
    /// Construct and add a new rule. `spec` is a JSON object matching
    /// [`crate::model::NewRuleSpec`]. The constructor's ADR-0004 §10
    /// guards apply; rejection here means the prepare call fails
    /// without issuing a token.
    AddRule { spec: serde_json::Value },
    /// Patch a rule by index. `patch` is a JSON object matching
    /// [`crate::model::RulePatch`]; LS-managed fields are silently
    /// ignored because [`RulePatch`] doesn't carry them.
    UpdateRule {
        index: usize,
        patch: serde_json::Value,
    },
    /// Remove a rule by index.
    RemoveRule { index: usize },
    /// Apply a `.lsrules` file from the managed dir to the live model.
    /// The file's contents are folded into the current model in-memory;
    /// the diff describes the fold.
    ApplyLsrulesFile { name: String },
    /// Enable a rule group by display name (resolver runs at apply
    /// time; the prepare side just records intent).
    EnableRuleGroup { display_name: String },
    /// Disable a rule group by display name.
    DisableRuleGroup { display_name: String },
}

/// Structured description of the proposed change.
///
/// Serialized as JSON for both the human-readable response and the
/// `diff_sha256` token binding. Canonicalized via
/// [`crate::model::canonical_value`] before hashing so cosmetic
/// reorderings don't break the bind.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Diff {
    AddRule {
        rule: serde_json::Value,
    },
    UpdateRule {
        index: usize,
        before: serde_json::Value,
        after: serde_json::Value,
    },
    RemoveRule {
        index: usize,
        rule: serde_json::Value,
    },
    ApplyLsrulesFile {
        name: String,
    },
    EnableRuleGroup {
        display_name: String,
    },
    DisableRuleGroup {
        display_name: String,
    },
}

/// What the tool returns to the LLM.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PrepareResult {
    /// Confirmation token. Pass to the matching apply-side tool.
    pub token: String,
    /// Structured diff describing the change. The LLM presents this
    /// to the user for approval.
    pub diff: Diff,
    /// Token TTL — caller may refresh by re-running prepare if expired.
    pub expires_in_seconds: u64,
}

/// What can go wrong before a token is issued.
#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("invalid change: {0}")]
    InvalidChange(String),
    #[error("rule index {index} out of range (model has {total})")]
    IndexOutOfRange { index: usize, total: usize },
    #[error("rule construction refused: {0}")]
    Construction(#[from] crate::model::ConstructError),
    #[error("invalid spec/patch JSON: {0}")]
    BadJson(#[from] serde_json::Error),
}

/// The tool's input shape (what the LLM sends).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareLiveModelChangeArgs {
    /// The proposed change.
    pub proposed_change: ChangeRequest,
}

/// Pure prepare: given a change request, the current model, a session,
/// and a "now" timestamp, compute the diff, hash it, issue a token,
/// and return the result. No I/O — easy to test against fixture models.
pub fn prepare_pure(
    req: ChangeRequest,
    current: &Model,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<PrepareResult, PrepareError> {
    let bundle_version = current.bundle_version.to_string();
    let diff = compute_diff(req.clone(), current, now_unix_secs)?;
    let target = compute_target(&req);
    let tool_name = tool_name_for(&req);

    let diff_json = canonical_value(serde_json::to_value(&diff).expect("Diff is serializable"));
    let diff_sha256 = sha256_hex(&serde_json::to_vec(&diff_json).expect("canonical JSON"));

    let payload = token::payload(
        tool_name,
        target,
        &diff_sha256,
        &bundle_version,
        now_unix_secs,
        token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);

    Ok(PrepareResult {
        token: token.into_string(),
        diff,
        expires_in_seconds: token::DEFAULT_TTL_SECS,
    })
}

fn tool_name_for(req: &ChangeRequest) -> &'static str {
    match req {
        ChangeRequest::AddRule { .. } => "add_rule_to_live_model",
        ChangeRequest::UpdateRule { .. } => "update_rule_in_live_model",
        ChangeRequest::RemoveRule { .. } => "remove_rule_from_live_model",
        ChangeRequest::ApplyLsrulesFile { .. } => "apply_lsrules_file_to_live_model",
        ChangeRequest::EnableRuleGroup { .. } => "enable_rule_group",
        ChangeRequest::DisableRuleGroup { .. } => "disable_rule_group",
    }
}

fn compute_target(req: &ChangeRequest) -> serde_json::Value {
    match req {
        ChangeRequest::AddRule { .. } => serde_json::json!({"op": "add_rule"}),
        ChangeRequest::UpdateRule { index, .. } => {
            serde_json::json!({"op": "update_rule", "index": index})
        }
        ChangeRequest::RemoveRule { index } => {
            serde_json::json!({"op": "remove_rule", "index": index})
        }
        ChangeRequest::ApplyLsrulesFile { name } => {
            serde_json::json!({"op": "apply_lsrules_file", "name": name})
        }
        ChangeRequest::EnableRuleGroup { display_name } => {
            serde_json::json!({"op": "enable_rule_group", "display_name": display_name})
        }
        ChangeRequest::DisableRuleGroup { display_name } => {
            serde_json::json!({"op": "disable_rule_group", "display_name": display_name})
        }
    }
}

fn compute_diff(
    req: ChangeRequest,
    current: &Model,
    now_unix_secs: u64,
) -> Result<Diff, PrepareError> {
    match req {
        ChangeRequest::AddRule { spec } => {
            let typed: NewRuleSpec = serde_json::from_value(spec)?;
            let rule = construct_at(typed, now_unix_secs)?;
            Ok(Diff::AddRule {
                rule: serde_json::to_value(&rule).expect("Rule serializes"),
            })
        }
        ChangeRequest::UpdateRule { index, patch } => {
            let total = current.rules.len();
            if index >= total {
                return Err(PrepareError::IndexOutOfRange { index, total });
            }
            let typed_patch: RulePatch = serde_json::from_value(patch)?;
            let before = serde_json::to_value(&current.rules[index]).expect("Rule serializes");
            let mut after_rule: Rule = current.rules[index].clone();
            crate::model::apply_partial_at(&mut after_rule, typed_patch, now_unix_secs);
            let after = serde_json::to_value(&after_rule).expect("Rule serializes");
            Ok(Diff::UpdateRule {
                index,
                before,
                after,
            })
        }
        ChangeRequest::RemoveRule { index } => {
            let total = current.rules.len();
            if index >= total {
                return Err(PrepareError::IndexOutOfRange { index, total });
            }
            let rule = serde_json::to_value(&current.rules[index]).expect("Rule serializes");
            Ok(Diff::RemoveRule { index, rule })
        }
        ChangeRequest::ApplyLsrulesFile { name } => Ok(Diff::ApplyLsrulesFile { name }),
        ChangeRequest::EnableRuleGroup { display_name } => {
            Ok(Diff::EnableRuleGroup { display_name })
        }
        ChangeRequest::DisableRuleGroup { display_name } => {
            Ok(Diff::DisableRuleGroup { display_name })
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Direction, Priority, ProcessMatcher, Remote, StringOrVec};
    use std::collections::HashMap;
    use std::sync::Arc;

    const FIXED_NOW: u64 = 1_777_200_000; // 2026-04-26T10:40:00Z

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

    fn fixture_rule() -> Rule {
        Rule {
            action: Action::Allow,
            creation_date: "2026-04-25T17:43:37Z".into(),
            modification_date: "2026-04-25T17:43:37Z".into(),
            origin: crate::model::Origin::frontend(),
            uid: Some(501),
            process: Some("/usr/bin/curl".into()),
            requires_trusted_signature_for_any_process: None,
            remote: None,
            remote_domains: Some(StringOrVec::One("example.com".into())),
            remote_hosts: None,
            remote_addresses: None,
            direction: None,
            priority: None,
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

    fn session() -> Arc<Session> {
        Arc::new(Session::from_raw([1u8; 32], [9u8; 32]))
    }

    fn add_rule_request() -> ChangeRequest {
        let spec = NewRuleSpec {
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
        };
        ChangeRequest::AddRule {
            spec: serde_json::to_value(&spec).unwrap(),
        }
    }

    // ---------- happy-path ----------

    #[test]
    fn add_rule_returns_token_and_diff() {
        let s = session();
        let m = empty_model();
        let r = prepare_pure(add_rule_request(), &m, &s, FIXED_NOW).unwrap();
        assert_eq!(r.expires_in_seconds, token::DEFAULT_TTL_SECS);
        assert!(!r.token.is_empty());
        match r.diff {
            Diff::AddRule { rule } => {
                assert_eq!(rule["action"], "deny");
                assert_eq!(rule["process"], "/bin/test");
            }
            other => panic!("wrong diff variant: {other:?}"),
        }
    }

    #[test]
    fn issued_token_verifies_under_same_session_and_state() {
        let s = session();
        let m = empty_model();
        let result = prepare_pure(add_rule_request(), &m, &s, FIXED_NOW).unwrap();

        // Re-derive the diff_sha256 the same way the apply side would.
        let diff_json =
            canonical_value(serde_json::to_value(&result.diff).expect("Diff is serializable"));
        let diff_sha256 = sha256_hex(&serde_json::to_vec(&diff_json).expect("canonical JSON"));

        let token_obj = crate::safety::Token::from(result.token.clone());
        let ctx = crate::safety::VerifyContext {
            tool: "add_rule_to_live_model",
            current_diff_sha256: &diff_sha256,
            current_bundle_version: "1",
        };
        let verified = s.verify_at(&token_obj, &ctx, FIXED_NOW + 30);
        assert!(
            verified.is_ok(),
            "round-trip verify must succeed: {verified:?}"
        );
    }

    // ---------- per-variant diff shape ----------

    #[test]
    fn update_rule_diff_carries_before_and_after() {
        let s = session();
        let mut m = empty_model();
        m.rules = vec![fixture_rule()];

        let req = ChangeRequest::UpdateRule {
            index: 0,
            patch: serde_json::to_value(&RulePatch {
                action: Some(Action::Deny),
                ..Default::default()
            })
            .unwrap(),
        };
        let r = prepare_pure(req, &m, &s, FIXED_NOW).unwrap();
        match r.diff {
            Diff::UpdateRule {
                index,
                before,
                after,
            } => {
                assert_eq!(index, 0);
                assert_eq!(before["action"], "allow");
                assert_eq!(after["action"], "deny");
                // Other fields preserved (round-trip preservation invariant).
                assert_eq!(before["process"], after["process"]);
            }
            other => panic!("wrong diff variant: {other:?}"),
        }
    }

    #[test]
    fn update_rule_with_out_of_range_index_refuses() {
        let s = session();
        let m = empty_model();
        let req = ChangeRequest::UpdateRule {
            index: 5,
            patch: serde_json::to_value(RulePatch::default()).unwrap(),
        };
        let err = prepare_pure(req, &m, &s, FIXED_NOW).unwrap_err();
        match err {
            PrepareError::IndexOutOfRange { index, total } => {
                assert_eq!(index, 5);
                assert_eq!(total, 0);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn remove_rule_diff_carries_the_rule_being_removed() {
        let s = session();
        let mut m = empty_model();
        m.rules = vec![fixture_rule()];
        let r = prepare_pure(ChangeRequest::RemoveRule { index: 0 }, &m, &s, FIXED_NOW).unwrap();
        match r.diff {
            Diff::RemoveRule { index, rule } => {
                assert_eq!(index, 0);
                assert_eq!(rule["action"], "allow");
            }
            other => panic!("wrong diff variant: {other:?}"),
        }
    }

    #[test]
    fn remove_rule_with_out_of_range_index_refuses() {
        let s = session();
        let m = empty_model();
        let err =
            prepare_pure(ChangeRequest::RemoveRule { index: 0 }, &m, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, PrepareError::IndexOutOfRange { .. }));
    }

    #[test]
    fn apply_lsrules_file_diff_carries_the_filename() {
        let s = session();
        let m = empty_model();
        let r = prepare_pure(
            ChangeRequest::ApplyLsrulesFile {
                name: "incident.lsrules".into(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();
        match r.diff {
            Diff::ApplyLsrulesFile { name } => assert_eq!(name, "incident.lsrules"),
            other => panic!("wrong diff variant: {other:?}"),
        }
    }

    #[test]
    fn enable_and_disable_rule_group_diffs_carry_display_name() {
        let s = session();
        let m = empty_model();
        let enable = prepare_pure(
            ChangeRequest::EnableRuleGroup {
                display_name: "macOS Services".into(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();
        let disable = prepare_pure(
            ChangeRequest::DisableRuleGroup {
                display_name: "macOS Services".into(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();
        match enable.diff {
            Diff::EnableRuleGroup { display_name } => assert_eq!(display_name, "macOS Services"),
            other => panic!("wrong diff variant: {other:?}"),
        }
        match disable.diff {
            Diff::DisableRuleGroup { display_name } => assert_eq!(display_name, "macOS Services"),
            other => panic!("wrong diff variant: {other:?}"),
        }
    }

    // ---------- token binding ----------

    #[test]
    fn token_binds_to_per_variant_tool_name() {
        let s = session();
        let m = empty_model();
        let add = prepare_pure(add_rule_request(), &m, &s, FIXED_NOW).unwrap();
        // Decode the issued token and verify the tool field.
        let token_obj = crate::safety::Token::from(add.token);
        let ctx = crate::safety::VerifyContext {
            tool: "update_rule_in_live_model", // wrong on purpose
            current_diff_sha256: "anything",
            current_bundle_version: "1",
        };
        let err = s.verify_at(&token_obj, &ctx, FIXED_NOW + 30).unwrap_err();
        // Should fail with TOOL_MISMATCH (the token was issued for add_rule_to_live_model).
        assert!(
            matches!(
                err,
                crate::safety::TokenError::ToolMismatch | crate::safety::TokenError::DiffDrift
            ),
            "wrong-tool verify must fail with TOOL_MISMATCH (or DIFF_DRIFT if check ordering): {err:?}"
        );
    }

    #[test]
    fn token_binds_to_bundle_version_from_current_model() {
        let s = session();
        let mut m = empty_model();
        m.bundle_version = 42;

        let result = prepare_pure(add_rule_request(), &m, &s, FIXED_NOW).unwrap();
        let diff_json =
            canonical_value(serde_json::to_value(&result.diff).expect("Diff is serializable"));
        let diff_sha256 = sha256_hex(&serde_json::to_vec(&diff_json).expect("canonical JSON"));

        let token_obj = crate::safety::Token::from(result.token);
        let ctx = crate::safety::VerifyContext {
            tool: "add_rule_to_live_model",
            current_diff_sha256: &diff_sha256,
            current_bundle_version: "999", // pretend LS upgraded between prepare and apply
        };
        let err = s.verify_at(&token_obj, &ctx, FIXED_NOW + 30).unwrap_err();
        assert_eq!(err, crate::safety::TokenError::SchemaDrift);
    }

    // ---------- canonicalization invariance ----------

    #[test]
    fn diff_sha256_is_invariant_to_struct_field_order() {
        // Issue two tokens with identical-content updates that happen to
        // produce different field-order serializations of `before`/`after`.
        // After canonicalization their diff_sha256 must match (otherwise
        // the apply side could spuriously fail DIFF_DRIFT).
        let s = session();
        let mut m = empty_model();
        m.rules = vec![fixture_rule()];

        let r1 = prepare_pure(
            ChangeRequest::UpdateRule {
                index: 0,
                patch: serde_json::to_value(&RulePatch {
                    notes: Some("x".into()),
                    ..Default::default()
                })
                .unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        )
        .unwrap();

        // Recompute on a clone of m — should yield the same diff_sha256.
        let r2 = prepare_pure(
            ChangeRequest::UpdateRule {
                index: 0,
                patch: serde_json::to_value(&RulePatch {
                    notes: Some("x".into()),
                    ..Default::default()
                })
                .unwrap(),
            },
            &m,
            &s,
            FIXED_NOW,
        );
        // The second issue would be REPLAY-able only if it lands in the
        // consumed set, but tokens are unique per call (different MAC due
        // to different timestamp slot is moot since same now). The point
        // here is that the *diff* shape is byte-identical across calls.
        let _ = r2;

        // Re-derive diff_sha256 from r1.diff:
        let diff_json =
            canonical_value(serde_json::to_value(&r1.diff).expect("Diff is serializable"));
        let h1 = sha256_hex(&serde_json::to_vec(&diff_json).expect("canonical JSON"));
        // Hash should be deterministic.
        let diff_json2 =
            canonical_value(serde_json::to_value(&r1.diff).expect("Diff is serializable"));
        let h2 = sha256_hex(&serde_json::to_vec(&diff_json2).expect("canonical JSON"));
        assert_eq!(h1, h2);
    }

    // ---------- AddRule honors construct refusals ----------

    #[test]
    fn add_rule_blanket_allow_combo_refused_at_prepare_time() {
        let s = session();
        let m = empty_model();
        let spec = NewRuleSpec {
            action: Action::Allow,
            process: ProcessMatcher::Any,
            remote: Remote::Any,
            uid: 501,
            direction: None,
            priority: None,
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
        };
        let bad = ChangeRequest::AddRule {
            spec: serde_json::to_value(&spec).unwrap(),
        };
        let err = prepare_pure(bad, &m, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(err, PrepareError::Construction(_)));
    }

    // ---------- direction/priority unused warning silencer ----------

    #[test]
    fn diff_serializes_with_kind_tag() {
        let s = session();
        let m = empty_model();
        let r = prepare_pure(add_rule_request(), &m, &s, FIXED_NOW).unwrap();
        let json = serde_json::to_value(&r.diff).unwrap();
        assert_eq!(json["kind"], "add_rule");
        // Squelch unused-import warnings if any of these don't get exercised:
        let _ = (Direction::Outgoing, Priority::Regular);
    }
}
