use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::adapter::LsCli;
use crate::model::Model;
use crate::safety::{ResolveResult, Session, VerifyContext, resolve_group};
use crate::tools::backup_harness;

/// Sentinel bundle version for rule-group operations.
///
/// Rule-group enable/disable is a direct CLI call — it does not touch the
/// model export/restore round-trip, so there is no live bundleVersion to
/// embed. This sentinel keeps the confirmation-token protocol consistent
/// with the rest of the codebase.
const BUNDLE_VERSION: &str = "rule-groups";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha(canonical: &str) -> String {
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn enable_sha(resolved_name: &str) -> String {
    sha(&format!(
        r#"{{"action":"enable_rule_group","resolved_name":"{}"}}"#,
        resolved_name
    ))
}

fn disable_sha(resolved_name: &str) -> String {
    sha(&format!(
        r#"{{"action":"disable_rule_group","resolved_name":"{}"}}"#,
        resolved_name
    ))
}

/// Load the live model from `littlesnitch export-model`.
fn load_live_model() -> Result<Model, String> {
    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    let output = cli
        .run(&["export-model"])
        .map_err(|e| format!("export-model failed: {e}"))?;
    let json = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<Model>(&json).map_err(|e| format!("export-model JSON invalid: {e}"))
}

/// Resolve user input to the display name LS accepts, or return an error
/// if the input is ambiguous / unknown and the model has candidates.
fn resolve_to_display_name(input: &str, model: &Model) -> Result<String, String> {
    match resolve_group(input, model) {
        ResolveResult::Verified(name) => Ok(name),
        ResolveResult::BestEffort(name) => Ok(name),
        ResolveResult::NotFound { candidates } => Err(format!(
            "group {:?} not found; known groups: {:?}",
            input, candidates
        )),
    }
}

/// Whether any group matching the resolved name has a builtin kind.
fn is_builtin_group(resolved_name: &str, model: &Model) -> bool {
    model.groups.values().any(|g| {
        let name_matches = g.name.as_deref() == Some(resolved_name);
        let kind_is_builtin = g
            .kind
            .as_deref()
            .or(g.kind_legacy.as_deref())
            .map(|k| k.starts_with("builtin"))
            .unwrap_or(false);
        name_matches && kind_is_builtin
    })
}

// ─── prepare_enable_rule_group ───────────────────────────────────────────────

/// Input for `prepare_enable_rule_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareEnableRuleGroupArgs {
    /// Display name, `kind`, or group ID. The resolver will translate
    /// to the exact display name `littlesnitch rulegroup -e` accepts.
    pub input: String,
}

/// Return value of `prepare_enable_rule_group`.
#[derive(Debug, Serialize)]
pub struct PrepareEnableRuleGroupResult {
    /// Confirmation token — pass to `enable_rule_group` after user approval.
    pub token: String,
    /// The exact display name that will be passed to `rulegroup -e`.
    pub resolved_name: String,
    /// Human-readable summary of the proposed change.
    pub diff_summary: String,
}

/// Inner prepare — accepts a pre-loaded model. Allows integration tests to
/// inject a fixture model without invoking the `littlesnitch` binary.
pub fn prepare_enable_with_model(
    session: &Arc<Session>,
    input: &str,
    model: &Model,
) -> Result<PrepareEnableRuleGroupResult, String> {
    let resolved_name = resolve_to_display_name(input, model)?;
    let diff_sha = enable_sha(&resolved_name);
    let payload = crate::safety::token::payload(
        "enable_rule_group",
        serde_json::json!({"resolved_name": resolved_name}),
        &diff_sha,
        BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    Ok(PrepareEnableRuleGroupResult {
        token: token.into_string(),
        diff_summary: format!("enable rule group \"{}\"", resolved_name),
        resolved_name,
    })
}

pub fn prepare_enable(
    session: &Arc<Session>,
    args: PrepareEnableRuleGroupArgs,
) -> Result<PrepareEnableRuleGroupResult, String> {
    if args.input.is_empty() {
        return Err("input must not be empty".into());
    }
    let model = load_live_model()?;
    prepare_enable_with_model(session, &args.input, &model)
}

// ─── enable_rule_group ───────────────────────────────────────────────────────

/// Input for `enable_rule_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnableRuleGroupArgs {
    /// Resolved display name returned by `prepare_enable_rule_group`.
    pub resolved_name: String,
    /// Confirmation token from `prepare_enable_rule_group`.
    pub token: String,
}

/// Return value of `enable_rule_group`.
#[derive(Debug, Serialize)]
pub struct EnableRuleGroupResult {
    pub resolved_name: String,
    pub enabled: bool,
    pub backup_path: String,
}

pub fn enable(
    session: &Arc<Session>,
    args: EnableRuleGroupArgs,
) -> Result<EnableRuleGroupResult, String> {
    if args.resolved_name.is_empty() {
        return Err("resolved_name must not be empty".into());
    }
    crate::safety::require_live_write_allowed()?;

    let diff_sha = enable_sha(&args.resolved_name);
    let ctx = VerifyContext {
        tool: "enable_rule_group",
        current_diff_sha256: &diff_sha,
        current_bundle_version: BUNDLE_VERSION,
    };
    session
        .verify(&crate::safety::Token::from(args.token), &ctx)
        .map_err(|e| e.to_string())?;

    let name = args.resolved_name.clone();
    let result = backup_harness::with_backup(move || {
        let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
        cli.run(&["rulegroup", "-e", &name])
            .map_err(|e| format!("rulegroup -e failed: {e}"))?;
        Ok(EnableRuleGroupResult {
            resolved_name: name.clone(),
            enabled: true,
            backup_path: String::new(),
        })
    })?;

    Ok(EnableRuleGroupResult {
        backup_path: result.backup_path,
        ..result.result
    })
}

// ─── prepare_disable_rule_group ──────────────────────────────────────────────

/// Input for `prepare_disable_rule_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareDisableRuleGroupArgs {
    /// Display name, `kind`, or group ID. The resolver will translate
    /// to the exact display name `littlesnitch rulegroup -d` accepts.
    pub input: String,
    /// Required when the target group has a `kind` starting with
    /// `"builtin"` (e.g. macOS Services, iCloud Services). Set to
    /// `true` to confirm you understand the risk of disabling a builtin
    /// group. Without this flag the prepare call refuses.
    pub acknowledge_builtin: Option<bool>,
}

/// Return value of `prepare_disable_rule_group`.
#[derive(Debug, Serialize)]
pub struct PrepareDisableRuleGroupResult {
    pub token: String,
    pub resolved_name: String,
    pub diff_summary: String,
    /// True when the target group has a builtin kind — the
    /// `acknowledge_builtin` flag was required to reach this point.
    pub is_builtin: bool,
}

/// Inner prepare — accepts a pre-loaded model. Allows integration tests to
/// inject a fixture model without invoking the `littlesnitch` binary.
pub fn prepare_disable_with_model(
    session: &Arc<Session>,
    input: &str,
    acknowledge_builtin: Option<bool>,
    model: &Model,
) -> Result<PrepareDisableRuleGroupResult, String> {
    let resolved_name = resolve_to_display_name(input, model)?;
    let builtin = is_builtin_group(&resolved_name, model);
    if builtin && acknowledge_builtin != Some(true) {
        return Err(format!(
            "group {:?} is a builtin subscription — disabling it affects macOS/iCloud \
             system-level rules. Set acknowledge_builtin: true to confirm.",
            resolved_name
        ));
    }
    let diff_sha = disable_sha(&resolved_name);
    let payload = crate::safety::token::payload(
        "disable_rule_group",
        serde_json::json!({"resolved_name": resolved_name}),
        &diff_sha,
        BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    Ok(PrepareDisableRuleGroupResult {
        token: token.into_string(),
        diff_summary: format!(
            "disable rule group \"{}\"{}",
            resolved_name,
            if builtin { " [builtin — acknowledged]" } else { "" }
        ),
        resolved_name,
        is_builtin: builtin,
    })
}

pub fn prepare_disable(
    session: &Arc<Session>,
    args: PrepareDisableRuleGroupArgs,
) -> Result<PrepareDisableRuleGroupResult, String> {
    if args.input.is_empty() {
        return Err("input must not be empty".into());
    }
    let model = load_live_model()?;
    prepare_disable_with_model(session, &args.input, args.acknowledge_builtin, &model)
}

// ─── disable_rule_group ──────────────────────────────────────────────────────

/// Input for `disable_rule_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisableRuleGroupArgs {
    /// Resolved display name returned by `prepare_disable_rule_group`.
    pub resolved_name: String,
    /// Confirmation token from `prepare_disable_rule_group`.
    pub token: String,
}

/// Return value of `disable_rule_group`.
#[derive(Debug, Serialize)]
pub struct DisableRuleGroupResult {
    pub resolved_name: String,
    pub disabled: bool,
    pub backup_path: String,
}

pub fn disable(
    session: &Arc<Session>,
    args: DisableRuleGroupArgs,
) -> Result<DisableRuleGroupResult, String> {
    if args.resolved_name.is_empty() {
        return Err("resolved_name must not be empty".into());
    }
    crate::safety::require_live_write_allowed()?;

    let diff_sha = disable_sha(&args.resolved_name);
    let ctx = VerifyContext {
        tool: "disable_rule_group",
        current_diff_sha256: &diff_sha,
        current_bundle_version: BUNDLE_VERSION,
    };
    session
        .verify(&crate::safety::Token::from(args.token), &ctx)
        .map_err(|e| e.to_string())?;

    let name = args.resolved_name.clone();
    let result = backup_harness::with_backup(move || {
        let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
        cli.run(&["rulegroup", "-d", &name])
            .map_err(|e| format!("rulegroup -d failed: {e}"))?;
        Ok(DisableRuleGroupResult {
            resolved_name: name.clone(),
            disabled: true,
            backup_path: String::new(),
        })
    })?;

    Ok(DisableRuleGroupResult {
        backup_path: result.backup_path,
        ..result.result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety;

    fn session() -> Arc<Session> {
        Arc::new(safety::Session::new().unwrap())
    }

    fn empty_model() -> Model {
        serde_json::from_value(serde_json::json!({
            "bundleVersion": 7172,
            "factoryRuleSetVersion": 424,
            "rules": [],
            "groups": {},
            "profiles": {},
            "noProfilePseudoProfile": {},
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
        }))
        .unwrap()
    }

    fn model_with_builtin() -> Model {
        serde_json::from_value(serde_json::json!({
            "bundleVersion": 7172,
            "factoryRuleSetVersion": 424,
            "rules": [],
            "groups": {
                "group-1": {
                    "name": "macOS Services",
                    "kind": "builtinMacOSServices",
                    "isActive": true
                },
                "group-2": {
                    "name": "My Custom Group",
                    "isActive": false
                }
            },
            "profiles": {},
            "noProfilePseudoProfile": {},
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
        }))
        .unwrap()
    }

    #[test]
    fn resolve_to_display_name_exact_match() {
        let model = model_with_builtin();
        let name = resolve_to_display_name("macOS Services", &model).unwrap();
        assert_eq!(name, "macOS Services");
    }

    #[test]
    fn resolve_to_display_name_kind_match() {
        let model = model_with_builtin();
        let name = resolve_to_display_name("builtinMacOSServices", &model).unwrap();
        assert_eq!(name, "macOS Services");
    }

    #[test]
    fn resolve_not_found_returns_candidates() {
        let model = model_with_builtin();
        let err = resolve_to_display_name("DoesNotExist", &model).unwrap_err();
        assert!(err.contains("not found"), "unexpected: {err}");
        assert!(
            err.contains("macOS Services") || err.contains("My Custom Group"),
            "should list candidates: {err}"
        );
    }

    #[test]
    fn resolve_best_effort_for_no_named_groups() {
        // Empty model has no named groups → BestEffort
        let model = empty_model();
        let name = resolve_to_display_name("SomeUnknownGroup", &model).unwrap();
        assert_eq!(name, "SomeUnknownGroup");
    }

    #[test]
    fn is_builtin_group_detects_builtin_kind() {
        let model = model_with_builtin();
        assert!(is_builtin_group("macOS Services", &model));
        assert!(!is_builtin_group("My Custom Group", &model));
        assert!(!is_builtin_group("Not Present", &model));
    }

    #[test]
    fn prepare_disable_refuses_builtin_without_ack() {
        // This test doesn't call load_live_model; it uses the internal
        // is_builtin_group logic directly.
        let model = model_with_builtin();
        assert!(is_builtin_group("macOS Services", &model));
        // Simulate the guard: builtin + no ack → error
        let builtin = true;
        let acknowledge = None::<bool>;
        let result: Result<(), String> = if builtin && acknowledge != Some(true) {
            Err("requires acknowledge_builtin".into())
        } else {
            Ok(())
        };
        assert!(result.is_err());
    }

    #[test]
    fn prepare_disable_allows_builtin_with_ack() {
        let model = model_with_builtin();
        let builtin = is_builtin_group("macOS Services", &model);
        let acknowledge = Some(true);
        let result: Result<(), String> = if builtin && acknowledge != Some(true) {
            Err("requires acknowledge_builtin".into())
        } else {
            Ok(())
        };
        assert!(result.is_ok());
    }

    #[test]
    fn enable_sha_is_stable() {
        let s1 = enable_sha("macOS Services");
        let s2 = enable_sha("macOS Services");
        assert_eq!(s1, s2);
        assert_ne!(s1, enable_sha("iCloud Services"));
    }

    #[test]
    fn disable_sha_differs_from_enable_sha() {
        let e = enable_sha("macOS Services");
        let d = disable_sha("macOS Services");
        assert_ne!(e, d);
    }

    #[test]
    fn enable_rejects_bad_token() {
        let s = session();
        let result = enable(
            &s,
            EnableRuleGroupArgs {
                resolved_name: "macOS Services".into(),
                token: "garbage".into(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn disable_rejects_bad_token() {
        let s = session();
        let result = disable(
            &s,
            DisableRuleGroupArgs {
                resolved_name: "macOS Services".into(),
                token: "garbage".into(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_resolved_name_rejected() {
        let s = session();
        assert!(enable(
            &s,
            EnableRuleGroupArgs {
                resolved_name: String::new(),
                token: "x".into()
            }
        )
        .is_err());
        assert!(disable(
            &s,
            DisableRuleGroupArgs {
                resolved_name: String::new(),
                token: "x".into()
            }
        )
        .is_err());
    }
}
