use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::adapter::LsCli;
use crate::safety::{Session, VerifyContext};
use crate::tools::backup_harness;

const BUNDLE_VERSION: &str = "factory-rule-groups";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha(canonical: &str) -> String {
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn update_sha(scope: Option<&str>) -> String {
    let s = scope.unwrap_or("all");
    sha(&format!(r#"{{"action":"update_factory_rule_groups","scope":"{}"}}"#, s))
}

// ─── prepare_update_factory_rule_groups ──────────────────────────────────────

/// Input for `prepare_update_factory_rule_groups`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareUpdateFactoryRuleGroupsArgs {
    /// Optional scope: `"apple"`, `"third-party"`, or `"all"` (default).
    pub scope: Option<String>,
}

/// Return value of `prepare_update_factory_rule_groups`.
#[derive(Debug, Serialize)]
pub struct PrepareUpdateFactoryRuleGroupsResult {
    pub token: String,
    pub diff_summary: String,
    pub scope: String,
}

pub fn prepare_update(
    session: &Arc<Session>,
    args: PrepareUpdateFactoryRuleGroupsArgs,
) -> Result<PrepareUpdateFactoryRuleGroupsResult, String> {
    let scope = validate_scope(args.scope.as_deref())?;
    let diff_sha = update_sha(args.scope.as_deref());
    let payload = crate::safety::token::payload(
        "update_factory_rule_groups",
        serde_json::json!({"scope": scope}),
        &diff_sha,
        BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    let description = match scope {
        "apple" => "update Apple factory rule groups only (`-a`)",
        "third-party" => "update third-party factory rule groups only (`-t`)",
        _ => "update all factory rule groups",
    };
    Ok(PrepareUpdateFactoryRuleGroupsResult {
        token: token.into_string(),
        diff_summary: description.into(),
        scope: scope.into(),
    })
}

// ─── update_factory_rule_groups ──────────────────────────────────────────────

/// Input for `update_factory_rule_groups`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateFactoryRuleGroupsArgs {
    /// Optional scope: `"apple"`, `"third-party"`, or `"all"` (default).
    /// Must match the scope in the issued token.
    pub scope: Option<String>,
    /// Confirmation token issued by `prepare_update_factory_rule_groups`.
    pub token: String,
}

/// Return value of `update_factory_rule_groups`.
#[derive(Debug, Serialize)]
pub struct UpdateFactoryRuleGroupsResult {
    pub scope: String,
    pub updated: bool,
    pub backup_path: String,
}

pub fn update(
    session: &Arc<Session>,
    args: UpdateFactoryRuleGroupsArgs,
) -> Result<UpdateFactoryRuleGroupsResult, String> {
    let scope = validate_scope(args.scope.as_deref())?;
    crate::safety::require_live_write_allowed()?;

    let diff_sha = update_sha(args.scope.as_deref());
    let ctx = VerifyContext {
        tool: "update_factory_rule_groups",
        current_diff_sha256: &diff_sha,
        current_bundle_version: BUNDLE_VERSION,
    };
    session
        .verify(&crate::safety::Token::from(args.token), &ctx)
        .map_err(|e| e.to_string())?;

    let scope_owned = scope.to_string();
    let result = backup_harness::with_backup(move || {
        let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
        let flag_args: Vec<&str> = match scope_owned.as_str() {
            "apple" => vec!["update-rule-groups", "-a"],
            "third-party" => vec!["update-rule-groups", "-t"],
            _ => vec!["update-rule-groups"],
        };
        cli.run(&flag_args)
            .map_err(|e| format!("update-rule-groups failed: {e}"))?;
        Ok(UpdateFactoryRuleGroupsResult {
            scope: scope_owned.clone(),
            updated: true,
            backup_path: String::new(),
        })
    })?;

    Ok(UpdateFactoryRuleGroupsResult {
        backup_path: result.backup_path,
        ..result.result
    })
}

fn validate_scope(scope: Option<&str>) -> Result<&'static str, String> {
    match scope {
        None | Some("all") => Ok("all"),
        Some("apple") => Ok("apple"),
        Some("third-party") => Ok("third-party"),
        Some(other) => Err(format!(
            "invalid scope {:?}: must be \"apple\", \"third-party\", or \"all\" (or omit)",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety;

    fn session() -> Arc<Session> {
        Arc::new(safety::Session::new().unwrap())
    }

    #[test]
    fn prepare_update_all_returns_token() {
        let s = session();
        let result = prepare_update(
            &s,
            PrepareUpdateFactoryRuleGroupsArgs { scope: None },
        )
        .unwrap();
        assert!(!result.token.is_empty());
        assert_eq!(result.scope, "all");
    }

    #[test]
    fn prepare_update_apple_scoped() {
        let s = session();
        let result = prepare_update(
            &s,
            PrepareUpdateFactoryRuleGroupsArgs {
                scope: Some("apple".into()),
            },
        )
        .unwrap();
        assert_eq!(result.scope, "apple");
        assert!(result.diff_summary.contains("Apple"));
    }

    #[test]
    fn prepare_update_rejects_invalid_scope() {
        let s = session();
        let err = prepare_update(
            &s,
            PrepareUpdateFactoryRuleGroupsArgs {
                scope: Some("invalid".into()),
            },
        )
        .unwrap_err();
        assert!(err.contains("invalid scope"), "unexpected: {err}");
    }

    #[test]
    fn update_rejects_bad_token() {
        let s = session();
        let result = update(
            &s,
            UpdateFactoryRuleGroupsArgs {
                scope: None,
                token: "garbage".into(),
            },
        );
        assert!(result.is_err());
    }
}
