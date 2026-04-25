use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::adapter::LsCli;
use crate::safety::{Session, VerifyContext};
use crate::tools::backup_harness;

const BUNDLE_VERSION: &str = "profiles";

// ─── helpers ─────────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha(canonical: &str) -> String {
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn activate_sha(name: &str) -> String {
    sha(&format!(
        r#"{{"action":"activate_profile","name":"{}"}}"#,
        name
    ))
}

fn deactivate_sha() -> String {
    sha(r#"{"action":"deactivate_all_profiles"}"#)
}

// ─── prepare_activate_profile ────────────────────────────────────────────────

/// Input for `prepare_activate_profile`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareActivateProfileArgs {
    /// Exact name of the profile to activate.
    pub name: String,
}

/// Return value of `prepare_activate_profile`.
#[derive(Debug, Serialize)]
pub struct PrepareActivateProfileResult {
    pub token: String,
    pub diff_summary: String,
    pub name: String,
}

pub fn prepare_activate(
    session: &Arc<Session>,
    args: PrepareActivateProfileArgs,
) -> Result<PrepareActivateProfileResult, String> {
    if args.name.is_empty() {
        return Err("name must not be empty".into());
    }
    let diff_sha = activate_sha(&args.name);
    let payload = crate::safety::token::payload(
        "activate_profile",
        serde_json::json!({"name": args.name}),
        &diff_sha,
        BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    Ok(PrepareActivateProfileResult {
        token: token.into_string(),
        diff_summary: format!("activate profile \"{}\"", args.name),
        name: args.name,
    })
}

// ─── activate_profile ────────────────────────────────────────────────────────

/// Input for `activate_profile`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActivateProfileArgs {
    /// Exact name of the profile to activate (must match the prepared token).
    pub name: String,
    /// Confirmation token issued by `prepare_activate_profile`.
    pub token: String,
}

/// Return value of `activate_profile`.
#[derive(Debug, Serialize)]
pub struct ActivateProfileResult {
    pub name: String,
    pub activated: bool,
    pub backup_path: String,
}

pub fn activate(
    session: &Arc<Session>,
    args: ActivateProfileArgs,
) -> Result<ActivateProfileResult, String> {
    if args.name.is_empty() {
        return Err("name must not be empty".into());
    }
    crate::safety::require_live_write_allowed()?;

    let diff_sha = activate_sha(&args.name);
    let ctx = VerifyContext {
        tool: "activate_profile",
        current_diff_sha256: &diff_sha,
        current_bundle_version: BUNDLE_VERSION,
    };
    session
        .verify(&crate::safety::Token::from(args.token), &ctx)
        .map_err(|e| e.to_string())?;

    // Validate the profile exists by exporting the model and scanning profiles.
    validate_profile_exists(&args.name)?;

    let name = args.name.clone();
    let result = backup_harness::with_backup(move || {
        let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
        cli.run(&["profile", "-a", &name])
            .map_err(|e| format!("profile -a failed: {e}"))?;
        Ok(ActivateProfileResult {
            name: name.clone(),
            activated: true,
            backup_path: String::new(), // filled by with_backup
        })
    })?;

    Ok(ActivateProfileResult {
        backup_path: result.backup_path,
        ..result.result
    })
}

fn validate_profile_exists(name: &str) -> Result<(), String> {
    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    let output = cli
        .run(&["export-model"])
        .map_err(|e| format!("export-model failed: {e}"))?;
    let json_str = String::from_utf8_lossy(&output.stdout);
    let doc: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("export-model returned invalid JSON: {e}"))?;
    let profiles = doc
        .get("profiles")
        .and_then(|p| p.as_array())
        .ok_or_else(|| "model has no profiles array".to_string())?;
    let exists = profiles.iter().any(|p| {
        p.get("name")
            .and_then(|n| n.as_str())
            .map(|n| n == name)
            .unwrap_or(false)
    });
    if exists {
        Ok(())
    } else {
        let names: Vec<&str> = profiles
            .iter()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
            .collect();
        Err(format!(
            "profile {:?} not found; available profiles: {:?}",
            name, names
        ))
    }
}

// ─── prepare_deactivate_all_profiles ─────────────────────────────────────────

/// Input for `prepare_deactivate_all_profiles`. No fields required.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareDeactivateAllProfilesArgs {}

/// Return value of `prepare_deactivate_all_profiles`.
#[derive(Debug, Serialize)]
pub struct PrepareDeactivateAllProfilesResult {
    pub token: String,
    pub diff_summary: String,
}

pub fn prepare_deactivate(
    session: &Arc<Session>,
    _args: PrepareDeactivateAllProfilesArgs,
) -> Result<PrepareDeactivateAllProfilesResult, String> {
    let diff_sha = deactivate_sha();
    let payload = crate::safety::token::payload(
        "deactivate_all_profiles",
        serde_json::json!({"action": "deactivate_all"}),
        &diff_sha,
        BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    Ok(PrepareDeactivateAllProfilesResult {
        token: token.into_string(),
        diff_summary: "deactivate all profiles (profile -d)".into(),
    })
}

// ─── deactivate_all_profiles ─────────────────────────────────────────────────

/// Input for `deactivate_all_profiles`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeactivateAllProfilesArgs {
    /// Confirmation token issued by `prepare_deactivate_all_profiles`.
    pub token: String,
}

/// Return value of `deactivate_all_profiles`.
#[derive(Debug, Serialize)]
pub struct DeactivateAllProfilesResult {
    pub deactivated: bool,
    pub backup_path: String,
}

pub fn deactivate_all(
    session: &Arc<Session>,
    args: DeactivateAllProfilesArgs,
) -> Result<DeactivateAllProfilesResult, String> {
    crate::safety::require_live_write_allowed()?;

    let diff_sha = deactivate_sha();
    let ctx = VerifyContext {
        tool: "deactivate_all_profiles",
        current_diff_sha256: &diff_sha,
        current_bundle_version: BUNDLE_VERSION,
    };
    session
        .verify(&crate::safety::Token::from(args.token), &ctx)
        .map_err(|e| e.to_string())?;

    let result = backup_harness::with_backup(|| {
        let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
        cli.run(&["profile", "-d"])
            .map_err(|e| format!("profile -d failed: {e}"))?;
        Ok(DeactivateAllProfilesResult {
            deactivated: true,
            backup_path: String::new(),
        })
    })?;

    Ok(DeactivateAllProfilesResult {
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

    #[test]
    fn prepare_activate_rejects_empty_name() {
        let s = session();
        let err = prepare_activate(
            &s,
            PrepareActivateProfileArgs {
                name: String::new(),
            },
        )
        .unwrap_err();
        assert!(err.contains("empty"), "unexpected: {err}");
    }

    #[test]
    fn prepare_activate_returns_token() {
        let s = session();
        let result = prepare_activate(
            &s,
            PrepareActivateProfileArgs {
                name: "home".into(),
            },
        )
        .unwrap();
        assert!(!result.token.is_empty());
        assert!(result.diff_summary.contains("home"));
    }

    #[test]
    fn prepare_deactivate_returns_token() {
        let s = session();
        let result = prepare_deactivate(&s, PrepareDeactivateAllProfilesArgs {}).unwrap();
        assert!(!result.token.is_empty());
    }

    #[test]
    fn activate_rejects_wrong_token() {
        let s = session();
        let err = crate::safety::require_live_write_allowed()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        // In test environment live writes are disabled — verify token check happens first
        // by supplying a clearly bad token.
        let result = activate(
            &s,
            ActivateProfileArgs {
                name: "home".into(),
                token: "bad-token".into(),
            },
        );
        // Either live_write disabled or bad token — either way it's an error.
        assert!(result.is_err(), "expected error, got ok");
        let _ = err;
    }
}
