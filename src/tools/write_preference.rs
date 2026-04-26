use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::cli::adapter::LsCli;
use crate::safety::{Session, Token, VerifyContext, require_writable};

/// Stable sentinel bundle_version for preference operations.
/// Preferences are not schema-versioned like the model, so schema-drift
/// detection is kept consistent via this sentinel rather than a live
/// export-model round-trip on every call.
const PREFS_BUNDLE_VERSION: &str = "preferences";

// ─── prepare_write_preference ───────────────────────────────────────────────

/// Input for `prepare_write_preference`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareWritePreferenceArgs {
    /// Preference key (camelCase). Must be on the write allowlist.
    pub key: String,
    /// New value as a JSON-typed value (boolean, string, number, etc.).
    pub value: serde_json::Value,
}

/// Return value of `prepare_write_preference`.
#[derive(Debug, Serialize)]
pub struct PrepareWritePreferenceResult {
    /// Confirmation token. Pass this to `write_preference` after user approval.
    pub token: String,
    /// Human-readable description of the proposed change.
    pub diff_summary: String,
    /// The key being written (echoed for confirmation display).
    pub key: String,
    /// The value being written (echoed for confirmation display).
    pub value: serde_json::Value,
}

pub fn prepare_write(
    session: &Arc<Session>,
    args: PrepareWritePreferenceArgs,
) -> Result<PrepareWritePreferenceResult, String> {
    require_writable(&args.key).map_err(|e| e.to_string())?;

    let diff_sha = compute_write_sha(&args.key, &args.value);
    let payload = crate::safety::token::payload(
        "write_preference",
        serde_json::json!({"key": args.key}),
        &diff_sha,
        PREFS_BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    let diff_summary = format!(
        "write globalDefaults[\"{}\"]\n  new value: {}",
        args.key,
        serde_json::to_string_pretty(&args.value).unwrap_or_else(|_| args.value.to_string())
    );
    Ok(PrepareWritePreferenceResult {
        token: token.into_string(),
        diff_summary,
        key: args.key,
        value: args.value,
    })
}

// ─── write_preference ────────────────────────────────────────────────────────

/// Input for `write_preference`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WritePreferenceArgs {
    /// Preference key (camelCase). Must match the key in the issued token.
    pub key: String,
    /// New value. Must match the value in the issued token.
    pub value: serde_json::Value,
    /// Confirmation token issued by `prepare_write_preference`.
    pub token: String,
}

/// Return value of `write_preference`.
#[derive(Debug, Serialize)]
pub struct WritePreferenceResult {
    pub key: String,
    pub value: serde_json::Value,
    pub written: bool,
}

pub fn write(
    session: &Arc<Session>,
    args: WritePreferenceArgs,
) -> Result<WritePreferenceResult, String> {
    require_writable(&args.key).map_err(|e| e.to_string())?;
    crate::safety::require_live_write_allowed()?;

    let diff_sha = compute_write_sha(&args.key, &args.value);
    let token = Token::from(args.token);
    session
        .verify(
            &token,
            &VerifyContext {
                tool: "write_preference",
                current_diff_sha256: &diff_sha,
                current_bundle_version: PREFS_BUNDLE_VERSION,
            },
        )
        .map_err(|e| format!("token verification failed: {e}"))?;

    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    let value_str = json_value_to_cli_arg(&args.value);
    cli.run(&["write-preference", &args.key, &value_str])
        .map_err(|e| format!("write-preference failed: {e}"))?;

    Ok(WritePreferenceResult {
        key: args.key,
        value: args.value,
        written: true,
    })
}

// ─── prepare_remove_preference ───────────────────────────────────────────────

/// Input for `prepare_remove_preference`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareRemovePreferenceArgs {
    /// Preference key (camelCase). Must be on the write allowlist.
    pub key: String,
}

/// Return value of `prepare_remove_preference`.
#[derive(Debug, Serialize)]
pub struct PrepareRemovePreferenceResult {
    /// Confirmation token. Pass this to `remove_preference` after user approval.
    pub token: String,
    /// Human-readable description of the proposed change.
    pub diff_summary: String,
    /// The key being removed (echoed for confirmation display).
    pub key: String,
}

pub fn prepare_remove(
    session: &Arc<Session>,
    args: PrepareRemovePreferenceArgs,
) -> Result<PrepareRemovePreferenceResult, String> {
    require_writable(&args.key).map_err(|e| e.to_string())?;

    let diff_sha = compute_remove_sha(&args.key);
    let payload = crate::safety::token::payload(
        "remove_preference",
        serde_json::json!({"key": args.key}),
        &diff_sha,
        PREFS_BUNDLE_VERSION,
        now_unix(),
        crate::safety::token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    let diff_summary = format!("remove globalDefaults[\"{}\"]", args.key);
    Ok(PrepareRemovePreferenceResult {
        token: token.into_string(),
        diff_summary,
        key: args.key,
    })
}

// ─── remove_preference ───────────────────────────────────────────────────────

/// Input for `remove_preference`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemovePreferenceArgs {
    /// Preference key (camelCase). Must match the key in the issued token.
    pub key: String,
    /// Confirmation token issued by `prepare_remove_preference`.
    pub token: String,
}

/// Return value of `remove_preference`.
#[derive(Debug, Serialize)]
pub struct RemovePreferenceResult {
    pub key: String,
    pub removed: bool,
}

pub fn remove(
    session: &Arc<Session>,
    args: RemovePreferenceArgs,
) -> Result<RemovePreferenceResult, String> {
    require_writable(&args.key).map_err(|e| e.to_string())?;
    crate::safety::require_live_write_allowed()?;

    let diff_sha = compute_remove_sha(&args.key);
    let token = Token::from(args.token);
    session
        .verify(
            &token,
            &VerifyContext {
                tool: "remove_preference",
                current_diff_sha256: &diff_sha,
                current_bundle_version: PREFS_BUNDLE_VERSION,
            },
        )
        .map_err(|e| format!("token verification failed: {e}"))?;

    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    cli.run(&["write-preference", "-r", &args.key])
        .map_err(|e| format!("write-preference -r failed: {e}"))?;

    Ok(RemovePreferenceResult {
        key: args.key,
        removed: true,
    })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn compute_write_sha(key: &str, value: &serde_json::Value) -> String {
    // Canonical JSON sorted by key to ensure determinism.
    let canonical = serde_json::json!({ "action": "write", "key": key, "value": value });
    hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
}

fn compute_remove_sha(key: &str) -> String {
    let canonical = serde_json::json!({ "action": "remove", "key": key });
    hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
}

/// Convert a JSON value to a string acceptable by the `littlesnitch write-preference` CLI.
/// Booleans → "true"/"false", strings → unquoted, numbers → string repr, others → JSON.
fn json_value_to_cli_arg(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_write_sha_is_deterministic() {
        let sha1 = compute_write_sha("activeSilentMode", &serde_json::Value::Bool(true));
        let sha2 = compute_write_sha("activeSilentMode", &serde_json::Value::Bool(true));
        assert_eq!(sha1, sha2);
    }

    #[test]
    fn compute_write_sha_differs_by_key() {
        let sha1 = compute_write_sha("activeSilentMode", &serde_json::Value::Bool(true));
        let sha2 = compute_write_sha("confirmAutomatically", &serde_json::Value::Bool(true));
        assert_ne!(sha1, sha2);
    }

    #[test]
    fn compute_write_sha_differs_by_value() {
        let sha1 = compute_write_sha("activeSilentMode", &serde_json::Value::Bool(true));
        let sha2 = compute_write_sha("activeSilentMode", &serde_json::Value::Bool(false));
        assert_ne!(sha1, sha2);
    }

    #[test]
    fn compute_remove_sha_is_deterministic() {
        let sha1 = compute_remove_sha("activeSilentMode");
        let sha2 = compute_remove_sha("activeSilentMode");
        assert_eq!(sha1, sha2);
    }

    #[test]
    fn write_sha_and_remove_sha_differ_for_same_key() {
        let ws = compute_write_sha("activeSilentMode", &serde_json::Value::Bool(true));
        let rs = compute_remove_sha("activeSilentMode");
        assert_ne!(ws, rs);
    }

    #[test]
    fn json_value_to_cli_arg_bool() {
        assert_eq!(
            json_value_to_cli_arg(&serde_json::Value::Bool(true)),
            "true"
        );
        assert_eq!(
            json_value_to_cli_arg(&serde_json::Value::Bool(false)),
            "false"
        );
    }

    #[test]
    fn json_value_to_cli_arg_string() {
        let v = serde_json::Value::String("hello".to_string());
        assert_eq!(json_value_to_cli_arg(&v), "hello");
    }

    #[test]
    fn prepare_write_rejected_for_hard_deny_key() {
        use std::sync::Arc;
        let session = Arc::new(Session::new().unwrap());
        let result = prepare_write(
            &session,
            PrepareWritePreferenceArgs {
                key: "networkFilterEnabled".to_string(),
                value: serde_json::Value::Bool(false),
            },
        );
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("networkFilterEnabled"),
            "error should name the key: {msg}"
        );
    }

    #[test]
    fn prepare_write_rejected_for_unknown_key() {
        use std::sync::Arc;
        let session = Arc::new(Session::new().unwrap());
        let result = prepare_write(
            &session,
            PrepareWritePreferenceArgs {
                key: "someUnknownKey".to_string(),
                value: serde_json::Value::Bool(true),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn prepare_write_succeeds_for_allowlisted_key() {
        use std::sync::Arc;
        let session = Arc::new(Session::new().unwrap());
        let result = prepare_write(
            &session,
            PrepareWritePreferenceArgs {
                key: "activeSilentMode".to_string(),
                value: serde_json::Value::Bool(true),
            },
        );
        assert!(result.is_ok(), "unexpected err: {:?}", result.err());
        let r = result.unwrap();
        assert!(!r.token.is_empty());
        assert!(r.diff_summary.contains("activeSilentMode"));
    }

    #[test]
    fn prepare_then_token_verifies_for_write() {
        use std::sync::Arc;
        let session = Arc::new(Session::new().unwrap());
        let key = "activeSilentMode";
        let value = serde_json::Value::Bool(true);
        let prep = prepare_write(
            &session,
            PrepareWritePreferenceArgs {
                key: key.to_string(),
                value: value.clone(),
            },
        )
        .unwrap();

        let diff_sha = compute_write_sha(key, &value);
        let token = Token::from(prep.token);
        let result = session.verify(
            &token,
            &VerifyContext {
                tool: "write_preference",
                current_diff_sha256: &diff_sha,
                current_bundle_version: PREFS_BUNDLE_VERSION,
            },
        );
        assert!(result.is_ok(), "token should verify: {:?}", result.err());
    }

    #[test]
    fn prepare_then_token_verifies_for_remove() {
        use std::sync::Arc;
        let session = Arc::new(Session::new().unwrap());
        let key = "activeSilentMode";
        let prep = prepare_remove(
            &session,
            PrepareRemovePreferenceArgs {
                key: key.to_string(),
            },
        )
        .unwrap();

        let diff_sha = compute_remove_sha(key);
        let token = Token::from(prep.token);
        let result = session.verify(
            &token,
            &VerifyContext {
                tool: "remove_preference",
                current_diff_sha256: &diff_sha,
                current_bundle_version: PREFS_BUNDLE_VERSION,
            },
        );
        assert!(result.is_ok(), "token should verify: {:?}", result.err());
    }
}
