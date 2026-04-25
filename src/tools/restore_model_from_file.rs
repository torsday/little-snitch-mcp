//! `restore_model_from_file` — escape hatch for advanced users.
//!
//! Reads a manually-edited model JSON from a file under the managed
//! directory and restores it whole-cloth via `restore-model -t`.
//! **Strongest classification** (`live_write_strong`) per ADR-0004:
//! the operator is replacing the entire live model from a file we
//! didn't author, so the safety guarantees of the per-rule chain
//! don't apply — the only thing standing between the file and the
//! live model is the operator's explicit acknowledgement.
//!
//! # Path security
//!
//! The file MUST live under the managed root. We canonicalize before
//! the prefix check so symlink escape (`/managed/escape -> /etc/...`)
//! is refused. The check happens at both prepare and apply time.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Model, canonical_value};
use crate::safety::{Session, Token, TokenError, VerifyContext, token};

/// Tool input shape (apply side).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RestoreModelFromFileArgs {
    /// Absolute path to the model JSON. Must be under the managed root.
    pub file_path: PathBuf,
    /// Confirmation token from `prepare_restore_model_from_file`.
    pub token: String,
}

/// Tool input shape (prepare side).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareRestoreFromFileArgs {
    pub file_path: PathBuf,
}

/// Result of a successful prepare.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PrepareRestoreResult {
    pub token: String,
    /// SHA-256 of the canonicalized JSON of the proposed new model.
    /// Operator can compare this against any external audit hash.
    pub diff_sha256: String,
    pub expires_in_seconds: u64,
}

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum RestoreFromFileError {
    #[error("PATH_OUTSIDE_MANAGED_DIR: {path:?} is not under the managed root {root:?}")]
    PathOutsideManagedDir { path: PathBuf, root: PathBuf },
    #[error("FILE_NOT_FOUND: {0:?}")]
    FileNotFound(PathBuf),
    #[error("READ_FAILED: cannot read {path:?}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("INVALID_MODEL_JSON: {path:?} did not parse as a Model: {source}")]
    InvalidModelJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("token verify failed: {0}")]
    Token(#[from] TokenError),
}

/// Pure prepare: validate the path is under managed root, parse the
/// file as a `Model`, hash its canonical form, issue a token bound to
/// (tool="restore_model_from_file", target=file_path,
/// diff_sha256=hash-of-new-model, bundle_version=current.bundle_version).
pub fn prepare_pure(
    session: &Arc<Session>,
    file_path: &Path,
    managed_root: &Path,
    current: &Model,
    now_unix_secs: u64,
) -> Result<PrepareRestoreResult, RestoreFromFileError> {
    let new_model = read_and_validate(file_path, managed_root)?;
    let bundle_version = current.bundle_version.to_string();
    let diff_sha256 = canonical_model_sha256(&new_model);
    let target = serde_json::json!({
        "op": "restore_model_from_file",
        "file_path": file_path.to_string_lossy(),
    });
    let payload = token::payload(
        "restore_model_from_file",
        target,
        &diff_sha256,
        &bundle_version,
        now_unix_secs,
        token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    Ok(PrepareRestoreResult {
        token: token.into_string(),
        diff_sha256,
        expires_in_seconds: token::DEFAULT_TTL_SECS,
    })
}

/// Pure apply: same validation as prepare, then verify token.
/// Returns the parsed Model (caller writes it to a temp file and calls
/// `restore-model -t <temp>`).
pub fn apply_pure(
    file_path: &Path,
    token_str: String,
    managed_root: &Path,
    current: &Model,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<Model, RestoreFromFileError> {
    let new_model = read_and_validate(file_path, managed_root)?;
    let bundle_version = current.bundle_version.to_string();
    let diff_sha256 = canonical_model_sha256(&new_model);
    let token = Token::from(token_str);
    let ctx = VerifyContext {
        tool: "restore_model_from_file",
        current_diff_sha256: &diff_sha256,
        current_bundle_version: &bundle_version,
    };
    session.verify_at(&token, &ctx, now_unix_secs)?;
    Ok(new_model)
}

/// Validate the path is under managed root, then read and parse.
///
/// Canonicalizes both sides before the prefix check so a symlink
/// pointing outside the managed root is refused.
fn read_and_validate(file_path: &Path, managed_root: &Path) -> Result<Model, RestoreFromFileError> {
    if !file_path.exists() {
        return Err(RestoreFromFileError::FileNotFound(file_path.to_path_buf()));
    }

    // Canonicalize both sides — defends against symlink escape.
    // canonicalize() requires the path to exist, which we just confirmed.
    let canonical_path =
        file_path
            .canonicalize()
            .map_err(|source| RestoreFromFileError::ReadFailed {
                path: file_path.to_path_buf(),
                source,
            })?;
    let canonical_root =
        managed_root
            .canonicalize()
            .map_err(|source| RestoreFromFileError::ReadFailed {
                path: managed_root.to_path_buf(),
                source,
            })?;

    if !canonical_path.starts_with(&canonical_root) {
        return Err(RestoreFromFileError::PathOutsideManagedDir {
            path: canonical_path,
            root: canonical_root,
        });
    }

    let bytes =
        std::fs::read(&canonical_path).map_err(|source| RestoreFromFileError::ReadFailed {
            path: canonical_path.clone(),
            source,
        })?;
    serde_json::from_slice::<Model>(&bytes).map_err(|source| {
        RestoreFromFileError::InvalidModelJson {
            path: canonical_path,
            source,
        }
    })
}

fn canonical_model_sha256(model: &Model) -> String {
    let v = serde_json::to_value(model).expect("Model serializes");
    let canon = canonical_value(v);
    let bytes = serde_json::to_vec(&canon).expect("canonical JSON");
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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

    const FIXED_NOW: u64 = 1_777_200_000;

    /// Set up a temp dir to act as the managed root. Returns
    /// (tmpdir guard, canonicalized root path).
    fn temp_managed_root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonicalize");
        (dir, root)
    }

    fn write_model_file(root: &Path, name: &str, model: &Model) -> PathBuf {
        let path = root.join(name);
        let serialized = serde_json::to_vec_pretty(model).unwrap();
        std::fs::write(&path, serialized).unwrap();
        path
    }

    // ---------- happy path ----------

    #[test]
    fn prepare_then_apply_round_trip() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let new_model = empty_model();
        let path = write_model_file(&root, "new_model.json", &new_model);

        let current = empty_model();
        let prep = prepare_pure(&s, &path, &root, &current, FIXED_NOW).unwrap();
        assert!(!prep.token.is_empty());
        assert_eq!(prep.expires_in_seconds, token::DEFAULT_TTL_SECS);

        let restored = apply_pure(&path, prep.token, &root, &current, &s, FIXED_NOW).unwrap();
        assert_eq!(restored.bundle_version, new_model.bundle_version);
    }

    // ---------- path security ----------

    #[test]
    fn refuses_path_outside_managed_dir() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let (_other, other_root) = temp_managed_root();
        let new_model = empty_model();
        let outside_path = write_model_file(&other_root, "model.json", &new_model);
        let current = empty_model();

        let err = prepare_pure(&s, &outside_path, &root, &current, FIXED_NOW).unwrap_err();
        match err {
            RestoreFromFileError::PathOutsideManagedDir { .. } => {}
            other => panic!("expected PathOutsideManagedDir, got {other:?}"),
        }
    }

    #[test]
    fn refuses_symlink_escape() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let (_outside, outside_root) = temp_managed_root();

        // Real model lives outside managed root.
        let real_path = write_model_file(&outside_root, "real_model.json", &empty_model());

        // Symlink lives inside managed root, points to the outside model.
        let sym_path = root.join("escape.json");
        symlink(&real_path, &sym_path).unwrap();

        let current = empty_model();
        let err = prepare_pure(&s, &sym_path, &root, &current, FIXED_NOW).unwrap_err();
        match err {
            RestoreFromFileError::PathOutsideManagedDir { path, .. } => {
                // canonical path should resolve to the outside-root location
                assert!(
                    !path.starts_with(&root),
                    "canonical path should be outside managed root after symlink resolution: {path:?}"
                );
            }
            other => panic!("expected PathOutsideManagedDir, got {other:?}"),
        }
    }

    #[test]
    fn refuses_missing_file() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let bogus = root.join("does_not_exist.json");
        let current = empty_model();

        let err = prepare_pure(&s, &bogus, &root, &current, FIXED_NOW).unwrap_err();
        assert!(matches!(err, RestoreFromFileError::FileNotFound(_)));
    }

    #[test]
    fn refuses_malformed_json() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let bad = root.join("bad.json");
        std::fs::write(&bad, b"this is not json").unwrap();
        let current = empty_model();

        let err = prepare_pure(&s, &bad, &root, &current, FIXED_NOW).unwrap_err();
        assert!(matches!(err, RestoreFromFileError::InvalidModelJson { .. }));
    }

    #[test]
    fn refuses_json_that_does_not_match_model_schema() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let bad = root.join("not_model.json");
        std::fs::write(&bad, br#"{"hello": "world"}"#).unwrap();
        let current = empty_model();

        // Missing required top-level fields like bundleVersion → parse error.
        let err = prepare_pure(&s, &bad, &root, &current, FIXED_NOW).unwrap_err();
        assert!(matches!(err, RestoreFromFileError::InvalidModelJson { .. }));
    }

    // ---------- token binding ----------

    #[test]
    fn diff_drift_when_file_modified_between_prepare_and_apply() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let mut new_model = empty_model();
        let path = write_model_file(&root, "model.json", &new_model);
        let current = empty_model();

        let prep = prepare_pure(&s, &path, &root, &current, FIXED_NOW).unwrap();

        // Tamper with the file between prepare and apply.
        new_model.bundle_version = 999;
        write_model_file(&root, "model.json", &new_model);

        let err = apply_pure(&path, prep.token, &root, &current, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(
            err,
            RestoreFromFileError::Token(TokenError::DiffDrift)
        ));
    }

    #[test]
    fn schema_drift_when_live_bundle_version_changes() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let new_model = empty_model();
        let path = write_model_file(&root, "model.json", &new_model);

        let mut prepare_state = empty_model();
        prepare_state.bundle_version = 1;
        let prep = prepare_pure(&s, &path, &root, &prepare_state, FIXED_NOW).unwrap();

        // Live LS upgraded between prepare and apply.
        let mut apply_state = empty_model();
        apply_state.bundle_version = 2;
        let err = apply_pure(&path, prep.token, &root, &apply_state, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(
            err,
            RestoreFromFileError::Token(TokenError::SchemaDrift)
        ));
    }

    #[test]
    fn replay_rejected() {
        let s = session();
        let (_dir, root) = temp_managed_root();
        let path = write_model_file(&root, "model.json", &empty_model());
        let current = empty_model();
        let prep = prepare_pure(&s, &path, &root, &current, FIXED_NOW).unwrap();

        apply_pure(&path, prep.token.clone(), &root, &current, &s, FIXED_NOW).unwrap();
        let err = apply_pure(&path, prep.token, &root, &current, &s, FIXED_NOW).unwrap_err();
        assert!(matches!(
            err,
            RestoreFromFileError::Token(TokenError::Replay)
        ));
    }
}
