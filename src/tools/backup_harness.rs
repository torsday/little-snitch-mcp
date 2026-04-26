//! Auto-backup harness for live-write operations.
//!
//! Every `live_write`-classified tool **must** call [`with_backup`] before
//! mutating the live Little Snitch model. The harness:
//!
//! 1. Runs `export_model_backup` to snapshot the current model.
//! 2. Captures the backup file path.
//! 3. Runs the caller-supplied mutation.
//! 4. Returns `(backup_path, result)` on success so the response can
//!    include the backup path for user reference.
//! 5. On failure, embeds the backup path in the error string so the user
//!    knows where to find the pre-mutation snapshot.

use serde::Serialize;

use crate::tools::export_model_backup::{self, ExportModelBackupArgs};

/// The combined output of a successful [`with_backup`] call.
#[derive(Debug, Serialize)]
pub struct BackupResult<T: Serialize> {
    /// Absolute path of the pre-mutation backup file.
    pub backup_path: String,
    /// The result returned by the operation.
    pub result: T,
}

/// Run `operation` behind a pre-mutation backup gate.
///
/// On success returns [`BackupResult`] containing both the backup path and
/// the operation result. On operation failure the error string is prefixed
/// with `[pre-mutation backup: <path>]` so the user can locate the snapshot.
///
/// If the backup itself fails the operation is **not** run — the caller
/// receives an error describing the backup failure.
pub fn with_backup<F, T>(operation: F) -> Result<BackupResult<T>, String>
where
    F: FnOnce() -> Result<T, String>,
    T: Serialize,
{
    let backup = export_model_backup::run(ExportModelBackupArgs {})
        .map_err(|e| format!("pre-mutation backup failed — refusing to proceed: {e}"))?;

    let backup_path = backup.backup_path;

    operation()
        .map(|result| BackupResult {
            backup_path: backup_path.clone(),
            result,
        })
        .map_err(|e| format!("[pre-mutation backup: {backup_path}] {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_op() -> Result<serde_json::Value, String> {
        Ok(json!({"done": true}))
    }

    fn err_op() -> Result<serde_json::Value, String> {
        Err("operation exploded".to_string())
    }

    #[test]
    fn with_backup_success_contains_result() {
        // We cannot run the real backup (no live LS binary in CI).
        // Test the harness logic by faking the backup step.
        let result = simulate_with_backup(ok_op, "/tmp/backup.json".to_string());
        let r = result.unwrap();
        assert_eq!(r.backup_path, "/tmp/backup.json");
        assert_eq!(r.result, json!({"done": true}));
    }

    #[test]
    fn with_backup_operation_failure_includes_path() {
        let result = simulate_with_backup(err_op, "/tmp/backup.json".to_string());
        let err = result.unwrap_err();
        assert!(
            err.contains("/tmp/backup.json"),
            "backup path missing from error: {err}"
        );
        assert!(
            err.contains("operation exploded"),
            "original error missing: {err}"
        );
    }

    #[test]
    fn backup_result_serializes_both_fields() {
        let r = BackupResult {
            backup_path: "/tmp/foo.json".to_string(),
            result: json!(42),
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["backup_path"], "/tmp/foo.json");
        assert_eq!(json["result"], 42);
    }

    /// Test helper: exercise the harness logic without needing a live LS binary.
    fn simulate_with_backup<F, T>(
        operation: F,
        fake_path: String,
    ) -> Result<BackupResult<T>, String>
    where
        F: FnOnce() -> Result<T, String>,
        T: Serialize,
    {
        operation()
            .map(|result| BackupResult {
                backup_path: fake_path.clone(),
                result,
            })
            .map_err(|e| format!("[pre-mutation backup: {fake_path}] {e}"))
    }
}
