use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;
use crate::managed_dir::ManagedDir;
use crate::time_fmt::compact_iso8601_utc;

/// Input for the `export_model_backup` tool.
/// No required fields — the destination path is computed automatically.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportModelBackupArgs {}

/// Return value of `export_model_backup`.
#[derive(Debug, Serialize)]
pub struct ExportModelBackupResult {
    /// Absolute path to the written backup file.
    pub backup_path: String,
    /// Timestamp used in the filename (ISO 8601 UTC, basic format).
    pub timestamp: String,
}

pub fn run(_args: ExportModelBackupArgs) -> Result<ExportModelBackupResult, String> {
    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;

    let timestamp = timestamp_now();
    let filename = format!("{timestamp}.json");
    let backup_path = managed.backups.join(&filename);

    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;

    cli.run(&["export-model", backup_path.to_str().unwrap()])
        .map_err(|e| format!("export-model failed: {e}"))?;

    // Ensure the file landed and set mode 600.
    if !backup_path.exists() {
        return Err(format!(
            "export-model succeeded but file not found at {backup_path:?}"
        ));
    }
    std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot set permissions on {backup_path:?}: {e}"))?;

    Ok(ExportModelBackupResult {
        backup_path: backup_path.to_string_lossy().into_owned(),
        timestamp,
    })
}

/// Returns the current UTC time as a filename-safe ISO 8601 basic string,
/// e.g. `20240115T123456Z`. Uses no external crates.
fn timestamp_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    compact_iso8601_utc(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Algorithm correctness for `compact_iso8601_utc` is tested at the
    // canonical seam in `crate::time_fmt`. Tests below verify only the
    // wiring and shape that's local to this module.

    #[test]
    fn timestamp_now_has_correct_format() {
        let ts = timestamp_now();
        assert_eq!(ts.len(), 16, "unexpected length: {ts}");
        assert!(ts.ends_with('Z'), "must end with Z: {ts}");
        assert!(ts.contains('T'), "must contain T: {ts}");
        // All chars except T and Z should be ASCII digits
        let digits: String = ts.chars().filter(|c| *c != 'T' && *c != 'Z').collect();
        assert!(
            digits.chars().all(|c| c.is_ascii_digit()),
            "non-digit chars: {ts}"
        );
    }
}
