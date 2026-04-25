use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;
use crate::managed_dir::ManagedDir;

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
    format_timestamp(secs)
}

fn format_timestamp(secs: u64) -> String {
    let (y, mo, d) = days_to_ymd(secs / 86400);
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{y:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z")
}

/// Hinnant's civil_from_days algorithm (days since Unix epoch → Y/M/D).
fn days_to_ymd(z: u64) -> (u64, u8, u8) {
    let z = z as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m as u8, d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_epoch() {
        assert_eq!(format_timestamp(0), "19700101T000000Z");
    }

    #[test]
    fn format_timestamp_known_date() {
        // 2020-01-01 00:00:00 UTC = 1577836800
        assert_eq!(format_timestamp(1577836800), "20200101T000000Z");
    }

    #[test]
    fn format_timestamp_with_time() {
        // 2024-01-15 12:34:56 UTC
        // 2024-01-15T00:00:00Z = 1705276800
        // + 12*3600 + 34*60 + 56 = 45296
        // = 1705322096
        assert_eq!(format_timestamp(1705322096), "20240115T123456Z");
    }

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
