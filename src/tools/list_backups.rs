use std::path::Path;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::managed_dir::ManagedDir;

/// Input for the `list_backups` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListBackupsArgs {}

/// A single entry in the backups listing.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct BackupEntry {
    /// Filename (not full path).
    pub filename: String,
    /// Timestamp string parsed from the filename (e.g. `20240115T123456Z`).
    pub timestamp: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// Return value of `list_backups`.
#[derive(Debug, Serialize)]
pub struct ListBackupsResult {
    /// Backup entries sorted newest-first. Empty when no backups exist.
    pub backups: Vec<BackupEntry>,
    /// Absolute path of the backups directory.
    pub backups_dir: String,
}

pub fn run(_args: ListBackupsArgs) -> Result<ListBackupsResult, String> {
    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;
    run_with_root(_args, &managed.backups)
}

pub fn run_with_root(
    _args: ListBackupsArgs,
    backups_dir: &Path,
) -> Result<ListBackupsResult, String> {
    let backups_dir_str = backups_dir.to_string_lossy().into_owned();

    if !backups_dir.exists() {
        return Ok(ListBackupsResult {
            backups: vec![],
            backups_dir: backups_dir_str,
        });
    }

    let read_dir = std::fs::read_dir(backups_dir)
        .map_err(|e| format!("cannot read backups directory: {e}"))?;

    let mut entries: Vec<BackupEntry> = read_dir
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Only include files that look like backup timestamps: digits + T + digits + Z + .json
            if !is_backup_filename(&name) {
                return None;
            }
            let meta = entry.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            let timestamp = name.strip_suffix(".json").unwrap_or(&name).to_owned();
            Some(BackupEntry {
                filename: name,
                timestamp,
                size_bytes: meta.len(),
            })
        })
        .collect();

    // Sort newest-first (timestamps are lexicographically ordered: YYYYMMDDThhmmssZ).
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(ListBackupsResult {
        backups: entries,
        backups_dir: backups_dir_str,
    })
}

/// Returns true for filenames like `20240115T123456Z.json`.
fn is_backup_filename(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    // stem must be exactly 16 chars: YYYYMMDDThhmmssZ
    if stem.len() != 16 {
        return false;
    }
    let bytes = stem.as_bytes();
    bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..15].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_backup(dir: &Path, name: &str, size: u64) {
        let path = dir.join(name);
        // Write `size` bytes of zeros.
        std::fs::write(&path, vec![0u8; size as usize]).unwrap();
    }

    #[test]
    fn empty_dir_returns_empty_list() {
        let tmp = TempDir::new().unwrap();
        let result = run_with_root(ListBackupsArgs {}, tmp.path()).unwrap();
        assert!(result.backups.is_empty());
    }

    #[test]
    fn nonexistent_dir_returns_empty_list() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("no-such-dir");
        let result = run_with_root(ListBackupsArgs {}, &missing).unwrap();
        assert!(result.backups.is_empty());
    }

    #[test]
    fn single_backup_returned() {
        let tmp = TempDir::new().unwrap();
        make_backup(tmp.path(), "20240115T123456Z.json", 1024);
        let result = run_with_root(ListBackupsArgs {}, tmp.path()).unwrap();
        assert_eq!(result.backups.len(), 1);
        assert_eq!(result.backups[0].filename, "20240115T123456Z.json");
        assert_eq!(result.backups[0].timestamp, "20240115T123456Z");
        assert_eq!(result.backups[0].size_bytes, 1024);
    }

    #[test]
    fn multiple_backups_sorted_newest_first() {
        let tmp = TempDir::new().unwrap();
        make_backup(tmp.path(), "20240101T000000Z.json", 100);
        make_backup(tmp.path(), "20240315T120000Z.json", 200);
        make_backup(tmp.path(), "20240201T060000Z.json", 150);
        let result = run_with_root(ListBackupsArgs {}, tmp.path()).unwrap();
        assert_eq!(result.backups.len(), 3);
        assert_eq!(result.backups[0].timestamp, "20240315T120000Z");
        assert_eq!(result.backups[1].timestamp, "20240201T060000Z");
        assert_eq!(result.backups[2].timestamp, "20240101T000000Z");
    }

    #[test]
    fn non_backup_files_ignored() {
        let tmp = TempDir::new().unwrap();
        make_backup(tmp.path(), "20240115T123456Z.json", 512);
        // These should be ignored:
        std::fs::write(tmp.path().join("README.txt"), b"ignore me").unwrap();
        std::fs::write(tmp.path().join("short.json"), b"{}").unwrap();
        std::fs::write(tmp.path().join("20240115T123456.json"), b"{}").unwrap(); // no Z
        std::fs::write(tmp.path().join("20240115X123456Z.json"), b"{}").unwrap(); // X not T
        let result = run_with_root(ListBackupsArgs {}, tmp.path()).unwrap();
        assert_eq!(result.backups.len(), 1);
        assert_eq!(result.backups[0].filename, "20240115T123456Z.json");
    }

    #[test]
    fn is_backup_filename_valid() {
        assert!(is_backup_filename("20240115T123456Z.json"));
        assert!(is_backup_filename("19700101T000000Z.json"));
    }

    #[test]
    fn is_backup_filename_invalid() {
        assert!(!is_backup_filename("20240115T123456.json")); // no Z
        assert!(!is_backup_filename("20240115X123456Z.json")); // X not T
        assert!(!is_backup_filename("short.json"));
        assert!(!is_backup_filename("README.txt"));
        assert!(!is_backup_filename("20240115T123456Z")); // no .json
    }
}
