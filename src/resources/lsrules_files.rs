use serde::Serialize;

pub const URI: &str = "littlesnitch://lsrules-files";

/// One entry in the listing returned by the `littlesnitch://lsrules-files` resource.
#[derive(Debug, Serialize)]
pub struct LsrulesFileEntry {
    pub name: String,
    pub size: u64,
    pub modified_at: String,
}

/// Read all `.lsrules` files from `rules_dir`, sorted by name.
pub fn list(rules_dir: &std::path::Path) -> Result<Vec<LsrulesFileEntry>, String> {
    if !rules_dir.exists() {
        return Ok(vec![]);
    }

    let mut entries: Vec<LsrulesFileEntry> = std::fs::read_dir(rules_dir)
        .map_err(|e| format!("cannot read rules directory: {e}"))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "lsrules")
                .unwrap_or(false)
        })
        .map(|entry| {
            let path = entry.path();
            let meta = std::fs::metadata(&path);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified_at = meta
                .and_then(|m| m.modified())
                .map(|t| {
                    let secs = t
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    // Format as ISO 8601 UTC (seconds granularity)
                    format_unix_secs(secs)
                })
                .unwrap_or_else(|_| "unknown".to_string());
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            LsrulesFileEntry {
                name,
                size,
                modified_at,
            }
        })
        .collect();

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn format_unix_secs(secs: u64) -> String {
    // Manual ISO 8601 UTC formatter without chrono dependency.
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Days since Unix epoch → proleptic Gregorian date
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u8, u8) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u8, d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_empty_dir_returns_empty() {
        let td = tempfile::tempdir().unwrap();
        let rules = td.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        let result = list(&rules).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_returns_lsrules_files_sorted() {
        let td = tempfile::tempdir().unwrap();
        let rules = td.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(rules.join("zzz.lsrules"), b"{}").unwrap();
        std::fs::write(rules.join("aaa.lsrules"), b"{}").unwrap();
        std::fs::write(rules.join("ignored.txt"), b"nope").unwrap();

        let result = list(&rules).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "aaa");
        assert_eq!(result[1].name, "zzz");
    }

    #[test]
    fn list_nonexistent_dir_returns_empty() {
        let result = list(std::path::Path::new("/tmp/__nonexistent_rules_dir__")).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn format_unix_secs_epoch() {
        // 2020-01-01T00:00:00Z = 1577836800 seconds
        assert_eq!(format_unix_secs(1577836800), "2020-01-01T00:00:00Z");
    }
}
