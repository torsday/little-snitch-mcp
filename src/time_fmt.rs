//! ISO 8601 UTC timestamp formatting from Unix seconds, no `chrono` dep.
//!
//! Two output shapes are needed across the project:
//!
//! - [`iso8601_utc`] — the standard `2026-04-25T17:43:37Z` form. Used for
//!   rule `creation_date` / `modification_date`, audit logs, diff payloads.
//! - [`compact_iso8601_utc`] — `20260425T174337Z` (no separators, filename-
//!   safe). Used for backup directory names and capture artifacts.
//!
//! Both share a single port of Howard Hinnant's `civil_from_days`
//! algorithm — historically duplicated five times across the codebase
//! in two slightly divergent variants. Centralized here so the algorithm
//! has exactly one canonical copy, fixed by tests at this seam.
//!
//! See <http://howardhinnant.github.io/date_algorithms.html#civil_from_days>.

/// Format Unix seconds (UTC) as ISO 8601 with separators: `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso8601_utc(secs: u64) -> String {
    let (y, mo, d, h, m, s) = ymd_hms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Format Unix seconds (UTC) as compact ISO 8601: `YYYYMMDDTHHMMSSZ`.
///
/// No separators — safe to embed in filenames and directory paths.
pub fn compact_iso8601_utc(secs: u64) -> String {
    let (y, mo, d, h, m, s) = ymd_hms(secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z")
}

/// Decompose Unix seconds (UTC) into `(year, month, day, hour, minute, second)`.
fn ymd_hms(secs: u64) -> (u64, u8, u8, u64, u64, u64) {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let (y, mo, d) = days_to_ymd(secs / 86400);
    (y, mo, d, h, m, s)
}

/// Convert days since Unix epoch (1970-01-01) to a proleptic Gregorian
/// `(year, month, day)` triple.
///
/// Howard Hinnant's `civil_from_days`. Defined for any `u64` input —
/// the algorithm is exact, branch-free, and dependency-free, which is why
/// we ported it instead of pulling in `chrono` or `time`.
fn days_to_ymd(days: u64) -> (u64, u8, u8) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
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

    /// Smoke-3 reference: 2026-04-25T17:43:37Z = 1777139017 unix secs.
    /// Pinned by `model::rule_construct` tests historically; preserved
    /// here so any future edit to `days_to_ymd` flagging this test means
    /// the algorithm broke.
    const SMOKE_3_UNIX: u64 = 1_777_139_017;
    const SMOKE_3_ISO: &str = "2026-04-25T17:43:37Z";
    const SMOKE_3_COMPACT: &str = "20260425T174337Z";

    #[test]
    fn iso8601_utc_matches_smoke_3() {
        assert_eq!(iso8601_utc(SMOKE_3_UNIX), SMOKE_3_ISO);
    }

    #[test]
    fn compact_iso8601_utc_matches_smoke_3() {
        assert_eq!(compact_iso8601_utc(SMOKE_3_UNIX), SMOKE_3_COMPACT);
    }

    #[test]
    fn unix_epoch_is_1970_01_01_midnight() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(compact_iso8601_utc(0), "19700101T000000Z");
    }

    #[test]
    fn handles_far_future() {
        // 2099-12-31T23:59:59Z = 4_102_444_799 unix secs.
        assert_eq!(iso8601_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn handles_leap_year() {
        // 2024-02-29T12:00:00Z = 1_709_208_000 unix secs.
        assert_eq!(iso8601_utc(1_709_208_000), "2024-02-29T12:00:00Z");
    }
}
