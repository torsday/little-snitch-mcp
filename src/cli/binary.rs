//! `littlesnitch` binary location.
//!
//! Resolution order per ADR-0001 and issue #11:
//! 1. `LSMCP_LS_BIN` environment variable (override / testing)
//! 2. `/Applications/Little Snitch.app/Contents/Components/littlesnitch` (canonical LS 6)
//! 3. `/Applications/Little Snitch.app/Contents/MacOS/littlesnitch` (fallback bundle path)
//! 4. `which littlesnitch` (PATH lookup, handles custom installs)
//!
//! The public entry point is [`resolve_binary`]. The inner
//! [`resolve_binary_with`] function is `pub(crate)` so that tests can
//! inject a fake `exists` predicate and a mock `which` result without
//! touching the real filesystem.

use std::path::{Path, PathBuf};
use thiserror::Error;

pub const ENV_KEY: &str = "LSMCP_LS_BIN";

const CANONICAL_PATHS: &[&str] = &[
    "/Applications/Little Snitch.app/Contents/Components/littlesnitch",
    "/Applications/Little Snitch.app/Contents/MacOS/littlesnitch",
];

const BINARY_NAME: &str = "littlesnitch";

/// Returned when no `littlesnitch` binary can be found.
///
/// `attempted` lists every path or strategy tried, in resolution order,
/// so the error message gives the operator an actionable diagnosis.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error(
    "littlesnitch binary not found; tried: {attempted}",
    attempted = self.attempted.join(", ")
)]
pub struct LsBinaryNotFound {
    pub attempted: Vec<String>,
}

/// Locate the `littlesnitch` binary.
///
/// Tries four strategies in order; returns the first path that exists.
/// See the module-level doc for the resolution order.
pub fn resolve_binary() -> Result<PathBuf, LsBinaryNotFound> {
    resolve_binary_with(
        std::env::var(ENV_KEY).ok(),
        |p| p.exists(),
        which_littlesnitch,
    )
}

/// Inner resolution logic with injectable dependencies for unit testing.
pub(crate) fn resolve_binary_with(
    env_override: Option<String>,
    exists: impl Fn(&Path) -> bool,
    which_fn: impl Fn() -> Option<PathBuf>,
) -> Result<PathBuf, LsBinaryNotFound> {
    let mut attempted: Vec<String> = Vec::new();

    if let Some(raw) = env_override {
        let p = PathBuf::from(&raw);
        if exists(&p) {
            return Ok(p);
        }
        attempted.push(format!("${}={}", ENV_KEY, raw));
    }

    for &path_str in CANONICAL_PATHS {
        let p = Path::new(path_str);
        if exists(p) {
            return Ok(p.to_path_buf());
        }
        attempted.push(path_str.to_string());
    }

    if let Some(p) = which_fn() {
        return Ok(p);
    }
    attempted.push(format!("`which {}`", BINARY_NAME));

    Err(LsBinaryNotFound { attempted })
}

fn which_littlesnitch() -> Option<PathBuf> {
    std::process::Command::new("which")
        .arg(BINARY_NAME)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                std::str::from_utf8(&o.stdout)
                    .ok()
                    .map(|s| PathBuf::from(s.trim()))
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found(_: &Path) -> bool {
        false
    }

    fn no_which() -> Option<PathBuf> {
        None
    }

    // ── branch 1: LSMCP_LS_BIN override ────────────────────────────────

    #[test]
    fn env_override_is_returned_when_path_exists() {
        let path = PathBuf::from("/custom/littlesnitch");
        let result = resolve_binary_with(
            Some(path.to_string_lossy().into_owned()),
            |p| p == path.as_path(),
            no_which,
        );
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn env_override_is_skipped_when_path_absent() {
        let canonical = PathBuf::from(CANONICAL_PATHS[0]);
        let result = resolve_binary_with(
            Some("/non-existent/littlesnitch".into()),
            |p| p == canonical.as_path(),
            no_which,
        );
        assert_eq!(result.unwrap(), canonical);
    }

    #[test]
    fn env_override_path_appears_in_error_when_absent() {
        let err = resolve_binary_with(
            Some("/bad/path/littlesnitch".into()),
            not_found,
            no_which,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("LSMCP_LS_BIN=/bad/path/littlesnitch"), "got: {msg}");
    }

    // ── branch 2: first canonical path ─────────────────────────────────

    #[test]
    fn first_canonical_path_returned_when_exists() {
        let canonical = PathBuf::from(CANONICAL_PATHS[0]);
        let result = resolve_binary_with(None, |p| p == canonical.as_path(), no_which);
        assert_eq!(result.unwrap(), canonical);
    }

    // ── branch 3: second canonical path ────────────────────────────────

    #[test]
    fn second_canonical_path_returned_when_only_fallback_exists() {
        let fallback = PathBuf::from(CANONICAL_PATHS[1]);
        let result = resolve_binary_with(None, |p| p == fallback.as_path(), no_which);
        assert_eq!(result.unwrap(), fallback);
    }

    // ── branch 4: which lookup ──────────────────────────────────────────

    #[test]
    fn which_result_returned_when_canonical_paths_absent() {
        let which_path = PathBuf::from("/usr/local/bin/littlesnitch");
        let result = resolve_binary_with(
            None,
            not_found,
            || Some(which_path.clone()),
        );
        assert_eq!(result.unwrap(), which_path);
    }

    // ── full miss ───────────────────────────────────────────────────────

    #[test]
    fn error_lists_all_attempted_paths_when_nothing_found() {
        let err = resolve_binary_with(None, not_found, no_which).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(CANONICAL_PATHS[0]), "missing canonical[0]: {msg}");
        assert!(msg.contains(CANONICAL_PATHS[1]), "missing canonical[1]: {msg}");
        assert!(msg.contains("`which littlesnitch`"), "missing which: {msg}");
    }

    #[test]
    fn error_attempted_has_two_entries_when_no_env_override() {
        let err = resolve_binary_with(None, not_found, no_which).unwrap_err();
        // 2 canonical paths + 1 which entry = 3
        assert_eq!(err.attempted.len(), 3);
    }

    #[test]
    fn error_attempted_has_extra_entry_when_env_override_present_but_absent() {
        let err = resolve_binary_with(
            Some("/missing".into()),
            not_found,
            no_which,
        )
        .unwrap_err();
        // env + 2 canonical + 1 which = 4
        assert_eq!(err.attempted.len(), 4);
    }

    #[test]
    fn error_display_is_human_readable() {
        let err = LsBinaryNotFound {
            attempted: vec!["a".into(), "b".into()],
        };
        assert_eq!(
            err.to_string(),
            "littlesnitch binary not found; tried: a, b"
        );
    }
}
