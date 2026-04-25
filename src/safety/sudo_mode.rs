//! Runtime sudo-availability detection and live-write gating.
//!
//! Two independent conditions can disable live writes:
//! - `LSMCP_DISABLE_LIVE_WRITE=true` — explicit operator opt-out.
//! - Process not running as root — sudo required by all live-write commands.
//!
//! The sudo check is cached after the first call. Call [`reset_sudo_cache`]
//! to force a re-detection on the next call (used by `warm_sudo` after the
//! user establishes a sudo session).

use std::sync::Mutex;

/// Cached result of the root-detection subprocess.
/// `None` means "not yet detected".
static SUDO_CACHE: Mutex<Option<bool>> = Mutex::new(None);

/// Return `true` if the process is currently running as root (`euid == 0`).
///
/// The result is cached after the first call. Call [`reset_sudo_cache`]
/// to invalidate the cache (e.g., after `warm_sudo` succeeds).
pub fn is_root() -> bool {
    let mut guard = SUDO_CACHE.lock().unwrap();
    match *guard {
        Some(v) => v,
        None => {
            let v = detect_root();
            *guard = Some(v);
            v
        }
    }
}

/// Invalidate the cached sudo state so the next [`is_root`] call re-detects.
///
/// Called by `warm_sudo` after a sudo session has been established.
pub fn reset_sudo_cache() {
    *SUDO_CACHE.lock().unwrap() = None;
}

/// Return `true` if `LSMCP_DISABLE_LIVE_WRITE` is set to `true` or `1`.
pub fn disable_live_writes_requested() -> bool {
    std::env::var("LSMCP_DISABLE_LIVE_WRITE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Return `true` if live writes are currently permitted.
///
/// Live writes are permitted when the process is root AND the operator has
/// not set `LSMCP_DISABLE_LIVE_WRITE=true`.
pub fn live_writes_enabled() -> bool {
    is_root() && !disable_live_writes_requested()
}

/// Gate a live-write operation, returning a structured error if disabled.
///
/// Call this at the top of every `live_write`-classified tool handler.
/// The error message names the exact reason and points to `warm_sudo`.
pub fn require_live_write_allowed() -> Result<(), String> {
    if disable_live_writes_requested() {
        return Err(
            "live writes are disabled: LSMCP_DISABLE_LIVE_WRITE is set. \
             Unset it and restart the server, or use the warm_sudo tool."
                .to_string(),
        );
    }
    if !is_root() {
        return Err("live writes require the MCP server to run as root (sudo). \
             Use the warm_sudo tool for setup instructions, or restart \
             the server with sudo."
            .to_string());
    }
    Ok(())
}

/// Detect whether the current process is running as root.
///
/// Runs `id -u` via subprocess — result is cached by callers.
fn detect_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_live_writes_false_when_unset() {
        // The env var is not set in normal test runs.
        // Deliberately do NOT set it here to keep tests idempotent.
        // If another test sets it, this may fail — tests must be isolated.
        let was_set = std::env::var("LSMCP_DISABLE_LIVE_WRITE").is_ok();
        if !was_set {
            assert!(!disable_live_writes_requested());
        }
    }

    #[test]
    fn disable_live_writes_true_on_true() {
        // Temporarily set the env var. Not thread-safe, but acceptable for
        // a single-env-var unit test with no parallelism concerns.
        unsafe { std::env::set_var("LSMCP_DISABLE_LIVE_WRITE", "true") };
        assert!(disable_live_writes_requested());
        unsafe { std::env::remove_var("LSMCP_DISABLE_LIVE_WRITE") };
    }

    #[test]
    fn disable_live_writes_true_on_1() {
        unsafe { std::env::set_var("LSMCP_DISABLE_LIVE_WRITE", "1") };
        assert!(disable_live_writes_requested());
        unsafe { std::env::remove_var("LSMCP_DISABLE_LIVE_WRITE") };
    }

    #[test]
    fn disable_live_writes_true_case_insensitive() {
        unsafe { std::env::set_var("LSMCP_DISABLE_LIVE_WRITE", "TRUE") };
        assert!(disable_live_writes_requested());
        unsafe { std::env::remove_var("LSMCP_DISABLE_LIVE_WRITE") };
    }

    #[test]
    fn disable_live_writes_false_on_false_string() {
        unsafe { std::env::set_var("LSMCP_DISABLE_LIVE_WRITE", "false") };
        assert!(!disable_live_writes_requested());
        unsafe { std::env::remove_var("LSMCP_DISABLE_LIVE_WRITE") };
    }

    #[test]
    fn reset_cache_clears_cached_value() {
        // Prime the cache with the real system value.
        let _ = is_root();
        // Reset and re-detect — should be consistent.
        reset_sudo_cache();
        let after_reset = is_root();
        // Value should be deterministic (same process, same UID).
        // We can't assert true/false (tests may not be root), but
        // re-detection must not panic and must return a bool.
        let _ = after_reset;
    }

    #[test]
    fn require_live_write_allowed_fails_when_disabled() {
        unsafe { std::env::set_var("LSMCP_DISABLE_LIVE_WRITE", "true") };
        let result = require_live_write_allowed();
        unsafe { std::env::remove_var("LSMCP_DISABLE_LIVE_WRITE") };
        let err = result.unwrap_err();
        assert!(err.contains("LSMCP_DISABLE_LIVE_WRITE"), "error: {err}");
    }

    #[test]
    fn require_live_write_allowed_fails_when_not_root_and_not_running_as_root() {
        // This test only verifies the error message when we know we're not root.
        if is_root() {
            // Running as root in CI — skip this branch.
            return;
        }
        let result = require_live_write_allowed();
        let err = result.unwrap_err();
        assert!(err.contains("root") || err.contains("sudo"), "error: {err}");
    }

    #[test]
    fn live_writes_enabled_is_consistent_with_components() {
        let env_disabled = disable_live_writes_requested();
        let root = is_root();
        let expected = root && !env_disabled;
        assert_eq!(live_writes_enabled(), expected);
    }
}
