//! `littlesnitch` subprocess wrapper with typed error mapping.
//!
//! All interactions with the `littlesnitch` process funnel through [`LsCli`].
//! No tool may call `std::process::Command::new("littlesnitch")` directly —
//! doing so bypasses the typed-error contract enforced here.
//!
//! ## Error mapping
//!
//! [`LsCliError`] captures the four known failure modes identified in
//! [docs/feasibility-report.md](../../docs/feasibility-report.md) §Error taxonomy.
//! Every non-zero exit passes through [`map_stderr`], which is exposed as
//! `pub(crate)` so unit tests can drive it with synthetic stderr strings
//! without needing a live binary.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::LazyLock,
};

use regex::Regex;
use thiserror::Error;

use super::binary::{LsBinaryNotFound, resolve_binary};

// ---------------------------------------------------------------------------
// Regexes — compiled once at first use, reused on every call.
// ---------------------------------------------------------------------------

static RE_NOT_AUTHORIZED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"command line tool is not authorized").unwrap()
});

static RE_MUST_BE_ROOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"must be run as root").unwrap());

// Captures the resource name between the double-quotes.
static RE_NOT_FOUND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Rule group or blocklist "([^"]+)" not found"#).unwrap()
});

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Typed errors produced by the `littlesnitch` CLI.
///
/// The four variants map directly to the error strings documented in
/// [docs/feasibility-report.md](../../docs/feasibility-report.md) §Error taxonomy.
#[derive(Debug, Error)]
pub enum LsCliError {
    /// The command line tool is not authorized (user has not granted CLI access).
    #[error("littlesnitch: command line tool is not authorized")]
    NotAuthorized,

    /// The command must be run as root (`sudo` required).
    #[error("littlesnitch: must be run as root")]
    MustBeRoot,

    /// The named rule group or blocklist does not exist.
    #[error("littlesnitch: rule group or blocklist \"{resource}\" not found")]
    NotFound { resource: String },

    /// Any other non-zero exit — the raw exit code and stderr are preserved.
    #[error("littlesnitch exited with code {exit_code}: {stderr}")]
    Generic { exit_code: i32, stderr: String },

    /// OS-level failure while spawning the subprocess.
    #[error("failed to spawn littlesnitch: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// LsCli
// ---------------------------------------------------------------------------

/// Thin wrapper around the `littlesnitch` subprocess.
///
/// Construct with [`LsCli::resolve`] (auto-detect binary path via
/// [`crate::cli::binary::resolve_binary`]) or [`LsCli::new`] (supply an
/// explicit path, e.g. in tests). All shell-out goes through [`LsCli::run`].
#[derive(Debug, Clone)]
pub struct LsCli {
    bin: PathBuf,
}

impl LsCli {
    /// Construct from an already-known binary path.
    pub fn new(bin: PathBuf) -> Self {
        Self { bin }
    }

    /// Walk the four-step resolution chain and return a ready-to-use [`LsCli`].
    ///
    /// Delegates to [`resolve_binary`]; returns [`LsBinaryNotFound`] if no
    /// `littlesnitch` binary can be located.
    pub fn resolve() -> Result<Self, LsBinaryNotFound> {
        Ok(Self::new(resolve_binary()?))
    }

    /// The resolved binary path.
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// Invoke `littlesnitch <args>` and return the raw [`Output`] on success,
    /// or a typed [`LsCliError`] on any non-zero exit or spawn failure.
    pub fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Output, LsCliError> {
        let output = Command::new(&self.bin).args(args).output()?;
        if output.status.success() {
            return Ok(output);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(map_stderr(output.status.code().unwrap_or(-1), &stderr))
    }
}

// ---------------------------------------------------------------------------
// Stderr → error mapping (pure fn; unit-tested without spawning a process)
// ---------------------------------------------------------------------------

/// Map a non-zero exit to the appropriate [`LsCliError`] variant.
///
/// Exposed as `pub(crate)` so unit tests can drive it with synthetic stderr
/// without needing a live `littlesnitch` binary.
pub(crate) fn map_stderr(exit_code: i32, stderr: &str) -> LsCliError {
    if RE_NOT_AUTHORIZED.is_match(stderr) {
        return LsCliError::NotAuthorized;
    }
    if RE_MUST_BE_ROOT.is_match(stderr) {
        return LsCliError::MustBeRoot;
    }
    if let Some(caps) = RE_NOT_FOUND.captures(stderr) {
        return LsCliError::NotFound {
            resource: caps[1].to_string(),
        };
    }
    LsCliError::Generic {
        exit_code,
        stderr: stderr.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_not_authorized() {
        let err = map_stderr(1, "Error: command line tool is not authorized");
        assert!(matches!(err, LsCliError::NotAuthorized));
    }

    #[test]
    fn map_must_be_root() {
        let err = map_stderr(1, "littlesnitch must be run as root!");
        assert!(matches!(err, LsCliError::MustBeRoot));
    }

    #[test]
    fn map_not_found_extracts_resource() {
        let err = map_stderr(1, r#"Rule group or blocklist "My Custom Group" not found."#);
        match err {
            LsCliError::NotFound { resource } => assert_eq!(resource, "My Custom Group"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn map_generic_preserves_code_and_stderr() {
        let err = map_stderr(127, "unexpected failure: no such file");
        match err {
            LsCliError::Generic { exit_code, stderr } => {
                assert_eq!(exit_code, 127);
                assert!(stderr.contains("no such file"));
            }
            other => panic!("expected Generic, got {other:?}"),
        }
    }
}
