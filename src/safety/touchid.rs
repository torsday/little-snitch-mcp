//! TouchID-for-sudo detection by inspecting PAM configuration files.
//!
//! ADR-0006 recommends `auth sufficient pam_tid.so` in `/etc/pam.d/sudo_local`
//! as the preferred path for enabling sudo from a GUI-spawned MCP client
//! (which has no TTY for password entry).

use std::io;

/// Result of checking whether TouchID for sudo is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchIdSudoStatus {
    /// `pam_tid.so` is enabled in a PAM config file.
    Configured,
    /// The PAM files were found and readable but contain no `pam_tid.so` line.
    NotConfigured,
    /// `/etc/pam.d/sudo_local` is absent (the primary config file does not exist).
    FileMissing,
    /// An I/O error occurred while reading the PAM config files.
    ReadError(String),
}

/// PAM files inspected, in preference order.
///
/// `sudo_local` is the recommended override file (not replaced on OS upgrade);
/// `sudo` is the fallback for systems without a `sudo_local`.
const PAM_FILES: &[&str] = &["/etc/pam.d/sudo_local", "/etc/pam.d/sudo"];

/// The regex that must match a non-commented line for `Configured` status.
///
/// Per the acceptance criteria: `^\s*auth\s+sufficient\s+pam_tid\.so\s*$`
/// We evaluate this without the `regex` crate by splitting on whitespace
/// after stripping leading whitespace.
fn line_enables_pam_tid(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return false;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    matches!(
        parts.as_slice(),
        ["auth", "sufficient", "pam_tid.so"] | ["auth", "sufficient", "pam_tid.so", _]
    )
}

/// Detect whether TouchID for sudo is configured on this machine.
///
/// Reads `/etc/pam.d/sudo_local` first; falls back to `/etc/pam.d/sudo`.
/// Returns [`TouchIdSudoStatus::FileMissing`] only when *both* files are absent.
pub fn detect() -> TouchIdSudoStatus {
    let mut any_found = false;

    for path in PAM_FILES {
        match std::fs::read_to_string(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return TouchIdSudoStatus::ReadError(e.to_string()),
            Ok(contents) => {
                any_found = true;
                if contents.lines().any(line_enables_pam_tid) {
                    return TouchIdSudoStatus::Configured;
                }
            }
        }
    }

    if any_found {
        TouchIdSudoStatus::NotConfigured
    } else {
        TouchIdSudoStatus::FileMissing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(contents: &str) -> bool {
        contents.lines().any(line_enables_pam_tid)
    }

    #[test]
    fn detects_enabled_line() {
        assert!(check("auth sufficient pam_tid.so\n"));
    }

    #[test]
    fn detects_with_leading_whitespace() {
        assert!(check("  auth  sufficient  pam_tid.so\n"));
    }

    #[test]
    fn ignores_commented_line() {
        assert!(!check("# auth sufficient pam_tid.so\n"));
    }

    #[test]
    fn ignores_wrong_control() {
        assert!(!check("auth required pam_tid.so\n"));
    }

    #[test]
    fn ignores_wrong_module() {
        assert!(!check("auth sufficient pam_other.so\n"));
    }

    #[test]
    fn detects_in_multiline_file() {
        let contents = "# PAM config\nauth required pam_deny.so\nauth sufficient pam_tid.so\n";
        assert!(check(contents));
    }

    #[test]
    fn empty_file_is_not_configured() {
        assert!(!check(""));
    }
}
