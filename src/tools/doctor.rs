//! Doctor tool: runs a set of environment checks and returns a structured
//! report. All checks are read-only; safe to call repeatedly.

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::{LsCli, LsCliError};
use crate::cli::binary::resolve_binary;
use crate::managed_dir::ManagedDir;
use crate::safety::RESTORE_MODEL_TERMINAL_GUARD_FLAG;

// Minimum LS version the MCP requires.
const MIN_VERSION: (u32, u32, u32) = (6, 3, 3);

/// Input for the `doctor` tool — no parameters.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DoctorArgs {}

/// Traffic-light severity for one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// Everything is correct; the check passes.
    Green,
    /// Partial: the MCP can operate but with reduced capability.
    Yellow,
    /// Blocking issue; the check fails.
    Red,
}

/// One diagnostic check in the [`DoctorReport`].
#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Full doctor report.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    /// `true` iff every check is `green`.
    pub ok: bool,
    pub checks: Vec<Check>,
}

pub fn run(_args: DoctorArgs) -> Result<DoctorReport, String> {
    let mut checks = Vec::new();

    checks.push(check_binary());
    checks.push(check_cli_authorized());
    checks.push(check_touchid_sudo());
    checks.push(check_managed_dir());
    checks.push(check_restore_model_terminal_flag());

    let ok = checks.iter().all(|c| c.status == CheckStatus::Green);
    Ok(DoctorReport { ok, checks })
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

fn check_binary() -> Check {
    match resolve_binary() {
        Err(e) => Check {
            name: "ls_binary",
            status: CheckStatus::Red,
            message: format!("littlesnitch binary not found: {e}"),
            remediation: Some(
                "Install Little Snitch 6.3.3+ from https://obdev.at/products/littlesnitch".into(),
            ),
        },
        Ok(bin) => {
            // Run --version and parse major.minor.patch
            match std::process::Command::new(&bin).arg("--version").output() {
                Err(e) => Check {
                    name: "ls_binary",
                    status: CheckStatus::Red,
                    message: format!("could not run {bin:?}: {e}"),
                    remediation: None,
                },
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let version_str = stdout.trim();
                    match parse_version(version_str) {
                        None => Check {
                            name: "ls_binary",
                            status: CheckStatus::Yellow,
                            message: format!(
                                "found at {bin:?} but could not parse version: {version_str:?}"
                            ),
                            remediation: Some("Upgrade Little Snitch to ≥ 6.3.3".into()),
                        },
                        Some(v) if v < MIN_VERSION => Check {
                            name: "ls_binary",
                            status: CheckStatus::Red,
                            message: format!(
                                "version {}.{}.{} is below minimum {}.{}.{}",
                                v.0, v.1, v.2, MIN_VERSION.0, MIN_VERSION.1, MIN_VERSION.2
                            ),
                            remediation: Some("Upgrade Little Snitch to ≥ 6.3.3".into()),
                        },
                        Some(v) => Check {
                            name: "ls_binary",
                            status: CheckStatus::Green,
                            message: format!(
                                "found at {} (version {}.{}.{})",
                                bin.display(),
                                v.0,
                                v.1,
                                v.2
                            ),
                            remediation: None,
                        },
                    }
                }
            }
        }
    }
}

fn check_cli_authorized() -> Check {
    let cli = match LsCli::resolve() {
        Err(e) => {
            return Check {
                name: "cli_authorized",
                status: CheckStatus::Red,
                message: format!("binary unavailable: {e}"),
                remediation: None,
            };
        }
        Ok(c) => c,
    };

    // Probe: run a cheap sudo-required command to distinguish
    // "not authorized" from "not root" from "ok (if sudo)".
    match cli.run(&["list-preferences", "-g"]) {
        Ok(_) => Check {
            name: "cli_authorized",
            status: CheckStatus::Green,
            message: "CLI is authorized and running as root".into(),
            remediation: None,
        },
        Err(LsCliError::NotAuthorized) => Check {
            name: "cli_authorized",
            status: CheckStatus::Red,
            message: "CLI is not authorized to make changes".into(),
            remediation: Some(
                "Open Little Snitch Preferences → Security and enable \
                 'Allow access via Terminal'"
                    .into(),
            ),
        },
        Err(LsCliError::MustBeRoot) => Check {
            name: "cli_authorized",
            status: CheckStatus::Yellow,
            message: "CLI is authorized but not running as root (sudo required for most tools)"
                .into(),
            remediation: Some(
                "Restart the MCP server with sudo, or configure TouchID for sudo \
                 (see check 'touchid_sudo')"
                    .into(),
            ),
        },
        Err(e) => Check {
            name: "cli_authorized",
            status: CheckStatus::Yellow,
            message: format!("probe call returned unexpected error: {e}"),
            remediation: None,
        },
    }
}

fn check_touchid_sudo() -> Check {
    // TouchID-for-sudo is configured via `auth sufficient pam_tid.so` in
    // /etc/pam.d/sudo or /etc/pam.d/sudo_local.
    let pam_files = ["/etc/pam.d/sudo_local", "/etc/pam.d/sudo"];
    for path in &pam_files {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let enabled = contents
                .lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains("pam_tid.so"));
            if enabled {
                return Check {
                    name: "touchid_sudo",
                    status: CheckStatus::Green,
                    message: format!("pam_tid.so enabled in {path}"),
                    remediation: None,
                };
            }
        }
    }
    Check {
        name: "touchid_sudo",
        status: CheckStatus::Yellow,
        message: "TouchID for sudo is not configured — sudo tools will require a terminal TTY"
            .into(),
        remediation: Some(
            "Add `auth sufficient pam_tid.so` as the first auth line in \
             /etc/pam.d/sudo_local (create the file if needed)"
                .into(),
        ),
    }
}

fn check_managed_dir() -> Check {
    match ManagedDir::bootstrap() {
        Err(e) => Check {
            name: "managed_dir",
            status: CheckStatus::Red,
            message: format!("cannot bootstrap managed directory: {e}"),
            remediation: Some(
                "Check that the managed directory path is accessible and writable. \
                 Override with LSMCP_MANAGED_DIR."
                    .into(),
            ),
        },
        Ok(managed) => {
            let meta = std::fs::metadata(&managed.root);
            match meta {
                Err(e) => Check {
                    name: "managed_dir",
                    status: CheckStatus::Red,
                    message: format!("managed directory stat failed: {e}"),
                    remediation: None,
                },
                Ok(m) => {
                    if m.permissions().readonly() {
                        Check {
                            name: "managed_dir",
                            status: CheckStatus::Red,
                            message: format!(
                                "managed directory is read-only: {}",
                                managed.root.display()
                            ),
                            remediation: Some("Check directory permissions (should be 700)".into()),
                        }
                    } else {
                        Check {
                            name: "managed_dir",
                            status: CheckStatus::Green,
                            message: format!("managed directory ready: {}", managed.root.display()),
                            remediation: None,
                        }
                    }
                }
            }
        }
    }
}

fn check_restore_model_terminal_flag() -> Check {
    // The --preserve-terminal-access flag (RESTORE_MODEL_TERMINAL_GUARD_FLAG = "-t")
    // was added in LS 6.3.3. We infer its presence from the version rather than
    // probing --help, which avoids a restore-model subprocess without a file argument.
    match resolve_binary() {
        Err(e) => Check {
            name: "restore_model_terminal_flag",
            status: CheckStatus::Red,
            message: format!("binary unavailable: {e}"),
            remediation: None,
        },
        Ok(bin) => match std::process::Command::new(&bin).arg("--version").output() {
            Err(e) => Check {
                name: "restore_model_terminal_flag",
                status: CheckStatus::Red,
                message: format!("could not read version: {e}"),
                remediation: None,
            },
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let version_str = stdout.trim();
                match parse_version(version_str) {
                    Some(v) if v >= MIN_VERSION => Check {
                        name: "restore_model_terminal_flag",
                        status: CheckStatus::Green,
                        message: format!(
                            "restore-model supports {} (LS {}.{}.{} ≥ 6.3.3)",
                            RESTORE_MODEL_TERMINAL_GUARD_FLAG, v.0, v.1, v.2
                        ),
                        remediation: None,
                    },
                    _ => Check {
                        name: "restore_model_terminal_flag",
                        status: CheckStatus::Red,
                        message: format!(
                            "restore-model --preserve-terminal-access unavailable \
                                 (version {:?} is below 6.3.3) — \
                                 model-surgery tools are disabled",
                            version_str
                        ),
                        remediation: Some("Upgrade Little Snitch to ≥ 6.3.3".into()),
                    },
                }
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    // Accept "6.3.3" or "Version 6.3.3" or "littlesnitch 6.3.3"
    let trimmed = s.rsplit_once(' ').map(|(_, v)| v).unwrap_or(s);
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].split('-').next()?.parse().ok()?;
    Some((major, minor, patch))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_basic() {
        assert_eq!(parse_version("6.3.3"), Some((6, 3, 3)));
    }

    #[test]
    fn parse_version_with_prefix() {
        assert_eq!(parse_version("littlesnitch 6.4.0"), Some((6, 4, 0)));
    }

    #[test]
    fn parse_version_with_build_suffix() {
        assert_eq!(parse_version("6.3.3-beta.1"), Some((6, 3, 3)));
    }

    #[test]
    fn parse_version_too_short_returns_none() {
        assert_eq!(parse_version("6.3"), None);
    }

    #[test]
    fn parse_version_non_numeric_returns_none() {
        assert_eq!(parse_version("not-a-version"), None);
    }

    #[test]
    fn doctor_report_ok_only_when_all_green() {
        let report = DoctorReport {
            ok: false,
            checks: vec![
                Check {
                    name: "a",
                    status: CheckStatus::Green,
                    message: "fine".into(),
                    remediation: None,
                },
                Check {
                    name: "b",
                    status: CheckStatus::Red,
                    message: "broken".into(),
                    remediation: None,
                },
            ],
        };
        // ok is set by run(), not by the struct — just verify the bool logic
        let ok = report.checks.iter().all(|c| c.status == CheckStatus::Green);
        assert!(!ok);
    }

    #[test]
    fn check_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Green).unwrap(),
            r#""green""#
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Yellow).unwrap(),
            r#""yellow""#
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Red).unwrap(),
            r#""red""#
        );
    }
}
