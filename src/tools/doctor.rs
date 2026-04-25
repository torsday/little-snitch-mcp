//! Doctor tool: runs a set of environment checks and returns a structured
//! report. All checks are read-only; safe to call repeatedly.

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::{LsCli, LsCliError};
use crate::cli::binary::resolve_binary;
use crate::cli::version::{VersionResult, check as check_version};
use crate::managed_dir::ManagedDir;
use crate::safety::RESTORE_MODEL_TERMINAL_GUARD_FLAG;
use crate::safety::touchid::{TouchIdSudoStatus, detect as detect_touchid};

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
    let checks = vec![
        check_binary(),
        check_cli_authorized(),
        check_touchid_sudo(),
        check_managed_dir(),
        check_restore_model_terminal_flag(),
    ];

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
        Ok(bin) => match check_version(&bin) {
            VersionResult::Compatible(v) => Check {
                name: "ls_binary",
                status: CheckStatus::Green,
                message: format!("found at {} (version {v})", bin.display()),
                remediation: None,
            },
            VersionResult::TooOld(v) => Check {
                name: "ls_binary",
                status: CheckStatus::Red,
                message: format!("version {v} is below minimum 6.3.3"),
                remediation: Some("Upgrade Little Snitch to ≥ 6.3.3".into()),
            },
            VersionResult::Unparseable(s) => Check {
                name: "ls_binary",
                status: CheckStatus::Yellow,
                message: format!("found at {bin:?} but could not parse version: {s:?}"),
                remediation: Some("Upgrade Little Snitch to ≥ 6.3.3".into()),
            },
        },
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
    match detect_touchid() {
        TouchIdSudoStatus::Configured => Check {
            name: "touchid_sudo",
            status: CheckStatus::Green,
            message: "pam_tid.so is enabled for sudo".into(),
            remediation: None,
        },
        TouchIdSudoStatus::NotConfigured | TouchIdSudoStatus::FileMissing => Check {
            name: "touchid_sudo",
            status: CheckStatus::Yellow,
            message: "TouchID for sudo is not configured — sudo tools will require a terminal TTY"
                .into(),
            remediation: Some(
                "Add `auth sufficient pam_tid.so` as the first auth line in \
                 /etc/pam.d/sudo_local (create the file if needed)"
                    .into(),
            ),
        },
        TouchIdSudoStatus::ReadError(e) => Check {
            name: "touchid_sudo",
            status: CheckStatus::Yellow,
            message: format!("could not read PAM config: {e}"),
            remediation: None,
        },
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
    // was added in LS 6.3.3. We infer its presence from the version.
    match resolve_binary() {
        Err(e) => Check {
            name: "restore_model_terminal_flag",
            status: CheckStatus::Red,
            message: format!("binary unavailable: {e}"),
            remediation: None,
        },
        Ok(bin) => match check_version(&bin) {
            VersionResult::Compatible(v) => Check {
                name: "restore_model_terminal_flag",
                status: CheckStatus::Green,
                message: format!(
                    "restore-model supports {RESTORE_MODEL_TERMINAL_GUARD_FLAG} (LS {v} ≥ 6.3.3)"
                ),
                remediation: None,
            },
            _ => Check {
                name: "restore_model_terminal_flag",
                status: CheckStatus::Red,
                message: "restore-model --preserve-terminal-access unavailable \
                          (version below 6.3.3) — model-surgery tools are disabled"
                    .into(),
                remediation: Some("Upgrade Little Snitch to ≥ 6.3.3".into()),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
