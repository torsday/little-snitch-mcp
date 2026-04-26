//! `warm_sudo` tool: TouchID setup instructions + sudo-readiness polling.
//!
//! Surfaces the one-time setup commands for Touch ID sudo (Tier 1) and the
//! keepalive command for terminal-based sudo auth (Tier 3), then polls for
//! sudo availability so the caller knows when live-write tools are unblocked.

use serde::{Deserialize, Serialize};

use crate::safety::{TouchIdSudoStatus, detect_touchid_sudo, reset_sudo_cache};

/// Polling configuration: check every 5 s, give up after 60 s (12 polls).
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLLS: u32 = 12;

/// Input for the `warm_sudo` tool.
#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
pub struct WarmSudoArgs {}

/// Instructions for the two supported sudo-setup paths.
#[derive(Debug, Serialize)]
pub struct SetupInstructions {
    /// Tier 1 — configure TouchID for sudo (one-time, recommended).
    pub tier1_touchid: Vec<String>,
    /// Tier 3 — keepalive command to run in a terminal (session-scoped).
    pub tier3_keepalive: String,
}

/// Return value of `warm_sudo`.
#[derive(Debug, Serialize)]
pub struct WarmSudoResult {
    /// True if the process was already root when the tool was invoked.
    pub already_root: bool,
    /// Current TouchID-for-sudo configuration status.
    pub touchid_status: String,
    /// Copy-pasteable setup instructions for each tier.
    pub instructions: SetupInstructions,
    /// True if sudo is available by the time the tool returns.
    pub sudo_available: bool,
    /// Number of `sudo -n true` polls performed (0 if already root).
    pub polls_performed: u32,
    /// Human-readable status summary.
    pub message: String,
}

/// Run the warm_sudo tool asynchronously (polls require async sleep).
pub async fn run(_args: WarmSudoArgs) -> Result<WarmSudoResult, String> {
    let already_root = crate::safety::is_root();
    let touchid_status = detect_touchid_sudo();

    let instructions = SetupInstructions {
        tier1_touchid: vec![
            "sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local".to_string(),
            "echo 'auth sufficient pam_tid.so' | sudo tee -a /etc/pam.d/sudo_local".to_string(),
            "# Then restart the MCP server with: sudo little-snitch-mcp".to_string(),
        ],
        tier3_keepalive: "sudo -v && (while true; do sudo -n true; sleep 60; done) &".to_string(),
    };

    if already_root {
        reset_sudo_cache();
        return Ok(WarmSudoResult {
            already_root: true,
            touchid_status: status_string(&touchid_status),
            instructions,
            sudo_available: true,
            polls_performed: 0,
            message: "MCP server is running as root — live-write tools are available.".to_string(),
        });
    }

    // Not root — poll for sudo availability.
    let mut polls = 0u32;
    let mut sudo_ok = false;
    while polls < MAX_POLLS {
        if check_sudo_noninteractive() {
            sudo_ok = true;
            break;
        }
        polls += 1;
        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
    // One final check after the last sleep.
    if !sudo_ok {
        sudo_ok = check_sudo_noninteractive();
    }

    if sudo_ok {
        reset_sudo_cache();
    }

    let message = if sudo_ok {
        "sudo is now available — live-write tools are enabled for this session.".to_string()
    } else {
        format!(
            "sudo is not yet available after {} polls ({} s). \
             Follow the setup instructions below, then invoke warm_sudo again.",
            polls,
            polls * POLL_INTERVAL_SECS as u32
        )
    };

    Ok(WarmSudoResult {
        already_root: false,
        touchid_status: status_string(&touchid_status),
        instructions,
        sudo_available: sudo_ok,
        polls_performed: polls,
        message,
    })
}

fn status_string(status: &TouchIdSudoStatus) -> String {
    match status {
        TouchIdSudoStatus::Configured => "configured".to_string(),
        TouchIdSudoStatus::NotConfigured => "not_configured".to_string(),
        TouchIdSudoStatus::FileMissing => "pam_file_missing".to_string(),
        TouchIdSudoStatus::ReadError(e) => format!("read_error: {e}"),
    }
}

/// Run `sudo -n true` and return true if it exits 0 (sudo available without
/// a password — either the MCP is root, TouchID is configured, or a keepalive
/// is active).
fn check_sudo_noninteractive() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_string_variants() {
        assert_eq!(status_string(&TouchIdSudoStatus::Configured), "configured");
        assert_eq!(
            status_string(&TouchIdSudoStatus::NotConfigured),
            "not_configured"
        );
        assert_eq!(
            status_string(&TouchIdSudoStatus::FileMissing),
            "pam_file_missing"
        );
        assert!(
            status_string(&TouchIdSudoStatus::ReadError("oops".to_string())).contains("read_error")
        );
    }

    #[test]
    fn instructions_have_pam_tid_command() {
        let instructions = SetupInstructions {
            tier1_touchid: vec![
                "sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local".to_string(),
                "echo 'auth sufficient pam_tid.so' | sudo tee -a /etc/pam.d/sudo_local".to_string(),
                "# Then restart the MCP server with: sudo little-snitch-mcp".to_string(),
            ],
            tier3_keepalive: "sudo -v && (while true; do sudo -n true; sleep 60; done) &"
                .to_string(),
        };
        assert!(
            instructions
                .tier1_touchid
                .iter()
                .any(|s| s.contains("pam_tid.so"))
        );
        assert!(instructions.tier3_keepalive.contains("sudo -v"));
    }

    #[test]
    fn result_serializes_all_fields() {
        let r = WarmSudoResult {
            already_root: true,
            touchid_status: "configured".to_string(),
            instructions: SetupInstructions {
                tier1_touchid: vec!["cmd1".to_string()],
                tier3_keepalive: "keepalive".to_string(),
            },
            sudo_available: true,
            polls_performed: 0,
            message: "ok".to_string(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["already_root"], true);
        assert_eq!(v["sudo_available"], true);
        assert_eq!(v["polls_performed"], 0);
        assert!(v["instructions"]["tier1_touchid"].is_array());
    }

    #[test]
    fn max_polls_constant_gives_60s() {
        assert_eq!(MAX_POLLS * POLL_INTERVAL_SECS as u32, 60);
    }
}
