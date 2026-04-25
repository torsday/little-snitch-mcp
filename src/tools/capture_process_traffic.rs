use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::binary::resolve_binary;
use crate::managed_dir::ManagedDir;
use crate::time_fmt::compact_iso8601_utc;

/// Default capture duration in seconds.
pub const DEFAULT_DURATION_SECS: u64 = 30;
/// Maximum allowed capture duration.
pub const MAX_DURATION_SECS: u64 = 300;
/// Default maximum file size: 10 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum allowed file size: 100 MiB.
pub const MAX_ALLOWED_BYTES: u64 = 100 * 1024 * 1024;

/// Input for `capture_process_traffic`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CaptureTrafficArgs {
    /// Absolute path to the process executable to capture.
    pub process_path: String,
    /// Optional: absolute path to the parent process for filtering (LS6 `-v` flag).
    pub parent_path: Option<String>,
    /// When true, write pcap format; when false (default), write hex format.
    #[serde(default)]
    pub pcap_format: bool,
    /// Capture duration in seconds (default 30, max 300).
    pub max_duration_seconds: Option<u64>,
    /// Maximum output file size in bytes (default 10 MiB, max 100 MiB).
    pub max_bytes: Option<u64>,
}

/// Return value of `capture_process_traffic`.
#[derive(Debug, Serialize)]
pub struct CaptureTrafficResult {
    /// Absolute path to the written capture file.
    pub capture_path: String,
    /// Extension used: "hex" or "pcap".
    pub format: String,
    /// Actual file size in bytes.
    pub file_size_bytes: u64,
    /// Duration the capture ran in seconds (may be less than requested if size cap hit).
    pub duration_seconds: f64,
    /// True if the capture was stopped because the size cap was reached.
    pub size_cap_hit: bool,
}

pub async fn run(args: CaptureTrafficArgs) -> Result<CaptureTrafficResult, String> {
    if args.process_path.is_empty() {
        return Err("process_path must not be empty".to_string());
    }

    let duration_secs = args.max_duration_seconds.unwrap_or(DEFAULT_DURATION_SECS);
    if duration_secs == 0 || duration_secs > MAX_DURATION_SECS {
        return Err(format!(
            "max_duration_seconds must be between 1 and {MAX_DURATION_SECS}"
        ));
    }

    let max_bytes = args.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    if max_bytes == 0 || max_bytes > MAX_ALLOWED_BYTES {
        return Err(format!(
            "max_bytes must be between 1 and {} (100 MiB)",
            MAX_ALLOWED_BYTES
        ));
    }

    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;

    let bin = resolve_binary().map_err(|e| format!("littlesnitch binary not found: {e}"))?;

    let ext = if args.pcap_format { "pcap" } else { "hex" };
    let timestamp = timestamp_now();
    let filename = format!("{timestamp}.{ext}");
    let capture_path = managed.captures.join(&filename);

    // Open the output file with mode 600.
    let output_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&capture_path)
        .map_err(|e| format!("cannot create capture file: {e}"))?;

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg("capture-traffic");
    if let Some(ref parent) = args.parent_path {
        cmd.arg("-v").arg(parent);
    }
    if args.pcap_format {
        cmd.arg("-p");
    }
    cmd.arg(&args.process_path);
    cmd.stdout(output_file);
    // Suppress stderr so it doesn't bleed into the MCP stdio transport.
    cmd.stderr(std::process::Stdio::null());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn capture-traffic: {e}"))?;

    let start = std::time::Instant::now();
    let deadline = Duration::from_secs(duration_secs);
    // Poll every 500ms to check file size.
    let poll_interval = Duration::from_millis(500);

    let mut size_cap_hit = false;
    loop {
        if start.elapsed() >= deadline {
            break;
        }
        tokio::time::sleep(poll_interval).await;

        // Check if process already exited.
        match child.try_wait() {
            Ok(Some(_)) => break, // process finished on its own
            Ok(None) => {}
            Err(_) => break,
        }

        // Check file size.
        let size = std::fs::metadata(&capture_path)
            .map(|m| m.len())
            .unwrap_or(0);
        if size >= max_bytes {
            size_cap_hit = true;
            break;
        }
    }

    // Kill the subprocess.
    let _ = child.kill().await;
    let _ = child.wait().await;

    let elapsed = start.elapsed().as_secs_f64();
    let file_size = std::fs::metadata(&capture_path)
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(CaptureTrafficResult {
        capture_path: capture_path.to_string_lossy().into_owned(),
        format: ext.to_string(),
        file_size_bytes: file_size,
        duration_seconds: elapsed,
        size_cap_hit,
    })
}

fn timestamp_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    compact_iso8601_utc(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        const {
            assert!(DEFAULT_DURATION_SECS <= MAX_DURATION_SECS);
            assert!(DEFAULT_MAX_BYTES <= MAX_ALLOWED_BYTES);
            assert!(MAX_DURATION_SECS == 300);
            assert!(MAX_ALLOWED_BYTES == 100 * 1024 * 1024);
        }
    }

    #[test]
    fn timestamp_format_is_correct() {
        let ts = timestamp_now();
        assert_eq!(ts.len(), 16);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[tokio::test]
    async fn rejects_empty_process_path() {
        let result = run(CaptureTrafficArgs {
            process_path: "".to_string(),
            parent_path: None,
            pcap_format: false,
            max_duration_seconds: None,
            max_bytes: None,
        })
        .await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("process_path"),
            "error should mention process_path"
        );
    }

    #[tokio::test]
    async fn rejects_zero_duration() {
        let result = run(CaptureTrafficArgs {
            process_path: "/usr/bin/curl".to_string(),
            parent_path: None,
            pcap_format: false,
            max_duration_seconds: Some(0),
            max_bytes: None,
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_over_max_duration() {
        let result = run(CaptureTrafficArgs {
            process_path: "/usr/bin/curl".to_string(),
            parent_path: None,
            pcap_format: false,
            max_duration_seconds: Some(MAX_DURATION_SECS + 1),
            max_bytes: None,
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_over_max_bytes() {
        let result = run(CaptureTrafficArgs {
            process_path: "/usr/bin/curl".to_string(),
            parent_path: None,
            pcap_format: false,
            max_duration_seconds: Some(1),
            max_bytes: Some(MAX_ALLOWED_BYTES + 1),
        })
        .await;
        assert!(result.is_err());
    }
}
