use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;

/// Input for the `tail_traffic` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TailTrafficArgs {
    /// Begin timestamp (ISO 8601 or relative like "30m ago", "1h ago").
    /// If omitted, the CLI returns all available history.
    pub begin: Option<String>,
    /// End timestamp (ISO 8601 or relative). Defaults to now.
    pub end: Option<String>,
    /// Filter: keep only entries where `connectingExecutable` contains this substring
    /// (case-insensitive).
    pub process_name: Option<String>,
    /// Filter: keep only entries where `remoteHostname` or `ipAddress` contains this
    /// substring (case-insensitive).
    pub remote_host: Option<String>,
    /// Filter: keep only entries with this direction (`"in"` or `"out"`).
    pub direction: Option<String>,
}

/// A single traffic-stats row returned by `littlesnitch log-traffic`.
///
/// Untrusted external data (hostnames, process paths) is wrapped in an
/// `untrusted_data` envelope per ADR-0004 §9b.
#[derive(Debug, Serialize)]
pub struct TrafficEntry {
    pub date: String,
    pub direction: String,
    pub uid: String,
    /// IP address of the remote host (from the CLI — safe numeric string).
    pub ip_address: String,
    /// Remote hostname as reported by LS. Untrusted (DNS-derived).
    pub remote_hostname: UntrustedData,
    /// Protocol name derived from the numeric protocol field (tcp/udp/other).
    pub protocol: String,
    pub port: u16,
    pub connect_count: u64,
    pub deny_count: u64,
    pub byte_count_in: u64,
    pub byte_count_out: u64,
    /// Path to the connecting executable. Untrusted (user-controlled filesystem path).
    pub connecting_executable: UntrustedData,
    /// Parent application executable. May be empty. Untrusted.
    pub parent_app_executable: UntrustedData,
}

/// Wrapper marking data that originates outside the trusted kernel/daemon boundary.
/// LLM consumers should treat the `value` as potentially adversarial input
/// (e.g. a hostname that embeds prompt-injection text).
#[derive(Debug, Serialize, Deserialize)]
pub struct UntrustedData {
    pub untrusted_data: String,
}

impl UntrustedData {
    fn new(s: impl Into<String>) -> Self {
        Self {
            untrusted_data: s.into(),
        }
    }

    fn contains_ci(&self, needle: &str) -> bool {
        self.untrusted_data
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    }
}

/// Return value of `tail_traffic`.
#[derive(Debug, Serialize)]
pub struct TailTrafficResult {
    pub entries: Vec<TrafficEntry>,
    pub count: usize,
    pub filtered_count: usize,
}

/// Maximum number of rows returned to guard against overwhelming the context window.
pub const MAX_ROWS: usize = 10_000;

pub fn run(args: TailTrafficArgs) -> Result<TailTrafficResult, String> {
    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;

    let mut cmd_args: Vec<String> = vec!["log-traffic".to_string()];
    if let Some(b) = &args.begin {
        cmd_args.push("-b".to_string());
        cmd_args.push(b.clone());
    }
    if let Some(e) = &args.end {
        cmd_args.push("-e".to_string());
        cmd_args.push(e.clone());
    }

    let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
    let output = cli
        .run(&str_args)
        .map_err(|e| format!("littlesnitch log-traffic failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let all_entries = parse_csv(&stdout)?;
    let total = all_entries.len();

    // Post-fetch filters
    let filtered: Vec<TrafficEntry> = all_entries
        .into_iter()
        .filter(|e| {
            if let Some(p) = &args.process_name {
                if !e.connecting_executable.contains_ci(p) {
                    return false;
                }
            }
            if let Some(h) = &args.remote_host {
                let needle = h.to_ascii_lowercase();
                if !e.ip_address.to_ascii_lowercase().contains(&needle)
                    && !e.remote_hostname.contains_ci(h)
                {
                    return false;
                }
            }
            if let Some(d) = &args.direction {
                if !e.direction.eq_ignore_ascii_case(d) {
                    return false;
                }
            }
            true
        })
        .take(MAX_ROWS)
        .collect();

    let count = filtered.len();
    Ok(TailTrafficResult {
        entries: filtered,
        count,
        filtered_count: total,
    })
}

/// Parse newline-delimited CSV from `littlesnitch log-traffic` output.
///
/// The format has 13 columns (confirmed empirically from the feasibility report):
/// date, direction, uid, ipAddress, remoteHostname, protocol, port,
/// connectCount, denyCount, byteCountIn, byteCountOut,
/// connectingExecutable, parentAppExecutable
///
/// Fields may be quoted CSV strings (especially paths).
fn parse_csv(output: &str) -> Result<Vec<TrafficEntry>, String> {
    let mut entries = Vec::new();

    for (line_no, line) in output.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip a header line if present
        if line_no == 0 && line.starts_with("date") {
            continue;
        }

        let cols = split_csv_line(line);
        if cols.len() < 13 {
            return Err(format!(
                "CSV line {line_no}: expected 13 columns, got {}; line: {line:?}",
                cols.len()
            ));
        }

        let date = cols[0].clone();
        let direction = cols[1].clone();
        let uid = cols[2].clone();
        let ip_address = cols[3].clone();
        let remote_hostname = UntrustedData::new(cols[4].clone());
        let protocol_num: u32 = cols[5].parse().unwrap_or(0);
        let protocol = protocol_name(protocol_num);
        let port: u16 = cols[6].parse().unwrap_or(0);
        let connect_count: u64 = cols[7].parse().unwrap_or(0);
        let deny_count: u64 = cols[8].parse().unwrap_or(0);
        let byte_count_in: u64 = cols[9].parse().unwrap_or(0);
        let byte_count_out: u64 = cols[10].parse().unwrap_or(0);
        let connecting_executable = UntrustedData::new(cols[11].clone());
        let parent_app_executable = UntrustedData::new(cols[12].clone());

        entries.push(TrafficEntry {
            date,
            direction,
            uid,
            ip_address,
            remote_hostname,
            protocol,
            port,
            connect_count,
            deny_count,
            byte_count_in,
            byte_count_out,
            connecting_executable,
            parent_app_executable,
        });
    }

    Ok(entries)
}

/// Map numeric protocol to a name. Only TCP and UDP are common; everything
/// else returns the numeric string.
fn protocol_name(num: u32) -> String {
    match num {
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        1 => "icmp".to_string(),
        n => n.to_string(),
    }
}

/// Parse a single CSV line, handling double-quoted fields.
/// Per RFC 4180: fields may be enclosed in double quotes; a double quote
/// inside a quoted field is escaped as two double quotes.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match (c, in_quotes) {
            ('"', false) => {
                in_quotes = true;
            }
            ('"', true) => {
                if chars.peek() == Some(&'"') {
                    // Escaped double-quote
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            (',', false) => {
                fields.push(std::mem::take(&mut current));
            }
            (other, _) => {
                current.push(other);
            }
        }
    }
    fields.push(current);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_csv_line_simple() {
        let cols = split_csv_line("a,b,c,d");
        assert_eq!(cols, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn split_csv_line_quoted_field() {
        let cols = split_csv_line(r#"a,"b,c",d"#);
        assert_eq!(cols, vec!["a", "b,c", "d"]);
    }

    #[test]
    fn split_csv_line_quoted_with_escaped_quote() {
        let cols = split_csv_line(r#"a,"b""c",d"#);
        assert_eq!(cols, vec!["a", "b\"c", "d"]);
    }

    #[test]
    fn split_csv_line_empty_field() {
        let cols = split_csv_line("a,,c");
        assert_eq!(cols, vec!["a", "", "c"]);
    }

    #[test]
    fn protocol_name_maps_known() {
        assert_eq!(protocol_name(6), "tcp");
        assert_eq!(protocol_name(17), "udp");
        assert_eq!(protocol_name(1), "icmp");
    }

    #[test]
    fn protocol_name_unknown_returns_number() {
        assert_eq!(protocol_name(99), "99");
    }

    #[test]
    fn parse_csv_single_row() {
        let csv = "2024-01-15T10:00:00Z,out,501,93.184.216.34,example.com,6,443,5,0,1024,512,\"/Applications/Safari.app/Contents/MacOS/Safari\",\"/Applications/Safari.app\"\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.date, "2024-01-15T10:00:00Z");
        assert_eq!(e.direction, "out");
        assert_eq!(e.uid, "501");
        assert_eq!(e.ip_address, "93.184.216.34");
        assert_eq!(e.remote_hostname.untrusted_data, "example.com");
        assert_eq!(e.protocol, "tcp");
        assert_eq!(e.port, 443);
        assert_eq!(e.connect_count, 5);
        assert_eq!(e.deny_count, 0);
        assert_eq!(e.byte_count_in, 1024);
        assert_eq!(e.byte_count_out, 512);
        assert_eq!(
            e.connecting_executable.untrusted_data,
            "/Applications/Safari.app/Contents/MacOS/Safari"
        );
        assert_eq!(
            e.parent_app_executable.untrusted_data,
            "/Applications/Safari.app"
        );
    }

    #[test]
    fn parse_csv_skips_header_line() {
        let csv = "date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable\n2024-01-15T10:00:00Z,out,501,1.2.3.4,host.example,6,80,1,0,100,50,/usr/bin/curl,\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_csv_skips_empty_lines() {
        let csv = "\n2024-01-15T10:00:00Z,out,501,1.2.3.4,,17,53,2,0,200,400,/usr/bin/dns-resolver,\n\n";
        let entries = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, "udp");
    }

    #[test]
    fn parse_csv_rejects_too_few_columns() {
        let csv = "a,b,c\n";
        let result = parse_csv(csv);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 13 columns"));
    }

    #[test]
    fn untrusted_data_contains_ci() {
        let d = UntrustedData::new("Example.COM");
        assert!(d.contains_ci("example.com"));
        assert!(d.contains_ci("EXAMPLE"));
        assert!(!d.contains_ci("google"));
    }

    #[test]
    fn max_rows_constant_reasonable() {
        assert!(MAX_ROWS >= 1000, "MAX_ROWS should be at least 1000");
        assert!(MAX_ROWS <= 100_000, "MAX_ROWS should not be unreasonably large");
    }
}
