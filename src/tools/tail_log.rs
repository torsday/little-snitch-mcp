use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;

/// Maximum allowed duration in seconds (1 hour).
pub const MAX_DURATION_SECS: u64 = 3600;

/// Input for the `tail_log` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TailLogArgs {
    /// How many seconds to collect log events. Maximum 3600 (1 hour).
    pub duration_secs: u64,
    /// Optional NSPredicate filter string, e.g. `"processName == 'Safari'"`.
    pub predicate: Option<String>,
}

/// Return value of `tail_log`.
#[derive(Debug, Serialize)]
pub struct TailLogResult {
    /// Log events parsed from the JSON stream.
    pub events: Vec<serde_json::Value>,
    /// Total number of events returned.
    pub count: usize,
    /// The duration that was requested, in seconds.
    pub duration_secs: u64,
}

pub fn run(args: TailLogArgs) -> Result<TailLogResult, String> {
    if args.duration_secs == 0 {
        return Err("duration_secs must be at least 1".to_string());
    }
    if args.duration_secs > MAX_DURATION_SECS {
        return Err(format!(
            "duration_secs {} exceeds maximum of {MAX_DURATION_SECS} (1 hour)",
            args.duration_secs
        ));
    }

    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;

    let duration_str = format!("{}s", args.duration_secs);
    let mut extra: Vec<String> = Vec::new();
    if let Some(pred) = args.predicate {
        extra.push("-p".to_string());
        extra.push(pred);
    }
    let mut cmd_args: Vec<&str> = vec!["log", "-j", "-l", &duration_str];
    for s in &extra {
        cmd_args.push(s.as_str());
    }

    let output = cli
        .run(&cmd_args)
        .map_err(|e| format!("littlesnitch log failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let events = parse_json_lines(&stdout)?;
    let count = events.len();

    Ok(TailLogResult {
        events,
        count,
        duration_secs: args.duration_secs,
    })
}

/// Parse newline-delimited JSON from `littlesnitch log -j` output.
///
/// Lines that are blank or don't start with `{`/`[` are silently skipped
/// (the CLI may emit header/footer text). Malformed JSON-shaped lines are
/// surfaced as errors so callers see real parse failures.
fn parse_json_lines(output: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut events = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('{') && !line.starts_with('[') {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => events.push(v),
            Err(e) => return Err(format!("failed to parse log event: {e}: {line}")),
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_duration() {
        let err = run(TailLogArgs {
            duration_secs: 0,
            predicate: None,
        })
        .unwrap_err();
        assert!(err.contains("at least 1"), "unexpected: {err}");
    }

    #[test]
    fn rejects_over_max_duration() {
        let err = run(TailLogArgs {
            duration_secs: MAX_DURATION_SECS + 1,
            predicate: None,
        })
        .unwrap_err();
        assert!(err.contains("exceeds maximum"), "unexpected: {err}");
    }

    #[test]
    fn accepts_max_duration_bound_check_only() {
        // Only verifies the bounds logic passes — no live binary required.
        if let Err(msg) = run(TailLogArgs {
            duration_secs: MAX_DURATION_SECS,
            predicate: None,
        }) {
            assert!(
                !msg.contains("exceeds maximum"),
                "got bounds error at max: {msg}"
            );
        }
    }

    #[test]
    fn parse_empty_output() {
        assert!(parse_json_lines("").unwrap().is_empty());
    }

    #[test]
    fn parse_single_event() {
        let events = parse_json_lines(r#"{"process":"Safari","remote":"example.com"}"#).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["process"], "Safari");
    }

    #[test]
    fn parse_multiple_events() {
        let input = "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
        assert_eq!(parse_json_lines(input).unwrap().len(), 3);
    }

    #[test]
    fn parse_skips_blank_lines() {
        let input = "{\"a\":1}\n\n{\"b\":2}\n";
        assert_eq!(parse_json_lines(input).unwrap().len(), 2);
    }

    #[test]
    fn parse_skips_non_json_text() {
        let input = "Starting log capture...\n{\"a\":1}\nDone.\n";
        assert_eq!(parse_json_lines(input).unwrap().len(), 1);
    }

    #[test]
    fn parse_errors_on_malformed_json_object() {
        let result = parse_json_lines("{invalid}\n");
        assert!(result.is_err(), "expected parse error for malformed JSON");
    }

    #[test]
    fn result_fields_consistent() {
        let r = TailLogResult {
            events: vec![serde_json::json!({"x": 1}), serde_json::json!({"y": 2})],
            count: 2,
            duration_secs: 30,
        };
        assert_eq!(r.count, r.events.len());
        assert_eq!(r.duration_secs, 30);
    }
}
