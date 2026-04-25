use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;

/// Input for the `show_restrictions` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ShowRestrictionsArgs {}

/// License and feature-gate information returned by `littlesnitch restrictions`.
#[derive(Debug, Serialize)]
pub struct ShowRestrictionsResult {
    /// Whether the copy is fully licensed (not demo/trial).
    pub licensed: bool,
    /// ISO 8601 date the license expires, or `null` for perpetual licenses.
    pub expires_at: Option<String>,
    /// `"full"` for a fully-featured license, `"limited"` for demo/trial mode.
    pub features: String,
    /// Raw output from the CLI for debugging unexpected formats.
    pub raw: String,
}

pub fn run(_args: ShowRestrictionsArgs) -> Result<ShowRestrictionsResult, String> {
    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    let output = cli
        .run(&["restrictions"])
        .map_err(|e| format!("littlesnitch restrictions failed: {e}"))?;

    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    parse_restrictions(&raw)
}

fn parse_restrictions(raw: &str) -> Result<ShowRestrictionsResult, String> {
    let lower = raw.to_ascii_lowercase();

    // Demo / unlicensed check — comes before the expires check because a
    // demo copy may also print expiry information.
    let licensed = !lower.contains("demo") && !lower.contains("not licensed");

    // Expiry: look for "expires on <date>" or "expired on <date>".
    // The CLI emits dates like "2025-01-01" or "January 1, 2025".
    let expires_at = extract_expiry(raw);

    // Feature level: "fully featured" → "full", anything else → "limited".
    let features = if lower.contains("fully featured") || lower.contains("full featured") {
        "full".to_string()
    } else {
        "limited".to_string()
    };

    Ok(ShowRestrictionsResult {
        licensed,
        expires_at,
        features,
        raw: raw.to_string(),
    })
}

/// Extract an expiry date from the restrictions output.
/// Returns ISO 8601 (YYYY-MM-DD) when the date is already in that format;
/// returns the raw date substring otherwise.
fn extract_expiry(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();

    // Pattern: "expires on YYYY-MM-DD" or "expired on YYYY-MM-DD"
    let (prefix, pos_opt) = if let Some(p) = lower.find("expired on ") {
        ("expired on ", Some(p))
    } else if let Some(p) = lower.find("expires on ") {
        ("expires on ", Some(p))
    } else {
        ("", None)
    };
    if let Some(pos) = pos_opt {
        let date_start = pos + prefix.len();
        let after = raw[date_start..].trim_start();
        let date_str: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ',')
            .collect();
        let date_str = date_str.trim_end_matches('.').trim().to_string();
        if !date_str.is_empty() {
            return Some(date_str);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_perpetual_full_license() {
        let raw = "Product never expires.\nHave fully featured non-expiring license.\n";
        let r = parse_restrictions(raw).unwrap();
        assert!(r.licensed);
        assert_eq!(r.expires_at, None);
        assert_eq!(r.features, "full");
    }

    #[test]
    fn parse_demo_mode() {
        let raw = "Running in demo mode.\nLimited features available.\n";
        let r = parse_restrictions(raw).unwrap();
        assert!(!r.licensed);
        assert_eq!(r.features, "limited");
    }

    #[test]
    fn parse_expiring_license() {
        let raw = "License expires on 2025-12-31.\nHave fully featured license.\n";
        let r = parse_restrictions(raw).unwrap();
        assert!(r.licensed);
        assert_eq!(r.expires_at.as_deref(), Some("2025-12-31"));
        assert_eq!(r.features, "full");
    }

    #[test]
    fn parse_expired_license() {
        let raw = "License expired on 2023-01-01.\nNot licensed.\n";
        let r = parse_restrictions(raw).unwrap();
        // expired + "not licensed" → unlicensed
        assert!(!r.licensed);
    }

    #[test]
    fn parse_unknown_format_returns_limited() {
        let raw = "Some unexpected output format.\n";
        let r = parse_restrictions(raw).unwrap();
        // unknown → conservative defaults
        assert!(r.licensed); // not explicitly marked unlicensed
        assert_eq!(r.features, "limited"); // not marked fully featured
    }
}
