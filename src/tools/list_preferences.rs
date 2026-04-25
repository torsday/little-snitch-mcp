use std::collections::BTreeMap;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;
use crate::safety::secret_prefs;

/// Which preference store to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PreferenceScope {
    /// System-wide defaults only (`-g`).
    Global,
    /// Per-user overrides only (`-u`).
    User,
    /// Both stores merged (default when omitted).
    All,
}

/// Input for the `list_preferences` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListPreferencesArgs {
    /// Which preference store to query.
    /// - `"global"` → system-wide defaults (`-g`)
    /// - `"user"` → per-user overrides (`-u`)
    /// - `"all"` → both stores merged (default when omitted)
    pub scope: Option<PreferenceScope>,
}

/// Return value of `list_preferences`.
#[derive(Debug, Serialize)]
pub struct ListPreferencesResult {
    /// Alphabetically-sorted map of preference key → value.
    /// Secret values are replaced with `"<redacted: KEY>"`.
    pub preferences: BTreeMap<String, serde_json::Value>,
    /// Total number of preference keys returned.
    pub count: usize,
}

pub fn run(args: ListPreferencesArgs) -> Result<ListPreferencesResult, String> {
    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;

    let scope = args.scope.unwrap_or(PreferenceScope::All);

    let prefs = match scope {
        PreferenceScope::Global => fetch_prefs(&cli, &["-g"])?,
        PreferenceScope::User => fetch_prefs(&cli, &["-u"])?,
        PreferenceScope::All => fetch_prefs(&cli, &[])?,
    };

    let count = prefs.len();
    Ok(ListPreferencesResult {
        preferences: prefs,
        count,
    })
}

/// Run `littlesnitch list-preferences [extra_args]` and parse `key = value` lines.
fn fetch_prefs(
    cli: &LsCli,
    extra_args: &[&str],
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let mut cmd_args = vec!["list-preferences"];
    cmd_args.extend_from_slice(extra_args);

    let output = cli
        .run(&cmd_args)
        .map_err(|e| format!("list-preferences failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_pref_lines(&stdout)
}

/// Parse `key = value` lines from `littlesnitch list-preferences` output.
///
/// Each line has the form `key = value`. The value may be any JSON-serializable
/// type (bool, number, string, array, object). Lines that don't match the
/// `key = value` pattern are silently skipped.
fn parse_pref_lines(output: &str) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let mut map = BTreeMap::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(2, " = ").collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0].trim().to_string();
        let raw_value = parts[1].trim();
        if key.is_empty() {
            continue;
        }
        let parsed: serde_json::Value = serde_json::from_str(raw_value)
            .unwrap_or_else(|_| serde_json::Value::String(raw_value.trim().to_string()));

        map.insert(key.clone(), secret_prefs::redact(&key, parsed));
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> BTreeMap<String, serde_json::Value> {
        parse_pref_lines(s).unwrap()
    }

    #[test]
    fn parses_bool_pref() {
        let m = parse("activeSilentMode = false\n");
        assert_eq!(m["activeSilentMode"], serde_json::json!(false));
    }

    #[test]
    fn parses_number_pref() {
        let m = parse("autoConfirmationDelay = 30\n");
        assert_eq!(m["autoConfirmationDelay"], serde_json::json!(30));
    }

    #[test]
    fn parses_string_pref() {
        let m = parse("autoConfirmationAction = \"allow\"\n");
        assert_eq!(m["autoConfirmationAction"], serde_json::json!("allow"));
    }

    #[test]
    fn parses_unquoted_string_as_string() {
        let m = parse("autoConfirmationAction = hello\n");
        assert_eq!(m["autoConfirmationAction"], serde_json::json!("hello"));
    }

    #[test]
    fn redacts_secret_key() {
        let m = parse("dnsEncryptionConfigurations = [{\"url\":\"https://example.com\"}]\n");
        let v = m["dnsEncryptionConfigurations"].as_str().unwrap();
        assert!(v.starts_with("<redacted:"), "expected redaction, got: {v}");
    }

    #[test]
    fn skips_malformed_lines() {
        let m = parse("noequalssign\nactiveSilentMode = true\n");
        assert!(!m.contains_key("noequalssign"));
        assert_eq!(m["activeSilentMode"], serde_json::json!(true));
    }

    #[test]
    fn empty_output_returns_empty_map() {
        let m = parse("");
        assert!(m.is_empty());
    }

    #[test]
    fn result_count_matches_map_len() {
        // Verify count field in the result struct
        let prefs: BTreeMap<String, serde_json::Value> = {
            let mut m = BTreeMap::new();
            m.insert("a".into(), serde_json::json!(1));
            m.insert("b".into(), serde_json::json!(2));
            m
        };
        let count = prefs.len();
        let result = ListPreferencesResult {
            preferences: prefs,
            count,
        };
        assert_eq!(result.count, 2);
    }
}
