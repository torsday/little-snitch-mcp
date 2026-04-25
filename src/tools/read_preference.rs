use std::collections::HashMap;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;

/// Input for the `read_preference` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadPreferenceArgs {
    /// One or more preference keys to read from the Little Snitch preferences.
    /// Each key is a dot-separated path into the `globalDefaults` dictionary,
    /// e.g. `"allowCitrixMode"` or `"statisticsEnabled"`.
    pub keys: Vec<String>,
}

/// Return value of `read_preference`.
#[derive(Debug, Serialize)]
pub struct ReadPreferenceResult {
    /// Map of key → value. A `null` value indicates the key is not present.
    pub values: HashMap<String, serde_json::Value>,
}

pub fn run(args: ReadPreferenceArgs) -> Result<ReadPreferenceResult, String> {
    if args.keys.is_empty() {
        return Err("`keys` must not be empty".into());
    }

    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;

    let mut values = HashMap::new();

    for key in &args.keys {
        if key.is_empty() {
            return Err("preference key must not be empty".into());
        }

        let output = cli
            .run(&["read-preference", key.as_str()])
            .map_err(|e| format!("read-preference {key:?} failed: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        // The CLI returns JSON output. A missing key returns null or an empty
        // result — do NOT trust the exit code (it is 0 even for missing keys).
        let value = if trimmed.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(trimmed).unwrap_or(serde_json::Value::String(trimmed.to_string()))
        };

        values.insert(key.clone(), value);
    }

    Ok(ReadPreferenceResult { values })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_keys_errors() {
        let err = run(ReadPreferenceArgs { keys: vec![] }).unwrap_err();
        assert!(err.contains("must not be empty"), "unexpected: {err}");
    }

    #[test]
    fn empty_key_string_errors() {
        // We can't call the real CLI in unit tests, but we can test validation
        // that happens before the CLI call.
        let err = run(ReadPreferenceArgs {
            keys: vec!["".into()],
        })
        .unwrap_err();
        assert!(err.contains("must not be empty"), "unexpected: {err}");
    }
}
