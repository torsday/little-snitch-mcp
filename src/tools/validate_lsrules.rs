use std::sync::LazyLock;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

static SCHEMA_STR: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/lsrules.schema.json"));

static VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema: serde_json::Value =
        serde_json::from_str(SCHEMA_STR).expect("lsrules schema JSON is well-formed");
    jsonschema::options()
        .build(&schema)
        .expect("lsrules schema compiles")
});

/// Input for the `validate_lsrules` tool. Provide exactly one of `path` or `inline_json`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ValidateLsrulesArgs {
    /// Absolute path to a `.lsrules` JSON file on disk.
    pub path: Option<String>,
    /// In-memory JSON object to validate without writing a file.
    pub inline_json: Option<serde_json::Value>,
}

/// One schema-validation error with its JSON Pointer location.
#[derive(Debug, Serialize)]
pub struct FieldError {
    /// JSON Pointer (RFC 6901) to the failing node, e.g. `/rules/0/action`.
    pub path: String,
    /// Human-readable description of what went wrong.
    pub message: String,
    /// Expected value or type hint, when available.
    pub expected: Option<String>,
    /// Actual value that triggered the error, when available.
    pub actual: Option<String>,
}

/// Return value of the `validate_lsrules` tool.
#[derive(Debug, Serialize)]
pub struct ValidateResult {
    pub valid: bool,
    pub errors: Vec<FieldError>,
}

pub fn run(args: ValidateLsrulesArgs) -> Result<ValidateResult, String> {
    let instance: serde_json::Value = match (args.path, args.inline_json) {
        (Some(_), Some(_)) => {
            return Err("provide exactly one of `path` or `inline_json`, not both".into());
        }
        (None, None) => {
            return Err("one of `path` or `inline_json` is required".into());
        }
        (Some(p), None) => {
            let raw = std::fs::read_to_string(&p)
                .map_err(|e| format!("cannot read file {p:?}: {e}"))?;
            serde_json::from_str(&raw)
                .map_err(|e| format!("file {p:?} is not valid JSON: {e}"))?
        }
        (None, Some(v)) => v,
    };

    let errors: Vec<FieldError> = VALIDATOR
        .iter_errors(&instance)
        .map(|e| FieldError {
            path: e.instance_path().to_string(),
            message: e.to_string(),
            expected: None,
            actual: None,
        })
        .collect();

    Ok(ValidateResult {
        valid: errors.is_empty(),
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_args(v: serde_json::Value) -> ValidateLsrulesArgs {
        ValidateLsrulesArgs {
            path: None,
            inline_json: Some(v),
        }
    }

    #[test]
    fn minimal_valid_document() {
        let result = run(valid_args(json!({"name": "My Rules"}))).unwrap();
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn missing_required_name() {
        let result = run(valid_args(json!({}))).unwrap();
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let result = run(valid_args(json!({"name": "X", "bogus": true}))).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn valid_rule_with_allow_action() {
        let result = run(valid_args(json!({
            "name": "Test",
            "rules": [{"action": "allow", "process": "any", "remote": "any"}]
        })))
        .unwrap();
        assert!(result.valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn invalid_rule_action_rejected() {
        let result = run(valid_args(json!({
            "name": "Test",
            "rules": [{"action": "INVALID"}]
        })))
        .unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn error_includes_json_pointer_path() {
        let result = run(valid_args(json!({
            "name": "Test",
            "rules": [{"action": "INVALID"}]
        })))
        .unwrap();
        assert!(!result.errors.is_empty());
        let first = &result.errors[0];
        assert!(
            first.path.contains("rules") || first.path.contains("action"),
            "unexpected path: {}",
            first.path
        );
    }

    #[test]
    fn both_inputs_is_error() {
        let args = ValidateLsrulesArgs {
            path: Some("/tmp/x.lsrules".into()),
            inline_json: Some(json!({})),
        };
        assert!(run(args).is_err());
    }

    #[test]
    fn no_inputs_is_error() {
        let args = ValidateLsrulesArgs {
            path: None,
            inline_json: None,
        };
        assert!(run(args).is_err());
    }

    #[test]
    fn missing_file_is_error() {
        let args = ValidateLsrulesArgs {
            path: Some("/tmp/__nonexistent_lsrules_test__.lsrules".into()),
            inline_json: None,
        };
        assert!(run(args).is_err());
    }
}
