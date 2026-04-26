use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::managed_dir::ManagedDir;
use crate::tools::validate_lsrules;

/// Input for the `create_lsrules_file` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateLsrulesArgs {
    /// Name for the rule group. The file is written to `<managed_dir>/rules/<name>.lsrules`.
    /// Must be a valid filename component (no path separators).
    pub name: String,
    /// Optional human-readable description stored in the file.
    pub description: Option<String>,
    /// Compact domain blocklist entries added to `denied-remote-domains`.
    pub denied_remote_domains: Option<Vec<String>>,
    /// Individual connection rules.  Each entry must conform to the lsrules rule schema.
    pub rules: Option<Vec<Value>>,
    /// When `true`, overwrite any existing file at the target path.
    /// Defaults to `false`.
    pub replace: Option<bool>,
}

/// Successful return value of `create_lsrules_file`.
#[derive(Debug, serde::Serialize)]
pub struct CreateResult {
    pub path: PathBuf,
    pub name: String,
}

pub fn run(args: CreateLsrulesArgs) -> Result<CreateResult, String> {
    // Reject names that look like path traversal.
    if args.name.is_empty()
        || args.name.contains('/')
        || args.name.contains('\\')
        || args.name == ".."
        || args.name == "."
    {
        return Err(format!(
            "invalid name {:?}: must be a plain filename with no path separators",
            args.name
        ));
    }

    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;
    run_inner(args, &managed.rules)
}

/// Inner implementation — accepts an explicit `rules_dir` path for testing.
pub fn run_with_root(args: CreateLsrulesArgs, managed_root: &std::path::Path) -> Result<CreateResult, String> {
    let rules_dir = managed_root.join("rules");
    std::fs::create_dir_all(&rules_dir)
        .map_err(|e| format!("cannot create rules dir {rules_dir:?}: {e}"))?;
    run_inner(args, &rules_dir)
}

fn run_inner(args: CreateLsrulesArgs, rules_dir: &std::path::Path) -> Result<CreateResult, String> {
    let target = rules_dir.join(format!("{}.lsrules", args.name));

    if target.exists() && !args.replace.unwrap_or(false) {
        return Err(format!(
            "file already exists at {target:?}; pass `replace: true` to overwrite"
        ));
    }

    // Build the JSON document from the caller-supplied fields.
    // Always emit "rules" so add/update/remove tools can rely on it existing.
    let mut doc = json!({ "name": args.name, "rules": [] });
    if let Some(desc) = args.description {
        doc["description"] = json!(desc);
    }
    if let Some(domains) = args.denied_remote_domains.filter(|d| !d.is_empty()) {
        doc["denied-remote-domains"] = json!(domains);
    }
    if let Some(rules) = args.rules.filter(|r| !r.is_empty()) {
        doc["rules"] = json!(rules);
    }

    // Validate before touching the filesystem.
    let result = validate_lsrules::run(validate_lsrules::ValidateLsrulesArgs {
        path: None,
        inline_json: Some(doc.clone()),
    })
    .map_err(|e| format!("schema validation error: {e}"))?;

    if !result.valid {
        let msgs: Vec<String> = result
            .errors
            .iter()
            .map(|e| format!("  {}: {}", e.path, e.message))
            .collect();
        return Err(format!(
            "content failed schema validation:\n{}",
            msgs.join("\n")
        ));
    }

    // Write with mode 600 (owner read+write only).
    let json_bytes =
        serde_json::to_vec_pretty(&doc).map_err(|e| format!("serialization error: {e}"))?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&target)
        .map_err(|e| format!("cannot open {target:?} for writing: {e}"))?;

    file.write_all(&json_bytes)
        .map_err(|e| format!("write error on {target:?}: {e}"))?;

    Ok(CreateResult {
        path: target,
        name: args.name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn with_temp_dir<F: FnOnce()>(f: F) {
        // Shared lock prevents concurrent env-var mutation across all managed-dir tests.
        let _guard = crate::managed_dir::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let td = tempfile::tempdir().unwrap();
        // SAFETY: protected by ENV_LOCK; no concurrent env mutation in this module.
        unsafe {
            std::env::set_var(crate::managed_dir::ENV_MANAGED_DIR, td.path().join("mcp"));
        }
        f();
        unsafe {
            std::env::remove_var(crate::managed_dir::ENV_MANAGED_DIR);
        }
    }

    fn minimal(name: &str) -> CreateLsrulesArgs {
        CreateLsrulesArgs {
            name: name.to_string(),
            description: None,
            denied_remote_domains: None,
            rules: None,
            replace: None,
        }
    }

    #[test]
    fn creates_file_with_correct_name() {
        with_temp_dir(|| {
            let result = run(minimal("my-rules")).unwrap();
            assert!(result.path.exists());
            assert_eq!(result.path.file_name().unwrap(), "my-rules.lsrules");
        });
    }

    #[test]
    fn file_has_mode_600() {
        with_temp_dir(|| {
            let result = run(minimal("mode-test")).unwrap();
            let mode = fs::metadata(&result.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected mode 600, got {mode:o}");
        });
    }

    #[test]
    fn file_contains_name_field() {
        with_temp_dir(|| {
            let result = run(minimal("check-name")).unwrap();
            let content: Value =
                serde_json::from_str(&fs::read_to_string(&result.path).unwrap()).unwrap();
            assert_eq!(content["name"], "check-name");
        });
    }

    #[test]
    fn refuses_overwrite_without_replace() {
        with_temp_dir(|| {
            run(minimal("dup")).unwrap();
            let err = run(minimal("dup")).unwrap_err();
            assert!(err.contains("replace: true"), "unexpected: {err}");
        });
    }

    #[test]
    fn replace_true_overwrites() {
        with_temp_dir(|| {
            run(minimal("overwrite-me")).unwrap();
            let mut args = minimal("overwrite-me");
            args.replace = Some(true);
            assert!(run(args).is_ok());
        });
    }

    #[test]
    fn description_stored_in_file() {
        with_temp_dir(|| {
            let args = CreateLsrulesArgs {
                description: Some("My desc".into()),
                ..minimal("with-desc")
            };
            let r = run(args).unwrap();
            let content: Value =
                serde_json::from_str(&fs::read_to_string(&r.path).unwrap()).unwrap();
            assert_eq!(content["description"], "My desc");
        });
    }

    #[test]
    fn valid_rule_is_accepted() {
        with_temp_dir(|| {
            let args = CreateLsrulesArgs {
                rules: Some(vec![
                    json!({"action": "allow", "process": "any", "remote": "any"}),
                ]),
                ..minimal("with-rule")
            };
            assert!(run(args).is_ok());
        });
    }

    #[test]
    fn invalid_rule_is_rejected() {
        with_temp_dir(|| {
            let args = CreateLsrulesArgs {
                rules: Some(vec![json!({"action": "INVALID"})]),
                ..minimal("bad-rule")
            };
            let err = run(args).unwrap_err();
            assert!(err.contains("schema validation"), "unexpected error: {err}");
        });
    }

    #[test]
    fn path_traversal_in_name_rejected() {
        with_temp_dir(|| {
            let args = minimal("../escape");
            assert!(run(args).is_err());
        });
    }
}
