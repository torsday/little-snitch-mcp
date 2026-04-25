use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

use crate::managed_dir::ManagedDir;
use crate::tools::validate_lsrules;

/// Input for the `add_rule_to_lsrules_file` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddRuleArgs {
    /// Name of the `.lsrules` file (without extension) in the managed rules directory.
    pub file_name: String,
    /// The rule object to append. Must be a valid lsrules rule.
    pub rule: serde_json::Value,
}

/// Return value of `add_rule_to_lsrules_file`.
#[derive(Debug, Serialize)]
pub struct AddRuleResult {
    pub file_name: String,
    /// True when an equivalent rule was already present; no change was made.
    pub already_present: bool,
    /// Index of the (new or pre-existing) rule in the `rules` array.
    pub rule_index: usize,
    pub rules_total: usize,
    pub diff: String,
}

pub fn run(args: AddRuleArgs) -> Result<AddRuleResult, String> {
    if args.file_name.is_empty() || args.file_name.contains('/') || args.file_name.contains('\\') {
        return Err(format!("invalid file_name {:?}", args.file_name));
    }

    if args.rule.as_object().is_none() {
        return Err("`rule` must be a JSON object".into());
    }

    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;

    let target = managed.lsrules_file(&args.file_name);
    if !target.exists() {
        return Err(format!("file not found: {target:?}"));
    }

    let raw =
        std::fs::read_to_string(&target).map_err(|e| format!("cannot read {target:?}: {e}"))?;

    let mut doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{target:?} is not valid JSON: {e}"))?;

    let rules = doc
        .get_mut("rules")
        .and_then(|r| r.as_array_mut())
        .ok_or_else(|| "file has no `rules` array".to_string())?;

    // Dedup: check if an equivalent rule already exists.
    let dedup_key = uniqueness_key(&args.rule);
    let existing_idx = rules.iter().position(|r| uniqueness_key(r) == dedup_key);

    if let Some(idx) = existing_idx {
        return Ok(AddRuleResult {
            file_name: args.file_name,
            already_present: true,
            rule_index: idx,
            rules_total: rules.len(),
            diff: String::new(),
        });
    }

    // Append the new rule.
    rules.push(args.rule.clone());
    let new_idx = rules.len() - 1;
    let rules_total = rules.len();

    // Validate before writing.
    let validation = validate_lsrules::run(validate_lsrules::ValidateLsrulesArgs {
        path: None,
        inline_json: Some(doc.clone()),
    })
    .map_err(|e| format!("post-add validation error: {e}"))?;

    if !validation.valid {
        let msgs: Vec<String> = validation
            .errors
            .iter()
            .map(|e| format!("  {}: {}", e.path, e.message))
            .collect();
        return Err(format!(
            "file would be invalid after adding rule:\n{}",
            msgs.join("\n")
        ));
    }

    let new_json =
        serde_json::to_string_pretty(&doc).map_err(|e| format!("serialization error: {e}"))?;

    let diff = make_diff(&raw, &new_json, &format!("{}.lsrules", args.file_name));

    let new_bytes = new_json.as_bytes();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&target)
        .map_err(|e| format!("cannot open {target:?} for writing: {e}"))?;
    file.write_all(new_bytes)
        .map_err(|e| format!("write error on {target:?}: {e}"))?;

    Ok(AddRuleResult {
        file_name: args.file_name,
        already_present: false,
        rule_index: new_idx,
        rules_total,
        diff,
    })
}

/// Produces a uniqueness key for deduplication: the tuple of
/// (process, remote, direction, ports, action) extracted from the rule.
/// Fields absent in the rule contribute `null` to the key.
fn uniqueness_key(rule: &serde_json::Value) -> [serde_json::Value; 5] {
    let get = |k: &str| rule.get(k).cloned().unwrap_or(serde_json::Value::Null);
    [
        get("process"),
        get("remote"),
        get("direction"),
        get("ports"),
        get("action"),
    ]
}

/// Produces a unified diff string between `before` and `after`.
fn make_diff(before: &str, after: &str, filename: &str) -> String {
    let diff = TextDiff::from_lines(before, after);
    let mut out = format!("--- a/{filename}\n+++ b/{filename}\n");
    for group in diff.grouped_ops(3) {
        for op in group {
            for change in diff.iter_changes(&op) {
                let prefix = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                out.push_str(prefix);
                out.push_str(change.value());
                if !change.value().ends_with('\n') {
                    out.push('\n');
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn with_temp_dir<F: FnOnce()>(f: F) {
        let _guard = crate::managed_dir::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let td = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var(crate::managed_dir::ENV_MANAGED_DIR, td.path().join("mcp"));
        }
        f();
        unsafe {
            std::env::remove_var(crate::managed_dir::ENV_MANAGED_DIR);
        }
    }

    fn write_file(name: &str, content: &serde_json::Value) {
        let managed = ManagedDir::bootstrap().unwrap();
        let path = managed.lsrules_file(name);
        let bytes = serde_json::to_vec_pretty(content).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(&bytes).unwrap();
    }

    #[test]
    fn add_new_rule_appends_it() {
        with_temp_dir(|| {
            write_file(
                "rules",
                &json!({
                    "name": "rules",
                    "rules": [
                        {"action": "allow", "process": "any", "remote": "any"}
                    ]
                }),
            );
            let result = run(AddRuleArgs {
                file_name: "rules".into(),
                rule: json!({"action": "deny", "process": "/usr/bin/curl", "remote": "any"}),
            })
            .unwrap();
            assert!(!result.already_present);
            assert_eq!(result.rule_index, 1);
            assert_eq!(result.rules_total, 2);
            assert!(result.diff.contains('+'));
        });
    }

    #[test]
    fn adding_duplicate_rule_is_noop() {
        with_temp_dir(|| {
            write_file(
                "dup",
                &json!({
                    "name": "dup",
                    "rules": [
                        {"action": "allow", "process": "any", "remote": "any"}
                    ]
                }),
            );
            let result = run(AddRuleArgs {
                file_name: "dup".into(),
                rule: json!({"action": "allow", "process": "any", "remote": "any"}),
            })
            .unwrap();
            assert!(result.already_present);
            assert_eq!(result.rule_index, 0);
            assert_eq!(result.rules_total, 1);
            assert!(result.diff.is_empty());
        });
    }

    #[test]
    fn dedup_only_matches_same_tuple() {
        with_temp_dir(|| {
            write_file(
                "nodup",
                &json!({
                    "name": "nodup",
                    "rules": [
                        {"action": "allow", "process": "any", "remote": "any"}
                    ]
                }),
            );
            // Different action — should NOT be treated as duplicate
            let result = run(AddRuleArgs {
                file_name: "nodup".into(),
                rule: json!({"action": "deny", "process": "any", "remote": "any"}),
            })
            .unwrap();
            assert!(!result.already_present);
            assert_eq!(result.rules_total, 2);
        });
    }

    #[test]
    fn invalid_rule_is_rejected() {
        with_temp_dir(|| {
            write_file("invalid", &json!({"name": "invalid", "rules": []}));
            let err = run(AddRuleArgs {
                file_name: "invalid".into(),
                rule: json!({"action": "bad-action", "remote": "any"}),
            })
            .unwrap_err();
            assert!(err.contains("invalid after adding"), "unexpected: {err}");
        });
    }

    #[test]
    fn missing_file_errors() {
        with_temp_dir(|| {
            let err = run(AddRuleArgs {
                file_name: "missing".into(),
                rule: json!({"action": "allow", "remote": "any"}),
            })
            .unwrap_err();
            assert!(err.contains("not found"), "unexpected: {err}");
        });
    }

    #[test]
    fn non_object_rule_errors() {
        with_temp_dir(|| {
            write_file("badrule", &json!({"name": "badrule", "rules": []}));
            let err = run(AddRuleArgs {
                file_name: "badrule".into(),
                rule: json!("not an object"),
            })
            .unwrap_err();
            assert!(err.contains("must be a JSON object"), "unexpected: {err}");
        });
    }
}
