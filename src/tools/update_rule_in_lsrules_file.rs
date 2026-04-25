use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

use crate::managed_dir::ManagedDir;
use crate::tools::validate_lsrules;

/// Input for the `update_rule_in_lsrules_file` tool.
/// Provide `file_name`, exactly one selector (`index` or `match_tuple`),
/// and `updates` — a partial rule object whose key/value pairs overwrite
/// the matching rule's fields.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateRuleArgs {
    /// Name of the `.lsrules` file (without extension) in the managed rules directory.
    pub file_name: String,
    /// Zero-based index of the rule to update within the `rules` array.
    pub index: Option<usize>,
    /// Partial rule object — every key/value must exactly match the target rule.
    /// Exactly one rule must match; zero or multiple matches are errors.
    pub match_tuple: Option<serde_json::Value>,
    /// Partial rule object whose fields are merged into the matched rule.
    /// Existing fields not present in `updates` are preserved unchanged.
    pub updates: serde_json::Value,
}

/// Return value of `update_rule_in_lsrules_file`.
#[derive(Debug, Serialize)]
pub struct UpdateRuleResult {
    pub file_name: String,
    pub updated_index: usize,
    pub rule_before: serde_json::Value,
    pub rule_after: serde_json::Value,
    pub rules_remaining: usize,
    pub diff: String,
}

pub fn run(args: UpdateRuleArgs) -> Result<UpdateRuleResult, String> {
    if args.file_name.is_empty() || args.file_name.contains('/') || args.file_name.contains('\\') {
        return Err(format!(
            "invalid file_name {:?}: must be a plain filename with no path separators or backslashes",
            args.file_name
        ));
    }

    match (&args.index, &args.match_tuple) {
        (None, None) => return Err("provide exactly one of `index` or `match_tuple`".into()),
        (Some(_), Some(_)) => {
            return Err("provide exactly one of `index` or `match_tuple`, not both".into());
        }
        _ => {}
    }

    let Some(updates_obj) = args.updates.as_object() else {
        return Err("`updates` must be a JSON object".into());
    };
    if updates_obj.is_empty() {
        return Err("`updates` must not be empty".into());
    }

    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;

    let target = managed.lsrules_file(&args.file_name);
    if !target.exists() {
        return Err(format!(
            "file not found: {target:?} — use create_lsrules_file to create it first"
        ));
    }

    let raw =
        std::fs::read_to_string(&target).map_err(|e| format!("cannot read {target:?}: {e}"))?;

    let mut doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{target:?} is not valid JSON: {e}"))?;

    let rules = doc
        .get_mut("rules")
        .and_then(|r| r.as_array_mut())
        .ok_or_else(|| "file has no `rules` array".to_string())?;

    let update_idx = match (args.index, args.match_tuple) {
        (Some(i), None) => {
            if i >= rules.len() {
                return Err(format!(
                    "index {i} is out of range (file has {} rules)",
                    rules.len()
                ));
            }
            i
        }
        (None, Some(ref matcher)) => {
            let matches: Vec<usize> = rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule_matches(rule, matcher))
                .map(|(i, _)| i)
                .collect();

            match matches.as_slice() {
                [] => return Err("no rules matched the provided match_tuple".into()),
                [i] => *i,
                multiple => {
                    return Err(format!(
                        "match_tuple is ambiguous: {} rules matched (indices: {:?})",
                        multiple.len(),
                        multiple
                    ));
                }
            }
        }
        _ => unreachable!(),
    };

    let rule_before = rules[update_idx].clone();

    // Apply partial update: merge updates_obj fields into the rule object.
    let rule = rules[update_idx]
        .as_object_mut()
        .ok_or_else(|| format!("rule at index {update_idx} is not a JSON object"))?;
    for (k, v) in updates_obj {
        rule.insert(k.clone(), v.clone());
    }

    let rule_after = rules[update_idx].clone();
    let rules_remaining = rules.len();

    // Re-validate after update
    let validation = validate_lsrules::run(validate_lsrules::ValidateLsrulesArgs {
        path: None,
        inline_json: Some(doc.clone()),
    })
    .map_err(|e| format!("post-update validation error: {e}"))?;

    if !validation.valid {
        let msgs: Vec<String> = validation
            .errors
            .iter()
            .map(|e| format!("  {}: {}", e.path, e.message))
            .collect();
        return Err(format!(
            "file would be invalid after update:\n{}",
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

    Ok(UpdateRuleResult {
        file_name: args.file_name,
        updated_index: update_idx,
        rule_before,
        rule_after,
        rules_remaining,
        diff,
    })
}

/// Returns true if every key/value in `matcher` appears verbatim in `rule`.
fn rule_matches(rule: &serde_json::Value, matcher: &serde_json::Value) -> bool {
    let Some(obj) = matcher.as_object() else {
        return false;
    };
    obj.iter().all(|(k, v)| rule.get(k) == Some(v))
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
    fn update_by_index_changes_field() {
        with_temp_dir(|| {
            write_file(
                "rules",
                &json!({
                    "name": "rules",
                    "rules": [
                        {"action": "allow", "process": "any", "remote": "any"},
                        {"action": "deny", "process": "/usr/bin/curl", "remote": "any"}
                    ]
                }),
            );
            let result = run(UpdateRuleArgs {
                file_name: "rules".into(),
                index: Some(0),
                match_tuple: None,
                updates: json!({"action": "deny"}),
            })
            .unwrap();
            assert_eq!(result.updated_index, 0);
            assert_eq!(result.rule_before["action"], "allow");
            assert_eq!(result.rule_after["action"], "deny");
            assert_eq!(result.rule_after["process"], "any");
            assert_eq!(result.rules_remaining, 2);
        });
    }

    #[test]
    fn update_by_match_tuple_changes_field() {
        with_temp_dir(|| {
            write_file(
                "mtch",
                &json!({
                    "name": "mtch",
                    "rules": [
                        {"action": "allow", "process": "/usr/bin/ssh", "remote": "any"},
                        {"action": "deny", "process": "/usr/bin/curl", "remote": "any"}
                    ]
                }),
            );
            let result = run(UpdateRuleArgs {
                file_name: "mtch".into(),
                index: None,
                match_tuple: Some(json!({"process": "/usr/bin/curl"})),
                updates: json!({"action": "allow"}),
            })
            .unwrap();
            assert_eq!(result.rule_after["action"], "allow");
            assert_eq!(result.rule_after["process"], "/usr/bin/curl");
        });
    }

    #[test]
    fn update_preserves_unmentioned_fields() {
        with_temp_dir(|| {
            write_file(
                "preserve",
                &json!({
                    "name": "preserve",
                    "rules": [
                        {"action": "allow", "process": "/bin/sh", "remote": "any"}
                    ]
                }),
            );
            let result = run(UpdateRuleArgs {
                file_name: "preserve".into(),
                index: Some(0),
                match_tuple: None,
                updates: json!({"action": "deny"}),
            })
            .unwrap();
            assert_eq!(result.rule_after["process"], "/bin/sh");
            assert_eq!(result.rule_after["remote"], "any");
        });
    }

    #[test]
    fn ambiguous_match_tuple_errors() {
        with_temp_dir(|| {
            write_file(
                "ambig",
                &json!({
                    "name": "ambig",
                    "rules": [
                        {"action": "deny", "remote": "any"},
                        {"action": "deny", "remote": "any"}
                    ]
                }),
            );
            let err = run(UpdateRuleArgs {
                file_name: "ambig".into(),
                index: None,
                match_tuple: Some(json!({"action": "deny"})),
                updates: json!({"remote": "host:foo.com"}),
            })
            .unwrap_err();
            assert!(err.contains("ambiguous"), "unexpected: {err}");
        });
    }

    #[test]
    fn no_match_errors() {
        with_temp_dir(|| {
            write_file(
                "nomatch",
                &json!({
                    "name": "nomatch",
                    "rules": [{"action": "allow", "remote": "any"}]
                }),
            );
            let err = run(UpdateRuleArgs {
                file_name: "nomatch".into(),
                index: None,
                match_tuple: Some(json!({"action": "deny"})),
                updates: json!({"remote": "host:foo.com"}),
            })
            .unwrap_err();
            assert!(err.contains("no rules matched"), "unexpected: {err}");
        });
    }

    #[test]
    fn out_of_range_index_errors() {
        with_temp_dir(|| {
            write_file(
                "range",
                &json!({
                    "name": "range",
                    "rules": [{"action": "allow", "remote": "any"}]
                }),
            );
            let err = run(UpdateRuleArgs {
                file_name: "range".into(),
                index: Some(5),
                match_tuple: None,
                updates: json!({"action": "deny"}),
            })
            .unwrap_err();
            assert!(err.contains("out of range"), "unexpected: {err}");
        });
    }

    #[test]
    fn empty_updates_errors() {
        with_temp_dir(|| {
            write_file(
                "empty",
                &json!({
                    "name": "empty",
                    "rules": [{"action": "allow", "remote": "any"}]
                }),
            );
            let err = run(UpdateRuleArgs {
                file_name: "empty".into(),
                index: Some(0),
                match_tuple: None,
                updates: json!({}),
            })
            .unwrap_err();
            assert!(err.contains("must not be empty"), "unexpected: {err}");
        });
    }

    #[test]
    fn result_contains_diff() {
        with_temp_dir(|| {
            write_file(
                "difftest",
                &json!({
                    "name": "difftest",
                    "rules": [
                        {"action": "allow", "remote": "any"},
                        {"action": "deny", "remote": "any"}
                    ]
                }),
            );
            let result = run(UpdateRuleArgs {
                file_name: "difftest".into(),
                index: Some(0),
                match_tuple: None,
                updates: json!({"action": "deny"}),
            })
            .unwrap();
            assert!(result.diff.contains("---"), "diff should have header");
            assert!(result.diff.contains('-'), "diff should have removed lines");
            assert!(result.diff.contains('+'), "diff should have added lines");
        });
    }

    #[test]
    fn missing_file_errors() {
        with_temp_dir(|| {
            let err = run(UpdateRuleArgs {
                file_name: "missing".into(),
                index: Some(0),
                match_tuple: None,
                updates: json!({"action": "deny"}),
            })
            .unwrap_err();
            assert!(err.contains("not found"), "unexpected: {err}");
        });
    }
}
