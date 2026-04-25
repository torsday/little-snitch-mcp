use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

use crate::managed_dir::ManagedDir;
use crate::tools::validate_lsrules;

/// Input for the `remove_rule_from_lsrules_file` tool.
/// Provide `file_name` plus exactly one of `index` or `match_tuple`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveRuleArgs {
    /// Name of the `.lsrules` file (without extension) in the managed rules directory.
    pub file_name: String,
    /// Zero-based index of the rule to remove within the `rules` array.
    pub index: Option<usize>,
    /// Partial rule object — every key/value must exactly match the target rule.
    /// Exactly one rule must match; zero or multiple matches are errors.
    pub match_tuple: Option<serde_json::Value>,
}

/// Return value of `remove_rule_from_lsrules_file`.
#[derive(Debug, Serialize)]
pub struct RemoveRuleResult {
    pub file_name: String,
    pub removed_index: usize,
    pub removed_rule: serde_json::Value,
    pub rules_remaining: usize,
    pub diff: String,
}

pub fn run(args: RemoveRuleArgs) -> Result<RemoveRuleResult, String> {
    // Validate file_name
    if args.file_name.is_empty() || args.file_name.contains('/') || args.file_name.contains('\\') {
        return Err(format!(
            "invalid file_name {:?}: must be a plain filename with no path separators or backslashes",
            args.file_name
        ));
    }

    // Exactly one selector required
    match (&args.index, &args.match_tuple) {
        (None, None) => return Err("provide exactly one of `index` or `match_tuple`".into()),
        (Some(_), Some(_)) => {
            return Err("provide exactly one of `index` or `match_tuple`, not both".into());
        }
        _ => {}
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

    // Determine which index to remove
    let remove_idx = match (args.index, args.match_tuple) {
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

    let removed_rule = rules.remove(remove_idx);
    let rules_remaining = rules.len();

    // Re-validate after removal
    let validation = validate_lsrules::run(validate_lsrules::ValidateLsrulesArgs {
        path: None,
        inline_json: Some(doc.clone()),
    })
    .map_err(|e| format!("post-removal validation error: {e}"))?;

    if !validation.valid {
        let msgs: Vec<String> = validation
            .errors
            .iter()
            .map(|e| format!("  {}: {}", e.path, e.message))
            .collect();
        return Err(format!(
            "file would be invalid after removal:\n{}",
            msgs.join("\n")
        ));
    }

    // Serialize new content
    let new_json =
        serde_json::to_string_pretty(&doc).map_err(|e| format!("serialization error: {e}"))?;

    // Generate unified diff
    let diff = make_diff(&raw, &new_json, &format!("{}.lsrules", args.file_name));

    // Write back with mode 600
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

    Ok(RemoveRuleResult {
        file_name: args.file_name,
        removed_index: remove_idx,
        removed_rule,
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
    fn remove_by_index() {
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
            let result = run(RemoveRuleArgs {
                file_name: "rules".into(),
                index: Some(0),
                match_tuple: None,
            })
            .unwrap();
            assert_eq!(result.removed_index, 0);
            assert_eq!(result.removed_rule["action"], "allow");
            assert_eq!(result.rules_remaining, 1);
        });
    }

    #[test]
    fn remove_by_match_tuple() {
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
            let result = run(RemoveRuleArgs {
                file_name: "mtch".into(),
                index: None,
                match_tuple: Some(json!({"action": "deny", "process": "/usr/bin/curl"})),
            })
            .unwrap();
            assert_eq!(result.removed_rule["process"], "/usr/bin/curl");
            assert_eq!(result.rules_remaining, 1);
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
            let err = run(RemoveRuleArgs {
                file_name: "ambig".into(),
                index: None,
                match_tuple: Some(json!({"action": "deny"})),
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
            let err = run(RemoveRuleArgs {
                file_name: "nomatch".into(),
                index: None,
                match_tuple: Some(json!({"action": "deny"})),
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
            let err = run(RemoveRuleArgs {
                file_name: "range".into(),
                index: Some(5),
                match_tuple: None,
            })
            .unwrap_err();
            assert!(err.contains("out of range"), "unexpected: {err}");
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
            let result = run(RemoveRuleArgs {
                file_name: "difftest".into(),
                index: Some(0),
                match_tuple: None,
            })
            .unwrap();
            assert!(result.diff.contains("---"), "diff should have header");
            assert!(result.diff.contains('-'), "diff should have removed lines");
        });
    }

    #[test]
    fn missing_file_errors() {
        with_temp_dir(|| {
            let err = run(RemoveRuleArgs {
                file_name: "missing".into(),
                index: Some(0),
                match_tuple: None,
            })
            .unwrap_err();
            assert!(err.contains("not found"), "unexpected: {err}");
        });
    }
}
