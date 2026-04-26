use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

use crate::managed_dir::ManagedDir;

// ─── set_lsrules_metadata ───────────────────────────────────────────────────

/// Input for `set_lsrules_metadata`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetMetadataArgs {
    /// Name of the `.lsrules` file (without extension) in the managed rules directory.
    pub file_name: String,
    /// New value for the top-level `name` field. If omitted, the field is left unchanged.
    pub name: Option<String>,
    /// New value for the top-level `description` field.
    /// Pass `null` or omit to leave unchanged; pass `""` to clear the description.
    pub description: Option<String>,
}

/// Return value of `set_lsrules_metadata`.
#[derive(Debug, Serialize)]
pub struct SetMetadataResult {
    pub file_name: String,
    pub name: String,
    pub description: Option<String>,
    pub diff: String,
}

pub fn set_metadata(args: SetMetadataArgs) -> Result<SetMetadataResult, String> {
    validate_file_name(&args.file_name)?;
    if args.name.is_none() && args.description.is_none() {
        return Err("provide at least one of `name` or `description` to update".into());
    }

    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;
    let path = managed.lsrules_file(&args.file_name);

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let before = raw.clone();

    let mut doc: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;

    if let Some(new_name) = args.name {
        if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') {
            return Err(format!(
                "invalid name {:?}: must be a non-empty string with no path separators",
                new_name
            ));
        }
        doc["name"] = serde_json::Value::String(new_name);
    }
    if let Some(new_desc) = args.description {
        if new_desc.is_empty() {
            doc.as_object_mut().map(|m| m.remove("description"));
        } else {
            doc["description"] = serde_json::Value::String(new_desc);
        }
    }

    let after = serde_json::to_string_pretty(&doc)
        .map_err(|e| format!("cannot serialize updated document: {e}"))?
        + "\n";

    let diff = unified_diff(&before, &after, &args.file_name);

    // Write atomically via overwrite.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot open {} for writing: {e}", path.display()))?;
    file.write_all(after.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;

    let name = doc["name"].as_str().unwrap_or(&args.file_name).to_string();
    let description = doc["description"].as_str().map(str::to_string);

    Ok(SetMetadataResult {
        file_name: args.file_name,
        name,
        description,
        diff,
    })
}

// ─── diff_lsrules_files ─────────────────────────────────────────────────────

/// Input for `diff_lsrules_files`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffLsrulesArgs {
    /// Name of the first `.lsrules` file (without extension).
    pub file_a: String,
    /// Name of the second `.lsrules` file (without extension).
    pub file_b: String,
}

/// Return value of `diff_lsrules_files`.
#[derive(Debug, Serialize)]
pub struct DiffLsrulesResult {
    pub file_a: String,
    pub file_b: String,
    /// Unified diff between file_a and file_b. Empty string if files are identical.
    pub diff: String,
    pub identical: bool,
}

pub fn diff_files(args: DiffLsrulesArgs) -> Result<DiffLsrulesResult, String> {
    validate_file_name(&args.file_a)?;
    validate_file_name(&args.file_b)?;

    let managed =
        ManagedDir::bootstrap().map_err(|e| format!("cannot bootstrap managed directory: {e}"))?;

    let path_a = managed.lsrules_file(&args.file_a);
    let path_b = managed.lsrules_file(&args.file_b);

    let content_a = std::fs::read_to_string(&path_a)
        .map_err(|e| format!("cannot read {}: {e}", path_a.display()))?;
    let content_b = std::fs::read_to_string(&path_b)
        .map_err(|e| format!("cannot read {}: {e}", path_b.display()))?;

    let diff = unified_diff(
        &content_a,
        &content_b,
        &format!("{} → {}", args.file_a, args.file_b),
    );
    let identical = diff.is_empty();

    Ok(DiffLsrulesResult {
        file_a: args.file_a,
        file_b: args.file_b,
        diff,
        identical,
    })
}

// ─── shared helpers ──────────────────────────────────────────────────────────

fn validate_file_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(format!(
            "invalid file_name {:?}: must be a plain filename with no path separators",
            name
        ));
    }
    Ok(())
}

/// Produce a unified diff string between `old` and `new` labeled with `label`.
/// Returns an empty string when the contents are identical.
pub fn unified_diff(old: &str, new: &str, label: &str) -> String {
    if old == new {
        return String::new();
    }
    let diff = TextDiff::from_lines(old, new);
    let mut out = String::new();
    for change in diff.iter_all_changes() {
        let prefix = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        out.push_str(&format!("{prefix}{change}"));
    }
    format!("--- a/{label}\n+++ b/{label}\n{out}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_file_name_rejects_empty() {
        assert!(validate_file_name("").is_err());
    }

    #[test]
    fn validate_file_name_rejects_slash() {
        assert!(validate_file_name("dir/file").is_err());
        assert!(validate_file_name("dir\\file").is_err());
    }

    #[test]
    fn validate_file_name_accepts_plain() {
        assert!(validate_file_name("my-rules").is_ok());
        assert!(validate_file_name("MyRules123").is_ok());
    }

    #[test]
    fn unified_diff_identical_returns_empty() {
        let same = "line1\nline2\n";
        let diff = unified_diff(same, same, "test");
        assert_eq!(diff, "", "identical files should produce empty diff");
    }

    #[test]
    fn unified_diff_detects_change() {
        let old = "line1\nline2\n";
        let new = "line1\nline_changed\n";
        let diff = unified_diff(old, new, "test");
        assert!(diff.contains("-line2"), "diff should show removed line");
        assert!(
            diff.contains("+line_changed"),
            "diff should show added line"
        );
    }

    #[test]
    fn unified_diff_includes_label() {
        let diff = unified_diff("a\n", "b\n", "my-label");
        assert!(diff.contains("my-label"), "diff header must include label");
    }
}
