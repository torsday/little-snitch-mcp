//! Build-time enforcement of ADR-0004 §3: every CLI invocation of
//! `little-snitch restore-model` MUST include the `-t` Terminal-access
//! guard flag. There is no escape hatch.
//!
//! This test walks every `.rs` file under `src/`, finds non-comment
//! lines that mention `restore-model`, and fails the build if such a
//! line (combined with the surrounding window of source it belongs to)
//! has no accompanying `-t` flag.
//!
//! See `src/safety/cli.rs` for the rationale; see [#50] for the
//! original ticket.
//!
//! [#50]: https://github.com/torsday/little-snitch-mcp/issues/50

use std::fs;
use std::path::{Path, PathBuf};

const RESTORE_MODEL_LITERAL: &str = "restore-model";
const REQUIRED_FLAG: &str = "-t";
/// Number of lines forward from the `restore-model` mention to scan
/// for the `-t` flag. Argument lists are typically broken across a
/// handful of lines (one `.arg(...)` per line); 10 is a generous
/// upper bound that still keeps the test deterministic.
const WINDOW_AHEAD: usize = 10;

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src/").flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// True if this line is allowed to mention `restore-model` without `-t`
/// nearby. A line is exempt if:
/// - it is a single-line comment (leading `//` after trimming, or part
///   of a doc comment chain `///`/`//!`), or
/// - it is inside a documented allowlist context: a string of the
///   constant declaring the flag itself.
///
/// Note: we keep this conservative. Block comments (`/* ... */`) are
/// rare in the codebase; if they appear we accept the false positive
/// and force the author to either reorganise or extend this rule.
fn is_exempt_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

#[test]
fn every_restore_model_invocation_passes_the_terminal_guard_flag() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = PathBuf::from(manifest_dir).join("src");
    assert!(src.is_dir(), "src/ not found at {}", src.display());

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(!files.is_empty(), "no .rs files found under src/");

    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        let contents = fs::read_to_string(file).expect("read .rs file");
        let lines: Vec<&str> = contents.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains(RESTORE_MODEL_LITERAL) {
                continue;
            }
            if is_exempt_line(line) {
                continue;
            }
            // Don't flag the constant's own definition site.
            if file.ends_with("safety/cli.rs") {
                continue;
            }
            // Look in a small forward window for the -t flag.
            let end = (idx + WINDOW_AHEAD + 1).min(lines.len());
            let window = lines[idx..end].join("\n");
            if window.contains(REQUIRED_FLAG)
                || window.contains("RESTORE_MODEL_TERMINAL_GUARD_FLAG")
            {
                continue;
            }
            violations.push(format!(
                "{}:{}: `restore-model` without `-t` in the next {WINDOW_AHEAD} lines:\n  {}",
                file.strip_prefix(manifest_dir).unwrap_or(file).display(),
                idx + 1,
                line.trim_end(),
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "ADR-0004 §3 violation — `restore-model` invocations missing `-t` guard flag:\n\n{}\n\n\
         Use `safety::cli::RESTORE_MODEL_TERMINAL_GUARD_FLAG` and pass it adjacent to the \
         `\"restore-model\"` arg.",
        violations.join("\n"),
    );
}
