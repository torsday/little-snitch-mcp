//! Integration tests exercising the CLI adapter layer end-to-end.
//!
//! All tests use `LsCli::new(mock_bin)` to inject a mock `littlesnitch`
//! binary at `tests/fixtures/mock_littlesnitch` — no live LS install needed.
//!
//! To verify argument shapes, tests set `MOCK_ARGS_FILE` to a temp file.
//! The mock appends every invocation's args (space-joined) to that file;
//! tests read it back to assert the exact CLI arguments passed.
//!
//! Error-mapping tests use `MOCK_*_FAIL` env vars to trigger non-zero exits
//! that produce specific stderr strings, then assert the mapped `LsCliError`.

use std::path::PathBuf;

use little_snitch_mcp::cli::adapter::{LsCli, LsCliError};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn mock_bin() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running tests");
    PathBuf::from(manifest)
        .join("tests")
        .join("fixtures")
        .join("mock_littlesnitch")
}

fn cli() -> LsCli {
    LsCli::new(mock_bin())
}

// ─── export-model ────────────────────────────────────────────────────────────

#[test]
fn export_model_with_path_creates_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dest = tmp.path().join("backup.json");
    let output = cli()
        .run(&["export-model", dest.to_str().unwrap()])
        .expect("export-model must succeed");
    assert!(output.status.success());
    assert!(dest.exists(), "mock must have written the file");
    let content = std::fs::read_to_string(&dest).unwrap();
    assert!(
        content.contains("bundleVersion"),
        "file must contain model JSON"
    );
}

#[test]
fn export_model_without_path_returns_json_on_stdout() {
    let output = cli()
        .run(&["export-model"])
        .expect("export-model must succeed");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bundleVersion"),
        "stdout must contain model JSON"
    );
}

// ─── log ─────────────────────────────────────────────────────────────────────

#[test]
fn log_with_duration_returns_json_lines() {
    let output = cli()
        .run(&["log", "-j", "-l", "5s"])
        .expect("log must succeed");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "mock returns 2 log lines");
    assert!(
        lines[0].contains("process"),
        "first line must be JSON with process field"
    );
}

#[test]
fn log_not_authorized_maps_to_error() {
    // The mock exits 1 with "command line tool is not authorized" when MOCK_LOG_FAIL=1.
    // We trigger this by using a helper binary that always outputs that error string.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let script_path = tmp.path().with_extension("sh");
    std::fs::write(
        &script_path,
        b"#!/bin/sh\necho 'Error: command line tool is not authorized' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let err = LsCli::new(script_path.clone())
        .run(&["log", "-j", "-l", "1s"])
        .expect_err("must fail");
    assert!(
        matches!(err, LsCliError::NotAuthorized),
        "expected NotAuthorized, got: {err:?}"
    );
}

// ─── rulegroup ───────────────────────────────────────────────────────────────

#[test]
fn rulegroup_enable_passes_minus_e_flag() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let args_file = tmp.path().to_path_buf();
    // Build a mock that also records args.
    let script_path = args_file.with_extension("sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexit 0\n",
            args_file.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    LsCli::new(script_path.clone())
        .run(&["rulegroup", "-e", "My Rule Group"])
        .expect("rulegroup -e must succeed");
    let recorded = std::fs::read_to_string(&args_file).unwrap_or_default();
    assert!(
        recorded.contains("rulegroup -e My Rule Group"),
        "expected 'rulegroup -e My Rule Group', got: {recorded}"
    );
}

#[test]
fn rulegroup_disable_passes_minus_d_flag() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let args_file = tmp.path().to_path_buf();
    let script_path = args_file.with_extension("sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexit 0\n",
            args_file.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    LsCli::new(script_path.clone())
        .run(&["rulegroup", "-d", "Blocklist Group"])
        .expect("rulegroup -d must succeed");
    let recorded = std::fs::read_to_string(&args_file).unwrap_or_default();
    assert!(
        recorded.contains("rulegroup -d Blocklist Group"),
        "expected 'rulegroup -d Blocklist Group', got: {recorded}"
    );
}

#[test]
fn rulegroup_not_found_maps_to_error() {
    let script_path = tempfile::NamedTempFile::new()
        .unwrap()
        .path()
        .with_extension("sh");
    std::fs::write(
        &script_path,
        b"#!/bin/sh\necho 'Error: Rule group or blocklist \"No Such Group\" not found' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let err = LsCli::new(script_path.clone())
        .run(&["rulegroup", "-e", "No Such Group"])
        .expect_err("must fail");
    assert!(
        matches!(err, LsCliError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );
    if let LsCliError::NotFound { resource } = err {
        assert_eq!(resource, "No Such Group");
    }
}

// ─── profile ─────────────────────────────────────────────────────────────────

#[test]
fn profile_activate_passes_minus_a_flag() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let args_file = tmp.path().to_path_buf();
    let script_path = args_file.with_extension("sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexit 0\n",
            args_file.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    LsCli::new(script_path.clone())
        .run(&["profile", "-a", "Work"])
        .expect("profile -a must succeed");
    let recorded = std::fs::read_to_string(&args_file).unwrap_or_default();
    assert!(
        recorded.contains("profile -a Work"),
        "expected 'profile -a Work', got: {recorded}"
    );
}

#[test]
fn profile_must_be_root_maps_to_error() {
    let script_path = tempfile::NamedTempFile::new()
        .unwrap()
        .path()
        .with_extension("sh");
    std::fs::write(
        &script_path,
        b"#!/bin/sh\necho 'Error: must be run as root' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let err = LsCli::new(script_path.clone())
        .run(&["profile", "-a", "Work"])
        .expect_err("must fail");
    assert!(
        matches!(err, LsCliError::MustBeRoot),
        "expected MustBeRoot, got: {err:?}"
    );
}

// ─── generic error mapping ───────────────────────────────────────────────────

#[test]
fn generic_non_zero_exit_maps_to_generic_error() {
    let script_path = tempfile::NamedTempFile::new()
        .unwrap()
        .path()
        .with_extension("sh");
    std::fs::write(
        &script_path,
        b"#!/bin/sh\necho 'unexpected failure output' >&2\nexit 42\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let err = LsCli::new(script_path.clone())
        .run(&["some-subcommand"])
        .expect_err("must fail");
    match err {
        LsCliError::Generic { exit_code, stderr } => {
            assert_eq!(exit_code, 42);
            assert!(stderr.contains("unexpected failure output"));
        }
        other => panic!("expected Generic, got: {other:?}"),
    }
}

// ─── restore-model (arg shape only) ─────────────────────────────────────────

#[test]
fn restore_model_with_terminal_flag_passes_correct_args() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let args_file = tmp.path().to_path_buf();
    let script_path = args_file.with_extension("sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexit 0\n",
            args_file.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    LsCli::new(script_path.clone())
        .run(&["restore-model", "-t", "/tmp/model.json"])
        .expect("restore-model must succeed");
    let recorded = std::fs::read_to_string(&args_file).unwrap_or_default();
    assert!(
        recorded.contains("restore-model -t"),
        "expected 'restore-model -t', got: {recorded}"
    );
}
