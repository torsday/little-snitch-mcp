//! Integration tests for the full Track A authoring flow:
//! create → add → update → remove, with idempotency and reversibility checks.
//!
//! All tests operate in a temp managed directory and never touch user state.

use little_snitch_mcp::managed_dir::{ENV_LOCK, ENV_MANAGED_DIR};
use little_snitch_mcp::tools::{
    add_rule_to_lsrules_file::{self, AddRuleArgs},
    create_lsrules_file::{self, CreateLsrulesArgs},
    remove_rule_from_lsrules_file::{self, RemoveRuleArgs},
    update_rule_in_lsrules_file::{self, UpdateRuleArgs},
    validate_lsrules::{self, ValidateLsrulesArgs},
};
use serde_json::json;

/// Run `f` inside a fresh temp managed directory, serialized so tests
/// can't race on `LSMCP_MANAGED_DIR`.
fn with_temp_managed<F: FnOnce()>(f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let td = tempfile::tempdir().unwrap();
    // SAFETY: protected by ENV_LOCK.
    unsafe {
        std::env::set_var(ENV_MANAGED_DIR, td.path().join("mcp"));
    }
    f();
    unsafe {
        std::env::remove_var(ENV_MANAGED_DIR);
    }
}

/// Full CRUD cycle: create → add 3 rules → update one → remove another.
#[test]
fn full_crud_cycle_produces_expected_final_state() {
    with_temp_managed(|| {
        // 1. Create the file.
        let create = create_lsrules_file::run(CreateLsrulesArgs {
            name: "cycle".into(),
            description: Some("integration test".into()),
            denied_remote_domains: None,
            rules: None,
            replace: None,
        })
        .expect("create should succeed");
        assert_eq!(create.name, "cycle");

        // 2. Add three rules.
        let r1 = json!({"action": "allow", "process": "any", "remote": "any"});
        let r2 = json!({"action": "deny", "process": "/usr/bin/curl", "remote": "any"});
        let r3 = json!({"action": "allow", "process": "/usr/bin/ssh", "remote": "any"});

        for rule in [r1.clone(), r2.clone(), r3.clone()] {
            let res = add_rule_to_lsrules_file::run(AddRuleArgs {
                file_name: "cycle".into(),
                rule,
            })
            .expect("add should succeed");
            assert!(!res.already_present);
        }

        // 3. Update r2: flip action to allow.
        let upd = update_rule_in_lsrules_file::run(UpdateRuleArgs {
            file_name: "cycle".into(),
            index: None,
            match_tuple: Some(json!({"process": "/usr/bin/curl"})),
            updates: json!({"action": "allow"}),
        })
        .expect("update should succeed");
        assert_eq!(upd.rule_before["action"], "deny");
        assert_eq!(upd.rule_after["action"], "allow");

        // 4. Remove r3 by match_tuple.
        let rem = remove_rule_from_lsrules_file::run(RemoveRuleArgs {
            file_name: "cycle".into(),
            index: None,
            match_tuple: Some(json!({"process": "/usr/bin/ssh", "action": "allow"})),
        })
        .expect("remove should succeed");
        assert_eq!(rem.removed_rule["process"], "/usr/bin/ssh");
        assert_eq!(rem.rules_remaining, 2);

        // 5. Final file is schema-valid.
        let val = validate_lsrules::run(ValidateLsrulesArgs {
            path: Some(
                little_snitch_mcp::managed_dir::ManagedDir::bootstrap()
                    .unwrap()
                    .lsrules_file("cycle")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ),
            inline_json: None,
        })
        .expect("validate should not error");
        assert!(
            val.valid,
            "final file must be schema-valid: {:?}",
            val.errors
        );
    });
}

/// Adding the same rule twice is idempotent: second add returns already_present.
#[test]
fn add_is_idempotent() {
    with_temp_managed(|| {
        create_lsrules_file::run(CreateLsrulesArgs {
            name: "idem".into(),
            description: None,
            denied_remote_domains: None,
            rules: None,
            replace: None,
        })
        .unwrap();

        let rule = json!({"action": "allow", "process": "any", "remote": "any"});

        let first = add_rule_to_lsrules_file::run(AddRuleArgs {
            file_name: "idem".into(),
            rule: rule.clone(),
        })
        .unwrap();
        assert!(!first.already_present);
        assert_eq!(first.rules_total, 1);

        let second = add_rule_to_lsrules_file::run(AddRuleArgs {
            file_name: "idem".into(),
            rule,
        })
        .unwrap();
        assert!(second.already_present, "second add must be a no-op");
        assert_eq!(second.rules_total, 1, "rule count must not change");
        assert!(second.diff.is_empty(), "no diff for a no-op add");
    });
}

/// After removing the last rule, the file remains valid (empty rules array).
#[test]
fn remove_last_rule_leaves_valid_empty_file() {
    with_temp_managed(|| {
        create_lsrules_file::run(CreateLsrulesArgs {
            name: "last".into(),
            description: None,
            denied_remote_domains: None,
            rules: Some(vec![
                json!({"action": "allow", "process": "any", "remote": "any"}),
            ]),
            replace: None,
        })
        .unwrap();

        let rem = remove_rule_from_lsrules_file::run(RemoveRuleArgs {
            file_name: "last".into(),
            index: Some(0),
            match_tuple: None,
        })
        .unwrap();
        assert_eq!(rem.rules_remaining, 0);

        let val = validate_lsrules::run(ValidateLsrulesArgs {
            path: Some(
                little_snitch_mcp::managed_dir::ManagedDir::bootstrap()
                    .unwrap()
                    .lsrules_file("last")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ),
            inline_json: None,
        })
        .unwrap();
        assert!(val.valid, "empty-rules file must still be schema-valid");
    });
}

/// Remove on an already-removed rule (by index, out of range) returns an error.
#[test]
fn remove_after_removal_errors_gracefully() {
    with_temp_managed(|| {
        create_lsrules_file::run(CreateLsrulesArgs {
            name: "gone".into(),
            description: None,
            denied_remote_domains: None,
            rules: Some(vec![
                json!({"action": "allow", "process": "any", "remote": "any"}),
            ]),
            replace: None,
        })
        .unwrap();

        // Remove the only rule.
        remove_rule_from_lsrules_file::run(RemoveRuleArgs {
            file_name: "gone".into(),
            index: Some(0),
            match_tuple: None,
        })
        .unwrap();

        // Attempt to remove index 0 again — now out of range.
        let err = remove_rule_from_lsrules_file::run(RemoveRuleArgs {
            file_name: "gone".into(),
            index: Some(0),
            match_tuple: None,
        })
        .unwrap_err();
        assert!(err.contains("out of range"), "unexpected: {err}");
    });
}
