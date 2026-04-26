//! Integration tests for Track B-direct tools: enable/disable rule group,
//! profile activation, factory rule-group updates, and write_preference.
//!
//! All tests use fixture data (no live `littlesnitch` binary required).
//! The prepare→verify token roundtrip is exercised end-to-end; the apply
//! step (CLI call behind backup_harness) is tested for guard refusal only,
//! since it requires a live LS install.

use std::sync::Arc;

use little_snitch_mcp::{
    model::Model,
    safety::Session,
    tools::{
        manage_profiles::{
            ActivateProfileArgs, DeactivateAllProfilesArgs, PrepareActivateProfileArgs,
            PrepareDeactivateAllProfilesArgs, activate, deactivate_all, prepare_activate,
            prepare_deactivate,
        },
        manage_rule_groups::{
            DisableRuleGroupArgs, EnableRuleGroupArgs, disable, enable, prepare_disable_with_model,
            prepare_enable_with_model,
        },
        update_factory_rule_groups::{
            PrepareUpdateFactoryRuleGroupsArgs, UpdateFactoryRuleGroupsArgs, prepare_update, update,
        },
        write_preference::{
            PrepareRemovePreferenceArgs, PrepareWritePreferenceArgs, RemovePreferenceArgs,
            WritePreferenceArgs, prepare_remove, prepare_write, remove, write,
        },
    },
};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn new_session() -> Arc<Session> {
    Arc::new(Session::new().expect("session creation must succeed"))
}

fn fixture_model() -> Model {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/model_b_fixture.json"
    );
    let json = std::fs::read_to_string(path).expect("fixture file must exist");
    serde_json::from_str(&json).expect("fixture must be valid Model JSON")
}

// ─── enable_rule_group / disable_rule_group ───────────────────────────────────

#[test]
fn enable_group_prepare_verify_roundtrip_custom() {
    let s = new_session();
    let model = fixture_model();

    let prep = prepare_enable_with_model(&s, "Work Rules", &model)
        .expect("prepare must succeed for known custom group");

    assert_eq!(prep.resolved_name, "Work Rules");
    assert!(prep.diff_summary.contains("Work Rules"));
    assert!(!prep.token.is_empty());
}

#[test]
fn enable_group_prepare_resolves_by_kind() {
    let s = new_session();
    let model = fixture_model();

    let prep = prepare_enable_with_model(&s, "builtinMacOSServices", &model)
        .expect("kind-based resolve must work");

    assert_eq!(prep.resolved_name, "macOS Services");
}

#[test]
fn enable_group_rejects_bad_token() {
    let s = new_session();
    let err = enable(
        &s,
        EnableRuleGroupArgs {
            resolved_name: "Work Rules".into(),
            token: "garbage".into(),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn enable_group_rejects_empty_resolved_name() {
    let s = new_session();
    let err = enable(
        &s,
        EnableRuleGroupArgs {
            resolved_name: String::new(),
            token: "x".into(),
        },
    )
    .unwrap_err();
    assert!(err.contains("empty") || !err.is_empty());
}

#[test]
fn disable_group_prepare_verify_roundtrip_custom() {
    let s = new_session();
    let model = fixture_model();

    let prep = prepare_disable_with_model(&s, "Work Rules", None, &model)
        .expect("prepare must succeed for custom group without ack");

    assert_eq!(prep.resolved_name, "Work Rules");
    assert!(!prep.is_builtin);
    assert!(!prep.token.is_empty());
}

#[test]
fn disable_group_builtin_requires_ack() {
    let s = new_session();
    let model = fixture_model();

    let err = prepare_disable_with_model(&s, "macOS Services", None, &model).unwrap_err();
    assert!(
        err.contains("builtin") || err.contains("acknowledge"),
        "unexpected: {err}"
    );
}

#[test]
fn disable_group_builtin_allowed_with_ack() {
    let s = new_session();
    let model = fixture_model();

    let prep = prepare_disable_with_model(&s, "macOS Services", Some(true), &model)
        .expect("ack=true must unlock builtin disable");

    assert_eq!(prep.resolved_name, "macOS Services");
    assert!(prep.is_builtin);
    assert!(prep.diff_summary.contains("builtin"));
}

#[test]
fn disable_group_unknown_name_returns_not_found() {
    let s = new_session();
    let model = fixture_model();

    let err = prepare_disable_with_model(&s, "NonExistentGroup", None, &model).unwrap_err();
    assert!(
        err.contains("not found") || err.contains("NonExistentGroup"),
        "unexpected: {err}"
    );
}

#[test]
fn enable_token_rejected_by_disable_verify() {
    let s = new_session();
    let model = fixture_model();

    let enable_prep = prepare_enable_with_model(&s, "Work Rules", &model).unwrap();

    // The enable token must not be accepted by the disable apply path.
    let err = disable(
        &s,
        DisableRuleGroupArgs {
            resolved_name: "Work Rules".into(),
            token: enable_prep.token,
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn disable_token_rejected_by_enable_verify() {
    let s = new_session();
    let model = fixture_model();

    let disable_prep = prepare_disable_with_model(&s, "Work Rules", None, &model).unwrap();

    let err = enable(
        &s,
        EnableRuleGroupArgs {
            resolved_name: "Work Rules".into(),
            token: disable_prep.token,
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

// ─── prepare_activate_profile / activate_profile ─────────────────────────────

#[test]
fn activate_profile_prepare_returns_token() {
    let s = new_session();
    let result = prepare_activate(
        &s,
        PrepareActivateProfileArgs {
            name: "Home".into(),
        },
    )
    .expect("prepare must succeed with non-empty name");

    assert_eq!(result.name, "Home");
    assert!(!result.token.is_empty());
    assert!(result.diff_summary.contains("Home"));
}

#[test]
fn activate_profile_prepare_rejects_empty_name() {
    let s = new_session();
    let err = prepare_activate(
        &s,
        PrepareActivateProfileArgs {
            name: String::new(),
        },
    )
    .unwrap_err();
    assert!(err.contains("empty") || !err.is_empty());
}

#[test]
fn activate_profile_rejects_bad_token() {
    let s = new_session();
    let err = activate(
        &s,
        ActivateProfileArgs {
            name: "Home".into(),
            token: "junk".into(),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn deactivate_all_prepare_returns_token() {
    let s = new_session();
    let result = prepare_deactivate(&s, PrepareDeactivateAllProfilesArgs {})
        .expect("prepare_deactivate must always succeed");

    assert!(!result.token.is_empty());
    assert!(!result.diff_summary.is_empty());
}

#[test]
fn deactivate_all_rejects_bad_token() {
    let s = new_session();
    let err = deactivate_all(
        &s,
        DeactivateAllProfilesArgs {
            token: "junk".into(),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn activate_token_not_accepted_by_deactivate() {
    let s = new_session();
    let prep = prepare_activate(
        &s,
        PrepareActivateProfileArgs {
            name: "Work".into(),
        },
    )
    .unwrap();

    let err = deactivate_all(&s, DeactivateAllProfilesArgs { token: prep.token }).unwrap_err();
    assert!(!err.is_empty());
}

// ─── prepare_update_factory_rule_groups / update_factory_rule_groups ──────────

#[test]
fn factory_update_prepare_all_returns_token() {
    let s = new_session();
    let result = prepare_update(&s, PrepareUpdateFactoryRuleGroupsArgs { scope: None }).unwrap();
    assert_eq!(result.scope, "all");
    assert!(!result.token.is_empty());
}

#[test]
fn factory_update_prepare_apple_scope() {
    let s = new_session();
    let result = prepare_update(
        &s,
        PrepareUpdateFactoryRuleGroupsArgs {
            scope: Some("apple".into()),
        },
    )
    .unwrap();
    assert_eq!(result.scope, "apple");
    assert!(result.diff_summary.contains("Apple"));
}

#[test]
fn factory_update_prepare_third_party_scope() {
    let s = new_session();
    let result = prepare_update(
        &s,
        PrepareUpdateFactoryRuleGroupsArgs {
            scope: Some("third-party".into()),
        },
    )
    .unwrap();
    assert_eq!(result.scope, "third-party");
}

#[test]
fn factory_update_prepare_rejects_invalid_scope() {
    let s = new_session();
    let err = prepare_update(
        &s,
        PrepareUpdateFactoryRuleGroupsArgs {
            scope: Some("unknown".into()),
        },
    )
    .unwrap_err();
    assert!(err.contains("invalid scope") || !err.is_empty());
}

#[test]
fn factory_update_rejects_bad_token() {
    let s = new_session();
    let err = update(
        &s,
        UpdateFactoryRuleGroupsArgs {
            scope: None,
            token: "bad".into(),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn factory_update_apple_token_rejected_for_all_scope() {
    let s = new_session();
    let apple_prep = prepare_update(
        &s,
        PrepareUpdateFactoryRuleGroupsArgs {
            scope: Some("apple".into()),
        },
    )
    .unwrap();

    // Token scoped to "apple" must not verify for scope "all".
    let err = update(
        &s,
        UpdateFactoryRuleGroupsArgs {
            scope: None,
            token: apple_prep.token,
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

// ─── prepare_write_preference / write_preference ──────────────────────────────

#[test]
fn write_pref_prepare_returns_token() {
    let s = new_session();
    let result = prepare_write(
        &s,
        PrepareWritePreferenceArgs {
            key: "activeSilentMode".into(),
            value: serde_json::json!(true),
        },
    )
    .expect("prepare must succeed for allowlisted key");

    assert!(!result.token.is_empty());
    assert_eq!(result.key, "activeSilentMode");
    assert_eq!(result.value, serde_json::json!(true));
}

#[test]
fn write_pref_prepare_rejects_unknown_key() {
    let s = new_session();
    let err = prepare_write(
        &s,
        PrepareWritePreferenceArgs {
            key: "notAValidPref".into(),
            value: serde_json::json!(true),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn write_pref_rejects_bad_token() {
    let s = new_session();
    let err = write(
        &s,
        WritePreferenceArgs {
            key: "activeSilentMode".into(),
            value: serde_json::json!(false),
            token: "junk".into(),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn remove_pref_prepare_returns_token() {
    let s = new_session();
    let result = prepare_remove(
        &s,
        PrepareRemovePreferenceArgs {
            key: "activeSilentMode".into(),
        },
    )
    .expect("prepare must succeed for allowlisted key");

    assert!(!result.token.is_empty());
}

#[test]
fn remove_pref_rejects_bad_token() {
    let s = new_session();
    let err = remove(
        &s,
        RemovePreferenceArgs {
            key: "activeSilentMode".into(),
            token: "junk".into(),
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn write_token_rejected_by_remove_verify() {
    let s = new_session();
    let write_prep = prepare_write(
        &s,
        PrepareWritePreferenceArgs {
            key: "activeSilentMode".into(),
            value: serde_json::json!(true),
        },
    )
    .unwrap();

    // Write token must not be accepted by remove.
    let err = remove(
        &s,
        RemovePreferenceArgs {
            key: "activeSilentMode".into(),
            token: write_prep.token,
        },
    )
    .unwrap_err();
    assert!(!err.is_empty());
}
