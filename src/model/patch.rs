//! Round-trip-preserving rule patch + canonical key-order serialization.
//!
//! The Track-B-surgery flow ([#60](https://github.com/torsday/little-snitch-mcp/issues/60),
//! [#62](https://github.com/torsday/little-snitch-mcp/issues/62)) edits a
//! single field of an existing rule and round-trips the result through
//! `restore-model -t`. **Every other field of the rule must survive
//! untouched** — including the seven LS-managed fields (`factory_id`,
//! `protected`, `last_used`, `use_count`, `approved`, `hidden`,
//! `factory_help_text`), the `extra` HashMap of forward-compat fields,
//! and the rule's `creation_date`. Smoke-3 confirmed LS preserves what
//! we send; the MCP must take care not to drop fields on its side.
//!
//! # The two pieces
//!
//! - [`RulePatch`] — every field optional. `apply_partial` overlays
//!   only the `Some(_)` fields onto an existing rule. The seven
//!   LS-managed fields are deliberately absent from `RulePatch` so
//!   they're unreachable from the patch path.
//! - [`canonical_json`] — recursively sort all object keys
//!   alphabetically. LS sorts on export; comparing an MCP-sent rule
//!   to LS's re-export requires both sides be canonical or the diff
//!   reports cosmetic-only changes as real ones.
//!
//! # `modification_date` discipline
//!
//! `apply_partial` always bumps `modification_date` to the supplied
//! "now", regardless of whether any field actually changed. Conservative
//! choice: a no-op patch is unusual enough that recording the touch is
//! worth more than the false-positive in mod-date diffs. The high-level
//! `update_rule_at` honors this.

use crate::model::Model;
use crate::model::rule::{Action, Direction, Priority, Rule, StringOrVec};
use serde_json::{Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Subset of [`Rule`] fields a patch may touch.
///
/// **Notably absent**: `creation_date`, `origin`, `uid`, the seven
/// LS-managed fields (`factory_id`, `factory_help_text`, `protected`,
/// `last_used`, `use_count`, `approved`, `hidden`, `owner`), and
/// `extra`. Those are unreachable from a patch — protected by type.
///
/// `modification_date` is also unreachable; `apply_partial` bumps it
/// to the supplied "now" automatically.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RulePatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_trusted_signature_for_any_process: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_domains: Option<StringOrVec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_hosts: Option<StringOrVec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addresses: Option<StringOrVec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Errors `update_rule_at` can return.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PatchError {
    #[error("INDEX_OUT_OF_RANGE: rule index {index} is out of range (model has {total} rules)")]
    IndexOutOfRange { index: usize, total: usize },
}

/// Overlay every `Some(_)` field of `patch` onto `rule`, then bump
/// `modification_date` to the supplied "now".
///
/// Caller-supplied `now_unix_secs` for testability — production code
/// passes `SystemTime::now()` via [`apply_partial`].
pub fn apply_partial_at(rule: &mut Rule, patch: RulePatch, now_unix_secs: u64) {
    if let Some(v) = patch.action {
        rule.action = v;
    }
    if let Some(v) = patch.process {
        rule.process = Some(v);
    }
    if let Some(v) = patch.requires_trusted_signature_for_any_process {
        rule.requires_trusted_signature_for_any_process = Some(v);
    }
    if let Some(v) = patch.remote {
        rule.remote = Some(v);
    }
    if let Some(v) = patch.remote_domains {
        rule.remote_domains = Some(v);
    }
    if let Some(v) = patch.remote_hosts {
        rule.remote_hosts = Some(v);
    }
    if let Some(v) = patch.remote_addresses {
        rule.remote_addresses = Some(v);
    }
    if let Some(v) = patch.direction {
        rule.direction = Some(v);
    }
    if let Some(v) = patch.priority {
        rule.priority = Some(v);
    }
    if let Some(v) = patch.protocol {
        rule.protocol = Some(v);
    }
    if let Some(v) = patch.ports {
        rule.ports = Some(v);
    }
    if let Some(v) = patch.via {
        rule.via = Some(v);
    }
    if let Some(v) = patch.notes {
        rule.notes = Some(v);
    }
    if let Some(v) = patch.group {
        rule.group = Some(v);
    }

    rule.modification_date = format_iso8601_utc(now_unix_secs);
}

/// Wrapper around [`apply_partial_at`] that sources "now" from the
/// system clock.
pub fn apply_partial(rule: &mut Rule, patch: RulePatch) {
    apply_partial_at(rule, patch, now_unix());
}

/// Apply `patch` to `model.rules[index]`, bumping `modification_date`,
/// and return the updated model. Original is consumed.
pub fn update_rule_at(
    mut model: Model,
    index: usize,
    patch: RulePatch,
    now_unix_secs: u64,
) -> Result<Model, PatchError> {
    let total = model.rules.len();
    if index >= total {
        return Err(PatchError::IndexOutOfRange { index, total });
    }
    apply_partial_at(&mut model.rules[index], patch, now_unix_secs);
    Ok(model)
}

/// Real-clock wrapper around [`update_rule_at`].
pub fn update_rule(model: Model, index: usize, patch: RulePatch) -> Result<Model, PatchError> {
    update_rule_at(model, index, patch, now_unix())
}

/// Recursively serialize `value` with all object keys sorted
/// alphabetically. Returns a [`serde_json::Value`] with the same
/// data but canonical key order.
///
/// LS's own `export-model` sorts keys alphabetically on output (smoke-3
/// finding). Diff comparisons MUST canonicalize both sides or cosmetic
/// reorderings register as real changes — leading to spurious "diff
/// drift" rejections at the confirmation-token verifier.
pub fn canonical_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // BTreeMap-backed sort, then rebuild with canonical children.
            let mut sorted: Map<String, Value> = Map::new();
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (k, v) in entries {
                sorted.insert(k, canonical_value(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonical_value).collect()),
        // Strings, numbers, bools, null pass through.
        other => other,
    }
}

/// Convenience: serialize a [`Rule`] to a canonical-key-order JSON
/// value. Equivalent to `canonical_value(serde_json::to_value(rule)?)`
/// with the serialization wrapped.
pub fn canonical_json(rule: &Rule) -> Result<Value, serde_json::Error> {
    let v = serde_json::to_value(rule)?;
    Ok(canonical_value(v))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Manual ISO 8601 UTC formatter — matches the project convention from
/// `model::rule_construct::format_iso8601_utc`. Inlined here rather than
/// extracted into a util module because the duplication is ~20 lines
/// and a util module would cross the model/safety boundary for one
/// helper.
fn format_iso8601_utc(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u8, u8) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u8, d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Origin;
    use std::collections::HashMap;

    /// Build a fixture rule with 14 fields populated — covers the
    /// AC-required "12+ field" preservation test.
    fn fixture_rule_with_many_fields() -> Rule {
        let mut extra = HashMap::new();
        extra.insert(
            "futureLsField".to_string(),
            Value::String("preserved-via-flatten".into()),
        );

        Rule {
            action: Action::Allow,
            creation_date: "2026-01-01T00:00:00Z".into(),
            modification_date: "2026-01-01T00:00:00Z".into(),
            origin: Origin::frontend(),
            uid: Some(501),

            process: Some("/usr/bin/curl".into()),
            requires_trusted_signature_for_any_process: None,
            remote: None,
            remote_domains: Some(StringOrVec::One("example.com".into())),
            remote_hosts: None,
            remote_addresses: None,
            direction: Some(Direction::Outgoing),
            priority: Some(Priority::High),
            protocol: Some("tcp".into()),
            ports: Some("443".into()),
            via: Some("en0".into()),
            notes: Some("operator note: keep this rule".into()),
            group: Some("aaaaa1".into()),

            // LS-managed fields — preserved verbatim through patches.
            factory_id: Some("ls-factory-007".into()),
            factory_help_text: Some("factory-installed help".into()),
            protected: Some(true),
            last_used: Some("2026-04-25T12:34:56Z".into()),
            use_count: Some(42),
            approved: Some(true),
            hidden: Some(false),
            owner: Some("system".into()),

            extra,
        }
    }

    const FIXED_NOW: u64 = 1_777_200_000; // 2026-04-26T10:40:00Z (deterministic)
    const FIXED_NOW_ISO: &str = "2026-04-26T10:40:00Z";

    // ---------- AC: preserve all fields when changing one ----------

    #[test]
    fn changing_only_action_preserves_every_other_field() {
        let original = fixture_rule_with_many_fields();
        let mut patched = original.clone();
        let patch = RulePatch {
            action: Some(Action::Deny),
            ..Default::default()
        };
        apply_partial_at(&mut patched, patch, FIXED_NOW);

        // The intentional change.
        assert_eq!(patched.action, Action::Deny);
        // The mandatory side effect.
        assert_eq!(patched.modification_date, FIXED_NOW_ISO);

        // Every other field byte-equal.
        assert_eq!(patched.creation_date, original.creation_date);
        assert_eq!(patched.origin, original.origin);
        assert_eq!(patched.uid, original.uid);
        assert_eq!(patched.process, original.process);
        assert_eq!(
            patched.requires_trusted_signature_for_any_process,
            original.requires_trusted_signature_for_any_process
        );
        assert_eq!(patched.remote_domains, original.remote_domains);
        assert_eq!(patched.direction, original.direction);
        assert_eq!(patched.priority, original.priority);
        assert_eq!(patched.protocol, original.protocol);
        assert_eq!(patched.ports, original.ports);
        assert_eq!(patched.via, original.via);
        assert_eq!(patched.notes, original.notes);
        assert_eq!(patched.group, original.group);

        // Critically: the seven LS-managed fields are preserved.
        assert_eq!(patched.factory_id, original.factory_id);
        assert_eq!(patched.factory_help_text, original.factory_help_text);
        assert_eq!(patched.protected, original.protected);
        assert_eq!(patched.last_used, original.last_used);
        assert_eq!(patched.use_count, original.use_count);
        assert_eq!(patched.approved, original.approved);
        assert_eq!(patched.hidden, original.hidden);
        assert_eq!(patched.owner, original.owner);

        // Forward-compat extras preserved.
        assert_eq!(patched.extra, original.extra);
    }

    #[test]
    fn custom_notes_round_trip_via_canonical_json() {
        let mut rule = fixture_rule_with_many_fields();
        let custom = "operator note containing 🔒 unicode + \"quotes\" + newlines\nLine 2";
        rule.notes = Some(custom.to_string());

        let canon = canonical_json(&rule).unwrap();
        let serialized = serde_json::to_string(&canon).unwrap();
        let reparsed: Rule = serde_json::from_str(&serialized).unwrap();

        assert_eq!(reparsed.notes.as_deref(), Some(custom));
    }

    #[test]
    fn patching_notes_only_preserves_action() {
        let mut rule = fixture_rule_with_many_fields();
        let patch = RulePatch {
            notes: Some("updated note".into()),
            ..Default::default()
        };
        apply_partial_at(&mut rule, patch, FIXED_NOW);
        assert_eq!(rule.notes.as_deref(), Some("updated note"));
        assert_eq!(rule.action, Action::Allow); // unchanged
    }

    #[test]
    fn empty_patch_only_bumps_modification_date() {
        let original = fixture_rule_with_many_fields();
        let mut patched = original.clone();
        apply_partial_at(&mut patched, RulePatch::default(), FIXED_NOW);

        assert_eq!(patched.modification_date, FIXED_NOW_ISO);
        assert_ne!(patched.modification_date, original.modification_date);

        // Reset mod date and confirm everything else is identical.
        patched.modification_date = original.modification_date.clone();
        assert_eq!(patched, original);
    }

    // ---------- LS-managed fields are unreachable from RulePatch ----------

    #[test]
    fn rule_patch_serde_round_trip_drops_unknown_keys() {
        // Caller can't slip an LS-managed field through by JSON-deserialize
        // — `factory_id` etc. are simply not on RulePatch and serde
        // ignores unknown keys (default behavior).
        let json = serde_json::json!({
            "action": "deny",
            "factoryID": "attempted-injection",
            "protected": true,
            "useCount": 999
        });
        let patch: RulePatch = serde_json::from_value(json).unwrap();
        assert_eq!(patch.action, Some(Action::Deny));
        // No way to get the others back — the type doesn't carry them.
    }

    // ---------- update_rule_at ----------

    fn empty_model_with_rules(rules: Vec<Rule>) -> Model {
        let mut m: Model = serde_json::from_value(serde_json::json!({
            "bundleVersion": 1,
            "factoryRuleSetVersion": 1,
            "rules": [],
            "groups": {},
            "profiles": {},
            "noProfilePseudoProfile": null,
            "globalDefaults": {},
            "users": [],
            "codeRequirements": {},
            "developerTeamNames": {},
            "lastSeenExecutableByCodeIdentifier": {},
            "networkTriggers": [],
            "blocklistStatistics": null,
            "disabledDomainsInLists": [],
            "disabledHostNamesInLists": [],
            "disabledIPAddressRangesInLists": []
        }))
        .unwrap();
        m.rules = rules;
        m
    }

    #[test]
    fn update_rule_at_with_valid_index_succeeds() {
        let model = empty_model_with_rules(vec![fixture_rule_with_many_fields()]);
        let patch = RulePatch {
            action: Some(Action::Deny),
            ..Default::default()
        };
        let updated = update_rule_at(model, 0, patch, FIXED_NOW).unwrap();
        assert_eq!(updated.rules[0].action, Action::Deny);
    }

    #[test]
    fn update_rule_at_with_out_of_range_index_returns_error() {
        let model = empty_model_with_rules(vec![fixture_rule_with_many_fields()]);
        let err = update_rule_at(model, 5, RulePatch::default(), FIXED_NOW).unwrap_err();
        match err {
            PatchError::IndexOutOfRange { index, total } => {
                assert_eq!(index, 5);
                assert_eq!(total, 1);
            }
        }
    }

    #[test]
    fn update_rule_at_does_not_touch_other_rules() {
        let mut a = fixture_rule_with_many_fields();
        a.notes = Some("rule A".into());
        let mut b = fixture_rule_with_many_fields();
        b.notes = Some("rule B".into());
        let model = empty_model_with_rules(vec![a, b]);

        let patch = RulePatch {
            action: Some(Action::Deny),
            ..Default::default()
        };
        let updated = update_rule_at(model, 0, patch, FIXED_NOW).unwrap();

        assert_eq!(updated.rules[0].action, Action::Deny);
        assert_eq!(updated.rules[1].action, Action::Allow);
        assert_eq!(updated.rules[1].notes.as_deref(), Some("rule B"));
        // rule B's modification_date is untouched.
        assert_ne!(updated.rules[1].modification_date, FIXED_NOW_ISO);
    }

    // ---------- canonicalization ----------

    #[test]
    fn canonical_value_sorts_object_keys_alphabetically() {
        let v = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3,
        });
        let canon = canonical_value(v);
        let serialized = serde_json::to_string(&canon).unwrap();
        // serde_json::Map preserves insertion order, so this string
        // captures the actual key order after canonicalization.
        assert_eq!(serialized, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_value_recurses_into_nested_objects() {
        let v = serde_json::json!({
            "outer_z": { "inner_z": 1, "inner_a": 2 },
            "outer_a": "x",
        });
        let canon = canonical_value(v);
        let serialized = serde_json::to_string(&canon).unwrap();
        assert_eq!(
            serialized,
            r#"{"outer_a":"x","outer_z":{"inner_a":2,"inner_z":1}}"#
        );
    }

    #[test]
    fn canonical_value_recurses_into_arrays_of_objects() {
        let v = serde_json::json!([
            {"z": 1, "a": 2},
            {"y": 3, "b": 4},
        ]);
        let canon = canonical_value(v);
        let serialized = serde_json::to_string(&canon).unwrap();
        assert_eq!(serialized, r#"[{"a":2,"z":1},{"b":4,"y":3}]"#);
    }

    #[test]
    fn canonical_value_passes_scalars_through() {
        for s in ["null", "true", "42", r#""hello""#] {
            let v: Value = serde_json::from_str(s).unwrap();
            assert_eq!(canonical_value(v.clone()), v);
        }
    }

    #[test]
    fn canonical_json_of_rule_has_alphabetical_top_level_keys() {
        let rule = fixture_rule_with_many_fields();
        let canon = canonical_json(&rule).unwrap();
        let obj = canon.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "top-level keys must be alphabetical");
    }

    #[test]
    fn canonical_json_round_trips_through_string_serialization() {
        // The whole point of canonicalization is that a → string → parse → canon == canon.
        let rule = fixture_rule_with_many_fields();
        let canon_a = canonical_json(&rule).unwrap();
        let serialized = serde_json::to_string(&canon_a).unwrap();
        let reparsed: Value = serde_json::from_str(&serialized).unwrap();
        let canon_b = canonical_value(reparsed);
        assert_eq!(canon_a, canon_b);
    }

    #[test]
    fn two_rules_differing_only_by_field_order_canonicalize_identically() {
        // Construct two JSON values with the same content but different
        // key insertion order; canonicalization makes them equal.
        let a: Value = serde_json::from_str(r#"{"action":"allow","process":"x"}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"process":"x","action":"allow"}"#).unwrap();
        assert_eq!(canonical_value(a), canonical_value(b));
    }

    #[test]
    fn extra_fields_via_flatten_appear_in_canonical_output_at_top_level() {
        // A flattened HashMap field should land at the top level of the
        // serialized rule, and canonical_json should sort it among the
        // other top-level keys.
        let mut rule = fixture_rule_with_many_fields();
        rule.extra
            .insert("zzzFutureField".to_string(), Value::String("z".into()));
        rule.extra
            .insert("aaaFutureField".to_string(), Value::String("a".into()));

        let canon = canonical_json(&rule).unwrap();
        let obj = canon.as_object().unwrap();
        assert!(obj.contains_key("aaaFutureField"));
        assert!(obj.contains_key("zzzFutureField"));

        let keys: Vec<&String> = obj.keys().collect();
        let aaa_pos = keys
            .iter()
            .position(|k| k.as_str() == "aaaFutureField")
            .unwrap();
        let zzz_pos = keys
            .iter()
            .position(|k| k.as_str() == "zzzFutureField")
            .unwrap();
        assert!(aaa_pos < zzz_pos, "alphabetical order must be respected");
    }

    // ---------- iso8601 helper edge cases ----------

    #[test]
    fn iso8601_unix_epoch_is_1970_01_01() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_fixed_now_renders_correctly() {
        assert_eq!(format_iso8601_utc(FIXED_NOW), FIXED_NOW_ISO);
    }
}
