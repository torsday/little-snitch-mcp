//! Group-name resolver chain.
//!
//! `little-snitch rulegroup -e/-d` accepts only the localized display
//! name (smoke-1, [docs/feasibility-report.md](../../../docs/feasibility-report.md)).
//! The MCP must accept whatever shape the LLM gives it (display name,
//! `kind`, group ID) and resolve it to the display name LS will accept,
//! **without** silently rewriting the input in a way that hides
//! ambiguity.
//!
//! See [docs/spikes/2026-04-group-name-resolver.md](../../../docs/spikes/2026-04-group-name-resolver.md)
//! for the design rationale (notably: fuzzy matching is intentionally
//! *not* part of the chain — converting an LLM typo into a silent
//! mutation of a different group is exactly what the safety chain
//! exists to prevent).
//!
//! # Result variants
//!
//! - [`ResolveResult::Verified`] — the chain matched a known mapping.
//!   `live_write` callers may proceed with the contained display name.
//! - [`ResolveResult::BestEffort`] — the chain didn't match anything,
//!   but we have no candidates to suggest (model has no named groups).
//!   Callers must escalate to `live_write_strong` ack and forward the
//!   string verbatim.
//! - [`ResolveResult::NotFound`] — the chain didn't match anything
//!   *and* the model has named groups the user could have meant.
//!   Callers should refuse and surface the candidates so the LLM can
//!   re-select.

use crate::model::Model;
use std::collections::BTreeSet;

/// Outcome of a single resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveResult {
    /// Input mapped to a known display name with high confidence.
    /// Carries the exact string to pass to `rulegroup -e/-d`.
    Verified(String),
    /// Input did not match anything in the chain, but the model has
    /// no named groups to suggest as alternatives. Callers must
    /// escalate to `live_write_strong` ack and forward the input
    /// verbatim if the operator confirms intent.
    BestEffort(String),
    /// Input did not match anything in the chain *and* the model has
    /// named groups the user could have meant. Callers should refuse
    /// and present `candidates` so the LLM can re-select.
    NotFound { candidates: Vec<String> },
}

/// Static `kind → display name` map for builtin subscriptions.
///
/// Empirically grounded against smoke-1 outcomes. Grows as we
/// encounter more `kind` values during dogfooding. Locale assumption:
/// display names are localized by LS; the seed table targets `en_US`.
/// Non-`en_US` users will hit the [`ResolveResult::BestEffort`] path
/// for builtin groups until the table widens.
pub const SEED_KIND_MAP: &[(&str, &str)] = &[
    ("builtinMacOSServices", "macOS Services"),
    ("builtinICloudServices", "iCloud Services"),
];

/// Resolve `input` against `model.groups` per the spike-#4 chain:
///
/// 1. Exact match against any `groups[*].name` (non-null) — `Verified`.
/// 2. Match `groups[*].kind` (or legacy `type`) → look up display name
///    in [`SEED_KIND_MAP`] — `Verified`.
/// 3. Match `groups[*].id` (the HashMap key) → recurse through 1–2
///    against the located entry — `Verified`.
/// 4. Otherwise: `NotFound { candidates }` if the model has named
///    groups; `BestEffort(input.to_string())` if not.
///
/// When the resolver encounters a `kind` that's in the model but not
/// in [`SEED_KIND_MAP`], it logs a structured `unknown_kind_warning`
/// at `tracing::warn` for `doctor` to surface. This is not a refusal —
/// the chain proceeds to step 4 — but the operator gets visibility
/// into seed-table coverage gaps.
pub fn resolve_group(input: &str, model: &Model) -> ResolveResult {
    // Step 1: exact match against any group's `name` field.
    for g in model.groups.values() {
        if g.name.as_deref() == Some(input) {
            return ResolveResult::Verified(input.to_string());
        }
    }

    // Step 2: input is a `kind` value (canonical or legacy alias)
    // present in some group. The display name comes from SEED_KIND_MAP.
    for g in model.groups.values() {
        let group_kind = g.kind.as_deref().or(g.kind_legacy.as_deref());
        if group_kind == Some(input) {
            if let Some(display) = lookup_seed(input) {
                return ResolveResult::Verified(display.to_string());
            }
            warn_unknown_kind(input, model);
            // Fall through to step 4 — we know the kind exists in the
            // model but we don't have a display name for it.
            break;
        }
    }

    // Step 3: input is a group ID (the HashMap key).
    if let Some(g) = model.groups.get(input) {
        if let Some(display_name) = g.name.as_deref() {
            return ResolveResult::Verified(display_name.to_string());
        }
        if let Some(k) = g.kind.as_deref().or(g.kind_legacy.as_deref()) {
            if let Some(display) = lookup_seed(k) {
                return ResolveResult::Verified(display.to_string());
            }
            warn_unknown_kind(k, model);
            // Group exists but has neither a name nor a known kind —
            // fall through to step 4.
        }
    }

    // Step 4: nothing matched. Surface candidates if any exist.
    let candidates = candidate_display_names(model);
    if candidates.is_empty() {
        ResolveResult::BestEffort(input.to_string())
    } else {
        ResolveResult::NotFound { candidates }
    }
}

/// Look up `kind` in [`SEED_KIND_MAP`]. Pure; no logging.
pub fn lookup_seed(kind: &str) -> Option<&'static str> {
    SEED_KIND_MAP
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, v)| *v)
}

/// All non-null group display names in the model, deduplicated and sorted.
/// Used as the suggestion set when the resolver chain misses.
fn candidate_display_names(model: &Model) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for g in model.groups.values() {
        if let Some(n) = &g.name {
            names.insert(n.clone());
        } else if let Some(k) = g.kind.as_deref().or(g.kind_legacy.as_deref())
            && let Some(display) = lookup_seed(k)
        {
            names.insert(display.to_string());
        }
    }
    names.into_iter().collect()
}

fn warn_unknown_kind(kind: &str, model: &Model) {
    let groups_affected: Vec<&String> = model
        .groups
        .iter()
        .filter(|(_, g)| g.kind.as_deref() == Some(kind) || g.kind_legacy.as_deref() == Some(kind))
        .map(|(id, _)| id)
        .collect();

    tracing::warn!(
        event = "unknown_kind_warning",
        kind,
        groups_affected = ?groups_affected,
        remediation = "add to safety::resolver::SEED_KIND_MAP or report at \
                       https://github.com/torsday/little-snitch-mcp/issues",
        "encountered LS rule group kind that has no entry in SEED_KIND_MAP"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Group;
    use std::collections::HashMap;

    fn empty_model() -> Model {
        // Use serde_json default route to fill in remaining fields.
        serde_json::from_value(serde_json::json!({
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
        .expect("empty model fixture must parse")
    }

    fn group_with(name: Option<&str>, kind: Option<&str>, kind_legacy: Option<&str>) -> Group {
        Group {
            name: name.map(String::from),
            kind: kind.map(String::from),
            kind_legacy: kind_legacy.map(String::from),
            is_active: Some(true),
            update_interval: None,
            last_update_invalid_domains_count: None,
            extra: HashMap::new(),
        }
    }

    fn model_with_groups(entries: &[(&str, Group)]) -> Model {
        let mut m = empty_model();
        for (id, g) in entries {
            m.groups.insert((*id).into(), g.clone());
        }
        m
    }

    // ---------- Step 1: exact name match ----------

    #[test]
    fn exact_display_name_match_returns_verified() {
        let m = model_with_groups(&[(
            "aaaaa1",
            group_with(Some("My Local Group"), Some("local"), None),
        )]);
        assert_eq!(
            resolve_group("My Local Group", &m),
            ResolveResult::Verified("My Local Group".into())
        );
    }

    #[test]
    fn name_match_is_case_sensitive() {
        let m = model_with_groups(&[(
            "aaaaa1",
            group_with(Some("My Local Group"), Some("local"), None),
        )]);
        // case-different input doesn't match step 1; falls through to NotFound
        match resolve_group("my local group", &m) {
            ResolveResult::NotFound { candidates } => {
                assert!(candidates.contains(&"My Local Group".to_string()));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // ---------- Step 2: kind match via SEED_KIND_MAP ----------

    #[test]
    fn known_kind_resolves_to_display_name() {
        let m = model_with_groups(&[(
            "aaaaa2",
            group_with(None, Some("builtinMacOSServices"), None),
        )]);
        assert_eq!(
            resolve_group("builtinMacOSServices", &m),
            ResolveResult::Verified("macOS Services".into())
        );
    }

    #[test]
    fn known_kind_via_legacy_type_field_resolves() {
        let m = model_with_groups(&[(
            "aaaaa3",
            group_with(None, None, Some("builtinICloudServices")),
        )]);
        assert_eq!(
            resolve_group("builtinICloudServices", &m),
            ResolveResult::Verified("iCloud Services".into())
        );
    }

    #[test]
    fn kind_present_in_model_but_not_in_seed_map_falls_through_to_not_found() {
        // The model has a kind we don't recognize; chain continues to
        // step 4. Because there's a known display name (from another
        // group), we return NotFound with that as the suggestion.
        let m = model_with_groups(&[
            (
                "aaaaa4",
                group_with(None, Some("builtinNewlyAddedThing"), None),
            ),
            ("aaaaa5", group_with(Some("Local"), Some("local"), None)),
        ]);
        match resolve_group("builtinNewlyAddedThing", &m) {
            ResolveResult::NotFound { candidates } => {
                assert!(candidates.contains(&"Local".to_string()));
            }
            other => panic!("expected NotFound (warned + fell through), got {other:?}"),
        }
    }

    // ---------- Step 3: id lookup ----------

    #[test]
    fn id_lookup_resolves_via_name() {
        let m = model_with_groups(&[(
            "aaaaac",
            group_with(Some("macOS Services"), Some("local"), None),
        )]);
        assert_eq!(
            resolve_group("aaaaac", &m),
            ResolveResult::Verified("macOS Services".into())
        );
    }

    #[test]
    fn id_lookup_resolves_via_kind() {
        let m = model_with_groups(&[(
            "aaaaae",
            group_with(None, Some("builtinICloudServices"), None),
        )]);
        assert_eq!(
            resolve_group("aaaaae", &m),
            ResolveResult::Verified("iCloud Services".into())
        );
    }

    #[test]
    fn id_lookup_for_group_with_no_name_or_known_kind_falls_through() {
        // Group exists but has neither a non-null name nor a kind in
        // SEED_KIND_MAP — fall through to step 4.
        let m = model_with_groups(&[
            ("aaaaaf", group_with(None, Some("builtinNewly"), None)),
            ("aaaaag", group_with(Some("Other"), Some("local"), None)),
        ]);
        match resolve_group("aaaaaf", &m) {
            ResolveResult::NotFound { candidates } => {
                assert!(candidates.contains(&"Other".to_string()));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // ---------- Step 4: passthrough ----------

    #[test]
    fn unknown_input_with_no_named_groups_returns_best_effort() {
        let m = empty_model();
        assert_eq!(
            resolve_group("Some Random String", &m),
            ResolveResult::BestEffort("Some Random String".into())
        );
    }

    #[test]
    fn unknown_input_with_named_groups_returns_not_found_with_candidates() {
        let m = model_with_groups(&[
            ("aaaaa1", group_with(Some("Group A"), Some("local"), None)),
            ("aaaaa2", group_with(Some("Group B"), Some("local"), None)),
        ]);
        match resolve_group("Some Random String", &m) {
            ResolveResult::NotFound { candidates } => {
                let set: BTreeSet<_> = candidates.iter().collect();
                assert!(set.contains(&"Group A".to_string()));
                assert!(set.contains(&"Group B".to_string()));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn candidates_include_seeded_kinds_for_groups_with_null_name() {
        // A group with `name: None` but a known `kind` contributes its
        // display name (from SEED_KIND_MAP) to the candidates list.
        // Otherwise the operator wouldn't know to ask for "macOS Services".
        let m = model_with_groups(&[
            (
                "aaaaa1",
                group_with(None, Some("builtinMacOSServices"), None),
            ),
            ("aaaaa2", group_with(Some("My Local"), Some("local"), None)),
        ]);
        match resolve_group("nope", &m) {
            ResolveResult::NotFound { candidates } => {
                let set: BTreeSet<_> = candidates.iter().collect();
                assert!(set.contains(&"macOS Services".to_string()));
                assert!(set.contains(&"My Local".to_string()));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn candidates_are_deduplicated_and_sorted() {
        // Two groups happen to share a name — only one entry in candidates.
        let m = model_with_groups(&[
            ("a", group_with(Some("Same"), None, None)),
            ("b", group_with(Some("Same"), None, None)),
            ("c", group_with(Some("Other"), None, None)),
        ]);
        match resolve_group("nope", &m) {
            ResolveResult::NotFound { candidates } => {
                assert_eq!(candidates, vec!["Other".to_string(), "Same".to_string()]);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // ---------- SEED_KIND_MAP integrity ----------

    #[test]
    fn seed_map_has_no_duplicate_keys() {
        let mut seen = BTreeSet::new();
        for (k, _) in SEED_KIND_MAP {
            assert!(seen.insert(*k), "duplicate kind in SEED_KIND_MAP: {k}");
        }
    }

    #[test]
    fn seed_map_values_are_non_empty() {
        for (k, v) in SEED_KIND_MAP {
            assert!(!v.is_empty(), "empty display name for kind {k}");
        }
    }

    #[test]
    fn lookup_seed_returns_none_for_unknown_kind() {
        assert_eq!(lookup_seed("builtinNonExistentForSure"), None);
    }

    #[test]
    fn lookup_seed_returns_macos_services_for_known_kind() {
        assert_eq!(lookup_seed("builtinMacOSServices"), Some("macOS Services"));
    }

    // ---------- Step ordering ----------

    #[test]
    fn step_1_name_wins_over_step_2_kind_when_input_could_match_both() {
        // Imagine someone names their local group "builtinMacOSServices" — the
        // exact-name match wins because step 1 runs first. Pathological but
        // worth pinning so the chain order is deterministic.
        let m = model_with_groups(&[(
            "aaaaa1",
            group_with(Some("builtinMacOSServices"), Some("local"), None),
        )]);
        assert_eq!(
            resolve_group("builtinMacOSServices", &m),
            ResolveResult::Verified("builtinMacOSServices".into())
        );
    }
}
