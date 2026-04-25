//! Per-rule mutation guard.
//!
//! Implements the rule-level half of [ADR-0004 §8](../../../docs/adr/0004-safety-permissions-and-confirmation.md):
//! certain rules are *protected* against mutation through the MCP — either
//! flagged by LS itself (`protected: true`, `factory_id` set), tied to a
//! signed-binary trust check (`requires_trusted_signature_for_any_process`),
//! or owned by a builtin subscription group (`group.kind` starts with
//! `"builtin"`). These are not blanket refusals — they require the caller
//! to supply a `live_write_strong` acknowledgement, the same gate that
//! protects the kill-switch surface.
//!
//! The guard is **pure**: caller passes the rule, the intended mutation,
//! and the rule's group (looked up from `model.groups[rule.group]` if any).
//! No I/O, no global state — easy to test against fixture rules.
//!
//! # Where this gate must run
//!
//! Every code path that mutates an existing live-model rule:
//!
//! - [#60](https://github.com/torsday/little-snitch-mcp/issues/60) —
//!   `update_rule_in_live_model` and `remove_rule_from_live_model`. The
//!   guard runs before the confirmation-token issue step; if it returns
//!   `requires_strong_ack: true`, the prepare-side tool packages the
//!   strong-ack requirement into the token's payload so the apply-side
//!   tool can verify the operator typed the explicit acknowledgement
//!   string.
//! - Any future tool that takes a live-model rule reference and mutates it.

use crate::model::{Group, Rule};

/// What kind of mutation is being attempted on the rule.
///
/// Tracked separately from the guard logic so future intents (e.g.
/// `Disable`, `Reorder`) can apply different policies without
/// reshuffling the existing checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Edit one or more fields of the rule in place.
    Update,
    /// Delete the rule entirely.
    Remove,
}

/// Outcome of a single guard evaluation.
///
/// `allowed` is the bottom-line answer the caller branches on. The other
/// fields are diagnostic: they tell the caller *why* the answer landed
/// where it did and whether re-attempting with `live_write_strong` ack
/// would change the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardResult {
    /// True if the mutation may proceed *without* further escalation.
    /// False means either the caller must obtain a `live_write_strong`
    /// acknowledgement (when [`requires_strong_ack`] is `true`) or the
    /// mutation is unconditionally refused (currently no such case
    /// exists at this layer; reserved for future hard-rejects).
    pub allowed: bool,
    /// Human-readable explanation of which guard fired. `None` only when
    /// the rule passed every check and `allowed == true`.
    pub reason: Option<String>,
    /// True when re-attempting with a `live_write_strong` ack would
    /// flip `allowed` to `true`. Always `false` when `allowed` is
    /// already `true`.
    pub requires_strong_ack: bool,
}

impl GuardResult {
    fn allowed() -> Self {
        Self {
            allowed: true,
            reason: None,
            requires_strong_ack: false,
        }
    }

    fn needs_strong_ack(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            requires_strong_ack: true,
        }
    }
}

/// Evaluate the per-rule mutation policy.
///
/// `group` is the group entry that `rule.group` resolves to in
/// `model.groups`. Pass `None` if the rule has no `group` field, or
/// the lookup miss-id'd (in which case the builtin-group check is
/// skipped — there's no way to verify the rule belongs to a builtin
/// subscription without the group).
///
/// Returns `GuardResult { allowed: true }` when the rule is freely
/// mutable. Otherwise returns `requires_strong_ack: true` with a
/// reason naming the specific guard that fired. Order is deterministic
/// — the first matching guard's reason is returned, so audit logs
/// don't depend on rule field traversal order.
pub fn guard(rule: &Rule, _intent: Intent, group: Option<&Group>) -> GuardResult {
    if rule.protected.unwrap_or(false) {
        return GuardResult::needs_strong_ack(
            "rule has `protected: true` — mutating LS-protected rules requires \
             live_write_strong acknowledgement",
        );
    }

    if let Some(factory_id) = rule.factory_id.as_deref() {
        return GuardResult::needs_strong_ack(format!(
            "rule has `factoryID: {factory_id:?}` — factory rules are LS-managed and \
             mutating them requires live_write_strong acknowledgement"
        ));
    }

    if rule
        .requires_trusted_signature_for_any_process
        .unwrap_or(false)
    {
        return GuardResult::needs_strong_ack(
            "rule has `requiresTrustedSignatureForAnyProcess: true` — weakening the \
             signature trust gate requires live_write_strong acknowledgement",
        );
    }

    if let Some(group) = group
        && let Some(kind) = builtin_kind(group)
    {
        return GuardResult::needs_strong_ack(format!(
            "rule belongs to builtin group (kind: {kind:?}) — mutating rules in \
             builtin subscriptions requires live_write_strong acknowledgement"
        ));
    }

    GuardResult::allowed()
}

/// Return the group's `kind` (preferring the canonical field over the
/// legacy alias) iff it identifies a builtin subscription. Returns
/// `None` when the group is user-created or has no kind information.
fn builtin_kind(group: &Group) -> Option<&str> {
    let k = group.kind.as_deref().or(group.kind_legacy.as_deref())?;
    if k.starts_with("builtin") {
        Some(k)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Action;
    use std::collections::HashMap;

    fn plain_rule() -> Rule {
        Rule {
            action: Action::Allow,
            creation_date: String::new(),
            modification_date: String::new(),
            origin: crate::model::Origin::frontend(),
            uid: None,
            process: None,
            requires_trusted_signature_for_any_process: None,
            remote: None,
            remote_domains: None,
            remote_hosts: None,
            remote_addresses: None,
            direction: None,
            priority: None,
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
            factory_id: None,
            factory_help_text: None,
            protected: None,
            last_used: None,
            use_count: None,
            approved: None,
            hidden: None,
            owner: None,
            extra: HashMap::new(),
        }
    }

    fn group(kind: Option<&str>, kind_legacy: Option<&str>) -> Group {
        Group {
            name: None,
            kind: kind.map(String::from),
            kind_legacy: kind_legacy.map(String::from),
            is_active: Some(true),
            update_interval: None,
            last_update_invalid_domains_count: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn plain_rule_is_freely_mutable() {
        let g = guard(&plain_rule(), Intent::Update, None);
        assert!(g.allowed);
        assert!(!g.requires_strong_ack);
        assert!(g.reason.is_none());
    }

    #[test]
    fn protected_true_requires_strong_ack() {
        let mut r = plain_rule();
        r.protected = Some(true);
        let g = guard(&r, Intent::Update, None);
        assert!(!g.allowed);
        assert!(g.requires_strong_ack);
        let reason = g.reason.expect("must have a reason");
        assert!(
            reason.contains("protected"),
            "reason must name the field: {reason}"
        );
        assert!(
            reason.contains("live_write_strong"),
            "reason must name the escalation: {reason}"
        );
    }

    #[test]
    fn protected_false_or_absent_does_not_trip() {
        let mut r = plain_rule();
        r.protected = Some(false);
        assert!(guard(&r, Intent::Update, None).allowed);
        r.protected = None;
        assert!(guard(&r, Intent::Update, None).allowed);
    }

    #[test]
    fn factory_id_set_requires_strong_ack() {
        let mut r = plain_rule();
        r.factory_id = Some("ls-factory-001".into());
        let g = guard(&r, Intent::Remove, None);
        assert!(!g.allowed);
        assert!(g.requires_strong_ack);
        let reason = g.reason.unwrap();
        assert!(
            reason.contains("ls-factory-001"),
            "reason must name the id: {reason}"
        );
        assert!(reason.contains("factoryID") || reason.contains("factory_id"));
    }

    #[test]
    fn requires_trusted_signature_for_any_process_requires_strong_ack() {
        let mut r = plain_rule();
        r.requires_trusted_signature_for_any_process = Some(true);
        let g = guard(&r, Intent::Update, None);
        assert!(!g.allowed);
        assert!(g.requires_strong_ack);
        let reason = g.reason.unwrap();
        assert!(
            reason.contains("requiresTrustedSignatureForAnyProcess")
                || reason.contains("signature"),
            "reason must name the field: {reason}"
        );
    }

    #[test]
    fn requires_trusted_signature_false_or_absent_does_not_trip() {
        let mut r = plain_rule();
        r.requires_trusted_signature_for_any_process = Some(false);
        assert!(guard(&r, Intent::Update, None).allowed);
        r.requires_trusted_signature_for_any_process = None;
        assert!(guard(&r, Intent::Update, None).allowed);
    }

    #[test]
    fn rule_in_builtin_group_via_kind_requires_strong_ack() {
        let r = plain_rule();
        let g = group(Some("builtinMacOSServices"), None);
        let result = guard(&r, Intent::Update, Some(&g));
        assert!(!result.allowed);
        assert!(result.requires_strong_ack);
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("builtinMacOSServices"),
            "reason must name the kind: {reason}"
        );
        assert!(
            reason.contains("builtin"),
            "reason must mention builtin: {reason}"
        );
    }

    #[test]
    fn rule_in_builtin_group_via_kind_legacy_requires_strong_ack() {
        let r = plain_rule();
        // Some older fixtures use `type` (deserialized as `kind_legacy`)
        // instead of the newer `kind` field.
        let g = group(None, Some("builtinICloudServices"));
        let result = guard(&r, Intent::Remove, Some(&g));
        assert!(!result.allowed);
        assert!(result.requires_strong_ack);
        assert!(result.reason.unwrap().contains("builtinICloudServices"));
    }

    #[test]
    fn rule_in_user_created_group_is_allowed() {
        let r = plain_rule();
        let g = group(Some("local"), None);
        let result = guard(&r, Intent::Update, Some(&g));
        assert!(result.allowed);
        assert!(result.reason.is_none());
    }

    #[test]
    fn rule_with_no_group_lookup_skips_builtin_check() {
        // Rule references a group ID but the lookup miss'd (e.g., stale
        // model). We don't refuse on that basis alone — caller is
        // responsible for treating the missing group as a separate
        // class of error if needed.
        let r = plain_rule();
        let result = guard(&r, Intent::Update, None);
        assert!(result.allowed);
    }

    #[test]
    fn intent_does_not_change_outcome_for_current_guards() {
        // All four current guards refuse for the same reasons regardless
        // of whether the caller wants to update or remove the rule. This
        // is a pinning test — if a future Intent variant should refuse
        // differently, this test must change deliberately.
        let mut r = plain_rule();
        r.protected = Some(true);
        let upd = guard(&r, Intent::Update, None);
        let rem = guard(&r, Intent::Remove, None);
        assert_eq!(upd, rem);
    }

    #[test]
    fn first_matching_guard_wins_protected_before_factory_id() {
        let mut r = plain_rule();
        r.protected = Some(true);
        r.factory_id = Some("would-also-fire".into());
        let g = guard(&r, Intent::Update, None);
        let reason = g.reason.unwrap();
        assert!(reason.contains("protected"));
        assert!(!reason.contains("would-also-fire"));
    }

    #[test]
    fn group_with_non_builtin_kind_does_not_trip() {
        let r = plain_rule();
        for kind in ["local", "shared", "subscription", "user-defined"] {
            let g = group(Some(kind), None);
            assert!(
                guard(&r, Intent::Update, Some(&g)).allowed,
                "kind {kind:?} must not trigger builtin guard"
            );
        }
    }

    #[test]
    fn group_kind_matching_substring_but_not_prefix_does_not_trip() {
        let r = plain_rule();
        // A kind with "builtin" in the middle should NOT trip — the rule
        // is about builtin subscriptions which all start with "builtin".
        let g = group(Some("not-builtin-anything"), None);
        assert!(guard(&r, Intent::Update, Some(&g)).allowed);
    }

    // ---------- helper coverage ----------

    #[test]
    fn builtin_kind_prefers_canonical_kind_over_legacy() {
        let g = group(Some("builtinX"), Some("not-relevant"));
        assert_eq!(builtin_kind(&g), Some("builtinX"));
    }

    #[test]
    fn builtin_kind_falls_back_to_legacy_when_canonical_absent() {
        let g = group(None, Some("builtinY"));
        assert_eq!(builtin_kind(&g), Some("builtinY"));
    }

    #[test]
    fn builtin_kind_returns_none_for_user_kinds() {
        let g = group(Some("local"), Some("local-legacy"));
        assert_eq!(builtin_kind(&g), None);
    }
}
