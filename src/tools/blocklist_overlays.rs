//! `disable_blocklist_entry` / `enable_blocklist_entry` /
//! `list_blocklist_overlays` — overlay-array tools.
//!
//! LS exposes three top-level overlay arrays in the live model:
//! `disabledDomainsInLists`, `disabledHostNamesInLists`, and
//! `disabledIPAddressRangesInLists`. Append to disable a single
//! entry inside a subscribed blocklist; remove to re-enable.
//!
//! This is the **lowest-risk Track-B-surgery surface**: just appends
//! to top-level arrays. No rule-level guards apply (the entries are
//! not rules). Idempotent on both sides — duplicate appends are
//! no-ops; removes of absent entries are no-ops.
//!
//! # Token binding
//!
//! Each write tool has its own prepare counterpart (mirroring
//! `write_preference`'s pattern). The unified `prepare_live_model_change`
//! could be extended to cover these too as a future follow-up.

use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Model, RemoteOverlayEntry, canonical_value};
use crate::safety::{Session, Token, TokenError, VerifyContext, token};

/// Which overlay array the entry routes to.
///
/// The variant maps directly to one of the three top-level fields in
/// [`crate::model::Model`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlocklistEntryKind {
    /// Routes to `disabledDomainsInLists`.
    Domain,
    /// Routes to `disabledHostNamesInLists`.
    Host,
    /// Routes to `disabledIPAddressRangesInLists`.
    Address,
}

impl BlocklistEntryKind {
    fn array_mut<'a>(self, model: &'a mut Model) -> &'a mut Vec<RemoteOverlayEntry> {
        match self {
            BlocklistEntryKind::Domain => &mut model.disabled_domains_in_lists,
            BlocklistEntryKind::Host => &mut model.disabled_host_names_in_lists,
            BlocklistEntryKind::Address => &mut model.disabled_ip_address_ranges_in_lists,
        }
    }

    fn label(self) -> &'static str {
        match self {
            BlocklistEntryKind::Domain => "domain",
            BlocklistEntryKind::Host => "host",
            BlocklistEntryKind::Address => "address",
        }
    }
}

/// Result of `list_blocklist_overlays` — read-only.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ListOverlaysResult {
    pub disabled_domains: Vec<RemoteOverlayEntry>,
    pub disabled_hosts: Vec<RemoteOverlayEntry>,
    pub disabled_addresses: Vec<RemoteOverlayEntry>,
}

/// Args for `prepare_disable_blocklist_entry` and
/// `prepare_enable_blocklist_entry`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareOverlayArgs {
    pub entry: String,
    pub kind: BlocklistEntryKind,
}

/// Args for the apply-side write tools.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OverlayWriteArgs {
    pub entry: String,
    pub kind: BlocklistEntryKind,
    pub token: String,
}

/// What a prepare call returns (mirrors `prepare_live_model_change`'s shape).
#[derive(Debug, Serialize, JsonSchema)]
pub struct OverlayPrepareResult {
    pub token: String,
    pub diff: serde_json::Value,
    pub expires_in_seconds: u64,
}

/// What can go wrong on the apply side.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("token verify failed: {0}")]
    Token(#[from] TokenError),
}

// ─── read ──────────────────────────────────────────────────────────────────

/// Return all three overlay arrays from `model`.
pub fn list_overlays(model: &Model) -> ListOverlaysResult {
    ListOverlaysResult {
        disabled_domains: model.disabled_domains_in_lists.clone(),
        disabled_hosts: model.disabled_host_names_in_lists.clone(),
        disabled_addresses: model.disabled_ip_address_ranges_in_lists.clone(),
    }
}

// ─── pure data ops ─────────────────────────────────────────────────────────

/// Append `entry` to the matching array if not already present.
/// Returns `true` if the array changed (false = already present).
pub fn disable_pure(model: &mut Model, entry: &str, kind: BlocklistEntryKind) -> bool {
    let arr = kind.array_mut(model);
    if entry_present(arr, entry) {
        return false;
    }
    arr.push(serde_json::Value::String(entry.to_string()));
    true
}

/// Remove every occurrence of `entry` from the matching array.
/// Returns `true` if the array changed (false = absent to begin with).
pub fn enable_pure(model: &mut Model, entry: &str, kind: BlocklistEntryKind) -> bool {
    let arr = kind.array_mut(model);
    let before = arr.len();
    arr.retain(|v| !entry_value_matches(v, entry));
    arr.len() != before
}

fn entry_present(arr: &[RemoteOverlayEntry], entry: &str) -> bool {
    arr.iter().any(|v| entry_value_matches(v, entry))
}

/// An overlay entry matches `entry` when its JSON-string form equals it.
/// LS appears to store entries as bare JSON strings; we treat any other
/// JSON shape as non-matching (forward-compat: a future LS version
/// emitting object-shaped entries would need its own match rule).
fn entry_value_matches(v: &RemoteOverlayEntry, entry: &str) -> bool {
    matches!(v, serde_json::Value::String(s) if s == entry)
}

// ─── prepare ───────────────────────────────────────────────────────────────

/// Issue a token bound to a `disable` overlay op against the current model.
pub fn prepare_disable(
    session: &Arc<Session>,
    args: PrepareOverlayArgs,
    current: &Model,
    now_unix_secs: u64,
) -> OverlayPrepareResult {
    prepare_op(
        session,
        args.entry,
        args.kind,
        "disable",
        current,
        now_unix_secs,
    )
}

/// Issue a token bound to an `enable` overlay op against the current model.
pub fn prepare_enable(
    session: &Arc<Session>,
    args: PrepareOverlayArgs,
    current: &Model,
    now_unix_secs: u64,
) -> OverlayPrepareResult {
    prepare_op(
        session,
        args.entry,
        args.kind,
        "enable",
        current,
        now_unix_secs,
    )
}

fn prepare_op(
    session: &Arc<Session>,
    entry: String,
    kind: BlocklistEntryKind,
    op: &'static str,
    current: &Model,
    now_unix_secs: u64,
) -> OverlayPrepareResult {
    let bundle_version = current.bundle_version.to_string();
    let diff = build_diff(op, &entry, kind);
    let diff_sha256 = canonical_sha256(&diff);
    let target = serde_json::json!({
        "op": format!("{op}_blocklist_entry"),
        "kind": kind.label(),
        "entry": entry,
    });
    let payload = token::payload(
        tool_name(op),
        target,
        &diff_sha256,
        &bundle_version,
        now_unix_secs,
        token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    OverlayPrepareResult {
        token: token.into_string(),
        diff,
        expires_in_seconds: token::DEFAULT_TTL_SECS,
    }
}

// ─── apply ─────────────────────────────────────────────────────────────────

/// Apply a `disable_blocklist_entry` operation.
///
/// Verifies the token, then idempotently appends the entry. Returns
/// the updated model. Idempotent: a no-op disable still verifies the
/// token (and consumes it), so a malicious LLM can't replay a token
/// hoping the second use silently succeeds.
pub fn apply_disable_pure(
    mut current: Model,
    entry: String,
    kind: BlocklistEntryKind,
    token_str: String,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<Model, OverlayError> {
    verify_token(
        &current,
        &entry,
        kind,
        "disable",
        token_str,
        session,
        now_unix_secs,
    )?;
    disable_pure(&mut current, &entry, kind);
    Ok(current)
}

/// Apply an `enable_blocklist_entry` operation.
pub fn apply_enable_pure(
    mut current: Model,
    entry: String,
    kind: BlocklistEntryKind,
    token_str: String,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<Model, OverlayError> {
    verify_token(
        &current,
        &entry,
        kind,
        "enable",
        token_str,
        session,
        now_unix_secs,
    )?;
    enable_pure(&mut current, &entry, kind);
    Ok(current)
}

fn verify_token(
    current: &Model,
    entry: &str,
    kind: BlocklistEntryKind,
    op: &str,
    token_str: String,
    session: &Arc<Session>,
    now_unix_secs: u64,
) -> Result<(), OverlayError> {
    let bundle_version = current.bundle_version.to_string();
    let diff = build_diff(op, entry, kind);
    let diff_sha256 = canonical_sha256(&diff);
    let token = Token::from(token_str);
    let ctx = VerifyContext {
        tool: tool_name(op),
        current_diff_sha256: &diff_sha256,
        current_bundle_version: &bundle_version,
    };
    session.verify_at(&token, &ctx, now_unix_secs)?;
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

fn build_diff(op: &str, entry: &str, kind: BlocklistEntryKind) -> serde_json::Value {
    serde_json::json!({
        "kind": format!("{op}_blocklist_entry"),
        "entry": entry,
        "entry_kind": kind.label(),
    })
}

fn tool_name(op: &str) -> &'static str {
    match op {
        "disable" => "disable_blocklist_entry",
        "enable" => "enable_blocklist_entry",
        _ => unreachable!("op must be 'disable' or 'enable'"),
    }
}

fn canonical_sha256(value: &serde_json::Value) -> String {
    let canon = canonical_value(value.clone());
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&canon).expect("canonical JSON"));
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_model() -> Model {
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
        .unwrap()
    }

    fn session() -> Arc<Session> {
        Arc::new(Session::from_raw([1u8; 32], [9u8; 32]))
    }

    const FIXED_NOW: u64 = 1_777_200_000;

    // ---------- pure ops: idempotency ----------

    #[test]
    fn disable_pure_appends_when_absent() {
        let mut m = empty_model();
        assert!(disable_pure(
            &mut m,
            "ads.example",
            BlocklistEntryKind::Domain
        ));
        assert_eq!(m.disabled_domains_in_lists.len(), 1);
    }

    #[test]
    fn disable_pure_is_noop_when_present() {
        let mut m = empty_model();
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        // Second call — no change.
        let changed = disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        assert!(!changed);
        assert_eq!(m.disabled_domains_in_lists.len(), 1);
    }

    #[test]
    fn enable_pure_removes_when_present() {
        let mut m = empty_model();
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        let changed = enable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        assert!(changed);
        assert_eq!(m.disabled_domains_in_lists.len(), 0);
    }

    #[test]
    fn enable_pure_is_noop_when_absent() {
        let mut m = empty_model();
        let changed = enable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        assert!(!changed);
    }

    #[test]
    fn round_trip_disable_then_enable_returns_to_original() {
        let m_original = empty_model();
        let mut m = m_original.clone();
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        enable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        assert_eq!(
            m.disabled_domains_in_lists,
            m_original.disabled_domains_in_lists
        );
    }

    // ---------- pure ops: kind routing ----------

    #[test]
    fn disable_routes_domain_to_domain_array() {
        let mut m = empty_model();
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        assert_eq!(m.disabled_domains_in_lists.len(), 1);
        assert_eq!(m.disabled_host_names_in_lists.len(), 0);
        assert_eq!(m.disabled_ip_address_ranges_in_lists.len(), 0);
    }

    #[test]
    fn disable_routes_host_to_host_array() {
        let mut m = empty_model();
        disable_pure(&mut m, "host.example", BlocklistEntryKind::Host);
        assert_eq!(m.disabled_domains_in_lists.len(), 0);
        assert_eq!(m.disabled_host_names_in_lists.len(), 1);
        assert_eq!(m.disabled_ip_address_ranges_in_lists.len(), 0);
    }

    #[test]
    fn disable_routes_address_to_address_array() {
        let mut m = empty_model();
        disable_pure(&mut m, "10.0.0.0/8", BlocklistEntryKind::Address);
        assert_eq!(m.disabled_domains_in_lists.len(), 0);
        assert_eq!(m.disabled_host_names_in_lists.len(), 0);
        assert_eq!(m.disabled_ip_address_ranges_in_lists.len(), 1);
    }

    #[test]
    fn enable_in_one_kind_does_not_touch_other_kinds() {
        let mut m = empty_model();
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Host);
        enable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);
        assert_eq!(m.disabled_domains_in_lists.len(), 0);
        assert_eq!(m.disabled_host_names_in_lists.len(), 1);
    }

    // ---------- list ----------

    #[test]
    fn list_overlays_returns_all_three_arrays() {
        let mut m = empty_model();
        disable_pure(&mut m, "a.example", BlocklistEntryKind::Domain);
        disable_pure(&mut m, "h.example", BlocklistEntryKind::Host);
        disable_pure(&mut m, "10.0.0.0/8", BlocklistEntryKind::Address);
        let r = list_overlays(&m);
        assert_eq!(r.disabled_domains.len(), 1);
        assert_eq!(r.disabled_hosts.len(), 1);
        assert_eq!(r.disabled_addresses.len(), 1);
    }

    // ---------- prepare → apply round trip ----------

    #[test]
    fn prepare_then_apply_disable_round_trip() {
        let s = session();
        let m = empty_model();
        let prep = prepare_disable(
            &s,
            PrepareOverlayArgs {
                entry: "ads.example".into(),
                kind: BlocklistEntryKind::Domain,
            },
            &m,
            FIXED_NOW,
        );
        let new_model = apply_disable_pure(
            m,
            "ads.example".into(),
            BlocklistEntryKind::Domain,
            prep.token,
            &s,
            FIXED_NOW,
        )
        .unwrap();
        assert_eq!(new_model.disabled_domains_in_lists.len(), 1);
    }

    #[test]
    fn prepare_then_apply_enable_round_trip() {
        let s = session();
        let mut m = empty_model();
        disable_pure(&mut m, "ads.example", BlocklistEntryKind::Domain);

        let prep = prepare_enable(
            &s,
            PrepareOverlayArgs {
                entry: "ads.example".into(),
                kind: BlocklistEntryKind::Domain,
            },
            &m,
            FIXED_NOW,
        );
        let new_model = apply_enable_pure(
            m,
            "ads.example".into(),
            BlocklistEntryKind::Domain,
            prep.token,
            &s,
            FIXED_NOW,
        )
        .unwrap();
        assert_eq!(new_model.disabled_domains_in_lists.len(), 0);
    }

    // ---------- token verifier failures ----------

    #[test]
    fn wrong_kind_at_apply_yields_diff_drift() {
        let s = session();
        let m = empty_model();
        let prep = prepare_disable(
            &s,
            PrepareOverlayArgs {
                entry: "ads.example".into(),
                kind: BlocklistEntryKind::Domain,
            },
            &m,
            FIXED_NOW,
        );
        // Apply with kind=Host (different array) — diff hashes don't match.
        let err = apply_disable_pure(
            m,
            "ads.example".into(),
            BlocklistEntryKind::Host,
            prep.token,
            &s,
            FIXED_NOW,
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::Token(TokenError::DiffDrift)));
    }

    #[test]
    fn enable_token_used_for_disable_apply_yields_tool_mismatch() {
        let s = session();
        let m = empty_model();
        let prep = prepare_enable(
            &s,
            PrepareOverlayArgs {
                entry: "ads.example".into(),
                kind: BlocklistEntryKind::Domain,
            },
            &m,
            FIXED_NOW,
        );
        // Try the enable token against the disable apply.
        let err = apply_disable_pure(
            m,
            "ads.example".into(),
            BlocklistEntryKind::Domain,
            prep.token,
            &s,
            FIXED_NOW,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::Token(TokenError::ToolMismatch | TokenError::DiffDrift)
        ));
    }

    #[test]
    fn replay_rejected_for_disable() {
        let s = session();
        let m = empty_model();
        let prep = prepare_disable(
            &s,
            PrepareOverlayArgs {
                entry: "ads.example".into(),
                kind: BlocklistEntryKind::Domain,
            },
            &m,
            FIXED_NOW,
        );
        // First apply succeeds.
        let m2 = apply_disable_pure(
            m,
            "ads.example".into(),
            BlocklistEntryKind::Domain,
            prep.token.clone(),
            &s,
            FIXED_NOW,
        )
        .unwrap();
        // Second apply with same token must fail (the AC's idempotency
        // is on the data side; the token side is single-use).
        let err = apply_disable_pure(
            m2,
            "ads.example".into(),
            BlocklistEntryKind::Domain,
            prep.token,
            &s,
            FIXED_NOW,
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::Token(TokenError::Replay)));
    }
}
