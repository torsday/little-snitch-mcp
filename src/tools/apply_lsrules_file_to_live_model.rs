//! `apply_lsrules_file_to_live_model` — fold a Track-A `.lsrules`
//! file into the live model via a single `restore-model -t` call.
//!
//! This is the bulk-import path: a `.lsrules` file (per
//! `schemas/lsrules.schema.json`) translates to N model-schema rules,
//! all appended to `model.rules`, and pushed in a single transaction.
//! One backup, one Touch ID prompt, N rules added.
//!
//! # The translation contract
//!
//! `.lsrules` rules are a stripped-down format: no `creation_date`,
//! no `modification_date`, no `origin`, no `uid`. The MCP fills these
//! in at translation time per the smoke-3 corrected-rule shape.
//!
//! The compact shorthand fields (`denied-remote-domains`,
//! `denied-remote-hosts`, `denied-remote-addresses`) expand to one
//! deny rule per entry, all with `process: "any"`. This matches LS's
//! own behavior when subscribing to a denylist file.
//!
//! # Scope deliberately deferred
//!
//! - **Group creation** — the AC mentions creating a `groups` entry
//!   when missing. `model::Group` has more fields than `.lsrules`
//!   exposes; landing this requires either a separate group-design
//!   ticket or a permissive default-fill. Punted to a follow-up.
//! - **Live rollback orchestration** — needs LS access. The pure
//!   translate + prepare/apply pair this PR ships are the
//!   safety-critical core; rollback is plumbing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Action, Model, Origin, Rule, StringOrVec, canonical_value};
use crate::safety::{Session, Token, TokenError, VerifyContext, token};

/// Tool input shape (apply side).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyLsrulesFileArgs {
    /// `.lsrules` file basename (without `.lsrules` extension), located
    /// under `<managed_root>/rules/`.
    pub file_name: String,
    /// Confirmation token from `prepare_apply_lsrules_file`.
    pub token: String,
}

/// Tool input shape (prepare side).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PrepareApplyLsrulesFileArgs {
    pub file_name: String,
}

/// Result of a successful prepare.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PrepareApplyLsrulesResult {
    pub token: String,
    /// Number of rules that would be added (translated count).
    pub rules_to_add: usize,
    /// SHA-256 of the canonicalized JSON of the would-be folded model.
    pub diff_sha256: String,
    pub expires_in_seconds: u64,
}

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum ApplyLsrulesError {
    #[error("FILE_NOT_FOUND: {0:?}")]
    FileNotFound(PathBuf),
    #[error("READ_FAILED: cannot read {path:?}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("INVALID_LSRULES_JSON: {path:?}: {source}")]
    InvalidJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("TRANSLATION_FAILED: {0}")]
    Translation(String),
    #[error("token verify failed: {0}")]
    Token(#[from] TokenError),
}

/// Resolve the .lsrules file path under `<managed_root>/rules/<name>.lsrules`.
fn resolve_lsrules_path(managed_root: &Path, file_name: &str) -> PathBuf {
    managed_root
        .join("rules")
        .join(format!("{file_name}.lsrules"))
}

/// Read and parse a .lsrules file as raw JSON.
fn read_lsrules(path: &Path) -> Result<serde_json::Value, ApplyLsrulesError> {
    if !path.exists() {
        return Err(ApplyLsrulesError::FileNotFound(path.to_path_buf()));
    }
    let bytes = std::fs::read(path).map_err(|source| ApplyLsrulesError::ReadFailed {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| ApplyLsrulesError::InvalidJson {
        path: path.to_path_buf(),
        source,
    })
}

/// Translate a `.lsrules` document into model-schema rules.
///
/// Pure: no I/O. Caller supplies `uid` (per smoke-3 corrected shape)
/// and `now_unix_secs` for the timestamps.
///
/// Two streams produce rules:
///
/// 1. The `rules` array — each entry is translated near-verbatim,
///    filling in the MCP-required fields (creation_date, modification_date,
///    origin, uid).
/// 2. The compact `denied-remote-{domains,hosts,addresses}` shorthand —
///    each entry expands to one deny rule with `process: "any"`.
///
/// Order: `rules` array first (in declaration order), then expanded
/// shorthand (domains, hosts, addresses, in that order). Stable across
/// runs so the canonical hash is deterministic.
pub fn translate(
    doc: &serde_json::Value,
    uid: u32,
    now_unix_secs: u64,
) -> Result<Vec<Rule>, ApplyLsrulesError> {
    let mut out = Vec::new();
    let now = format_iso8601_utc(now_unix_secs);

    // (1) Per-rule translation.
    if let Some(rules) = doc.get("rules").and_then(|r| r.as_array()) {
        for (idx, raw) in rules.iter().enumerate() {
            out.push(translate_one_rule(raw, idx, uid, &now)?);
        }
    }

    // (2) Shorthand expansion.
    for (field, kind) in &[
        ("denied-remote-domains", DeniedRemoteKind::Domains),
        ("denied-remote-hosts", DeniedRemoteKind::Hosts),
        ("denied-remote-addresses", DeniedRemoteKind::Addresses),
    ] {
        if let Some(arr) = doc.get(*field).and_then(|v| v.as_array()) {
            for entry in arr {
                let s = entry.as_str().ok_or_else(|| {
                    ApplyLsrulesError::Translation(format!(
                        "{field}[*] must be a string, got {entry}"
                    ))
                })?;
                out.push(make_deny_rule(s, *kind, uid, &now));
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum DeniedRemoteKind {
    Domains,
    Hosts,
    Addresses,
}

fn make_deny_rule(entry: &str, kind: DeniedRemoteKind, uid: u32, now: &str) -> Rule {
    let mut r = blank_rule(uid, now);
    r.action = Action::Deny;
    r.process = Some("any".into());
    let single = StringOrVec::One(entry.to_string());
    match kind {
        DeniedRemoteKind::Domains => r.remote_domains = Some(single),
        DeniedRemoteKind::Hosts => r.remote_hosts = Some(single),
        DeniedRemoteKind::Addresses => r.remote_addresses = Some(single),
    }
    r
}

fn translate_one_rule(
    raw: &serde_json::Value,
    idx: usize,
    uid: u32,
    now: &str,
) -> Result<Rule, ApplyLsrulesError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| ApplyLsrulesError::Translation(format!("rules[{idx}] must be an object")))?;

    let mut r = blank_rule(uid, now);

    // action (required by schema, but defend defensively here too)
    let action_str = obj.get("action").and_then(|v| v.as_str()).ok_or_else(|| {
        ApplyLsrulesError::Translation(format!("rules[{idx}].action is required"))
    })?;
    r.action = match action_str {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        "ask" => Action::Ask,
        other => {
            return Err(ApplyLsrulesError::Translation(format!(
                "rules[{idx}].action {other:?} is not one of allow|deny|ask"
            )));
        }
    };

    // process or requiresTrustedSignatureForAnyProcess.
    if let Some(proc_str) = obj.get("process").and_then(|v| v.as_str()) {
        r.process = Some(proc_str.to_string());
    } else if obj
        .get("requiresTrustedSignatureForAnyProcess")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        r.requires_trusted_signature_for_any_process = Some(true);
    }
    // Else neither set — LS treats absence as "any". The constructor
    // could refuse but the .lsrules schema permits this combination
    // when paired with a remote-* matcher.

    // remote (special string).
    if let Some(rem) = obj.get("remote").and_then(|v| v.as_str()) {
        r.remote = Some(rem.to_string());
    }

    // remote-{domains,hosts,addresses} — string-or-array shape preserved.
    for (field, target) in [
        ("remote-domains", &mut r.remote_domains),
        ("remote-hosts", &mut r.remote_hosts),
        ("remote-addresses", &mut r.remote_addresses),
    ] {
        if let Some(v) = obj.get(field) {
            *target = Some(parse_string_or_vec(v, field, idx)?);
        }
    }

    // direction.
    if let Some(d) = obj.get("direction").and_then(|v| v.as_str()) {
        r.direction = Some(match d {
            "incoming" => crate::model::Direction::Incoming,
            "outgoing" => crate::model::Direction::Outgoing,
            "both" => crate::model::Direction::Both,
            other => {
                return Err(ApplyLsrulesError::Translation(format!(
                    "rules[{idx}].direction {other:?} unrecognized"
                )));
            }
        });
        // If translated to outgoing, drop it to match LS's omit-default behavior.
        if r.direction == Some(crate::model::Direction::Outgoing) {
            r.direction = None;
        }
    }

    // priority — same omit-default discipline.
    if let Some(p) = obj.get("priority").and_then(|v| v.as_str()) {
        r.priority = Some(match p {
            "high" => crate::model::Priority::High,
            "regular" => crate::model::Priority::Regular,
            other => {
                return Err(ApplyLsrulesError::Translation(format!(
                    "rules[{idx}].priority {other:?} unrecognized (expected high|regular)"
                )));
            }
        });
        if r.priority == Some(crate::model::Priority::Regular) {
            r.priority = None;
        }
    }

    // pass-through string fields.
    for (field, target) in [
        ("protocol", &mut r.protocol),
        ("ports", &mut r.ports),
        ("via", &mut r.via),
        ("notes", &mut r.notes),
    ] {
        if let Some(s) = obj.get(field).and_then(|v| v.as_str()) {
            *target = Some(s.to_string());
        }
    }

    Ok(r)
}

fn parse_string_or_vec(
    v: &serde_json::Value,
    field: &str,
    idx: usize,
) -> Result<StringOrVec, ApplyLsrulesError> {
    if let Some(s) = v.as_str() {
        Ok(StringOrVec::One(s.to_string()))
    } else if let Some(arr) = v.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let s = item.as_str().ok_or_else(|| {
                ApplyLsrulesError::Translation(format!("rules[{idx}].{field}[*] must be a string"))
            })?;
            out.push(s.to_string());
        }
        if out.len() == 1 {
            Ok(StringOrVec::One(out.into_iter().next().unwrap()))
        } else {
            Ok(StringOrVec::Many(out))
        }
    } else {
        Err(ApplyLsrulesError::Translation(format!(
            "rules[{idx}].{field} must be a string or array of strings"
        )))
    }
}

fn blank_rule(uid: u32, now: &str) -> Rule {
    Rule {
        action: Action::Allow,
        creation_date: now.to_string(),
        modification_date: now.to_string(),
        origin: Origin::frontend(),
        uid: Some(uid),
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
        extra: std::collections::HashMap::new(),
    }
}

/// Append rules to `model.rules`. Returns the modified model.
pub fn fold_into_model(mut current: Model, new_rules: Vec<Rule>) -> Model {
    current.rules.extend(new_rules);
    current
}

/// Pure prepare: read+validate file, translate, fold, hash, issue token.
pub fn prepare_pure(
    session: &Arc<Session>,
    file_name: &str,
    managed_root: &Path,
    current: &Model,
    uid: u32,
    now_unix_secs: u64,
) -> Result<PrepareApplyLsrulesResult, ApplyLsrulesError> {
    let path = resolve_lsrules_path(managed_root, file_name);
    let doc = read_lsrules(&path)?;
    let new_rules = translate(&doc, uid, now_unix_secs)?;
    let folded = fold_into_model(current.clone(), new_rules.clone());
    let diff_sha256 = canonical_model_sha256(&folded);
    let bundle_version = current.bundle_version.to_string();
    let target = serde_json::json!({
        "op": "apply_lsrules_file_to_live_model",
        "file_name": file_name,
        "rules_to_add": new_rules.len(),
    });
    let payload = token::payload(
        "apply_lsrules_file_to_live_model",
        target,
        &diff_sha256,
        &bundle_version,
        now_unix_secs,
        token::DEFAULT_TTL_SECS,
    );
    let token = session.issue(payload);
    Ok(PrepareApplyLsrulesResult {
        token: token.into_string(),
        rules_to_add: new_rules.len(),
        diff_sha256,
        expires_in_seconds: token::DEFAULT_TTL_SECS,
    })
}

/// Pure apply: same translation, recompute hash, verify token, return folded model.
pub fn apply_pure(
    file_name: &str,
    token_str: String,
    managed_root: &Path,
    current: &Model,
    session: &Arc<Session>,
    uid: u32,
    now_unix_secs: u64,
) -> Result<Model, ApplyLsrulesError> {
    let path = resolve_lsrules_path(managed_root, file_name);
    let doc = read_lsrules(&path)?;
    let new_rules = translate(&doc, uid, now_unix_secs)?;
    let folded = fold_into_model(current.clone(), new_rules);
    let diff_sha256 = canonical_model_sha256(&folded);

    let token = Token::from(token_str);
    let ctx = VerifyContext {
        tool: "apply_lsrules_file_to_live_model",
        current_diff_sha256: &diff_sha256,
        current_bundle_version: &current.bundle_version.to_string(),
    };
    session.verify_at(&token, &ctx, now_unix_secs)?;
    Ok(folded)
}

fn canonical_model_sha256(model: &Model) -> String {
    let v = serde_json::to_value(model).expect("Model serializes");
    let canon = canonical_value(v);
    let bytes = serde_json::to_vec(&canon).expect("canonical JSON");
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

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

    const FIXED_NOW: u64 = 1_777_200_000;
    const FIXED_NOW_ISO: &str = "2026-04-26T10:40:00Z";

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

    // ---------- translate: rules array ----------

    #[test]
    fn translate_handles_minimal_rule() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote": "any"}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.action, Action::Deny);
        assert_eq!(r.process.as_deref(), Some("any"));
        assert_eq!(r.remote.as_deref(), Some("any"));
        assert_eq!(r.creation_date, FIXED_NOW_ISO);
        assert_eq!(r.uid, Some(501));
        assert_eq!(r.origin.0, Origin::FRONTEND);
    }

    #[test]
    fn translate_omits_outgoing_direction() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote": "any", "direction": "outgoing"}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out[0].direction, None); // outgoing is the default — omitted
    }

    #[test]
    fn translate_keeps_incoming_direction() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote": "any", "direction": "incoming"}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out[0].direction, Some(crate::model::Direction::Incoming));
    }

    #[test]
    fn translate_omits_regular_priority() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote": "any", "priority": "regular"}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out[0].priority, None);
    }

    #[test]
    fn translate_keeps_high_priority() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote": "any", "priority": "high"}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out[0].priority, Some(crate::model::Priority::High));
    }

    #[test]
    fn translate_remote_domains_single_string_preserved() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote-domains": "evil.example"}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        match &out[0].remote_domains {
            Some(StringOrVec::One(s)) => assert_eq!(s, "evil.example"),
            other => panic!("expected One, got {other:?}"),
        }
    }

    #[test]
    fn translate_remote_domains_array_preserved_when_multi() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote-domains": ["a.example", "b.example"]}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        match &out[0].remote_domains {
            Some(StringOrVec::Many(v)) => assert_eq!(v.len(), 2),
            other => panic!("expected Many, got {other:?}"),
        }
    }

    #[test]
    fn translate_remote_domains_array_with_one_entry_collapses_to_string() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "deny", "process": "any", "remote-domains": ["only.example"]}]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        match &out[0].remote_domains {
            Some(StringOrVec::One(s)) => assert_eq!(s, "only.example"),
            other => panic!("expected One, got {other:?}"),
        }
    }

    #[test]
    fn translate_requires_trusted_signature() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{
                "action": "allow",
                "requiresTrustedSignatureForAnyProcess": true,
                "remote": "any"
            }]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out[0].process, None);
        assert_eq!(
            out[0].requires_trusted_signature_for_any_process,
            Some(true)
        );
    }

    #[test]
    fn translate_unknown_action_refused() {
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "log-only"}]
        });
        let err = translate(&doc, 501, FIXED_NOW).unwrap_err();
        assert!(matches!(err, ApplyLsrulesError::Translation(_)));
    }

    // ---------- translate: shorthand expansion ----------

    #[test]
    fn shorthand_domains_expand_to_one_deny_rule_per_entry() {
        let doc = serde_json::json!({
            "name": "test",
            "denied-remote-domains": ["a.example", "b.example", "c.example"]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out.len(), 3);
        for (i, expected) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            assert_eq!(out[i].action, Action::Deny);
            assert_eq!(out[i].process.as_deref(), Some("any"));
            match &out[i].remote_domains {
                Some(StringOrVec::One(s)) => assert_eq!(s, expected),
                other => panic!("entry {i}: expected One, got {other:?}"),
            }
        }
    }

    #[test]
    fn shorthand_hosts_and_addresses_route_to_their_arrays() {
        let doc = serde_json::json!({
            "name": "test",
            "denied-remote-hosts": ["host.example"],
            "denied-remote-addresses": ["10.0.0.0/8"],
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].remote_hosts.is_some());
        assert!(out[0].remote_domains.is_none());
        assert!(out[1].remote_addresses.is_some());
    }

    #[test]
    fn rules_array_processed_before_shorthand() {
        // Order matters for diff hash determinism.
        let doc = serde_json::json!({
            "name": "test",
            "rules": [{"action": "allow", "process": "/bin/ls", "remote": "any"}],
            "denied-remote-domains": ["evil.example"]
        });
        let out = translate(&doc, 501, FIXED_NOW).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].action, Action::Allow); // from rules[]
        assert_eq!(out[1].action, Action::Deny); // from shorthand
    }

    // ---------- prepare → apply round trip ----------

    fn write_lsrules_file(root: &Path, name: &str, body: &serde_json::Value) -> PathBuf {
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        let path = rules_dir.join(format!("{name}.lsrules"));
        std::fs::write(&path, serde_json::to_vec_pretty(body).unwrap()).unwrap();
        path
    }

    #[test]
    fn prepare_then_apply_round_trip_appends_rules() {
        let s = session();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let doc = serde_json::json!({
            "name": "test",
            "denied-remote-domains": ["a.example", "b.example"]
        });
        write_lsrules_file(&root, "test", &doc);

        let current = empty_model();
        let prep = prepare_pure(&s, "test", &root, &current, 501, FIXED_NOW).unwrap();
        assert_eq!(prep.rules_to_add, 2);

        let folded = apply_pure("test", prep.token, &root, &current, &s, 501, FIXED_NOW).unwrap();
        assert_eq!(folded.rules.len(), 2);
        assert_eq!(folded.rules[0].action, Action::Deny);
    }

    #[test]
    fn missing_file_refused_at_prepare() {
        let s = session();
        let dir = tempfile::tempdir().unwrap();
        let current = empty_model();
        let err =
            prepare_pure(&s, "nonexistent", dir.path(), &current, 501, FIXED_NOW).unwrap_err();
        assert!(matches!(err, ApplyLsrulesError::FileNotFound(_)));
    }

    #[test]
    fn malformed_json_refused() {
        let s = session();
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::write(rules_dir.join("bad.lsrules"), b"not json").unwrap();

        let current = empty_model();
        let err = prepare_pure(&s, "bad", dir.path(), &current, 501, FIXED_NOW).unwrap_err();
        assert!(matches!(err, ApplyLsrulesError::InvalidJson { .. }));
    }

    #[test]
    fn diff_drift_when_file_changes_between_prepare_and_apply() {
        let s = session();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let doc1 = serde_json::json!({
            "name": "test",
            "denied-remote-domains": ["a.example"]
        });
        write_lsrules_file(root, "test", &doc1);

        let current = empty_model();
        let prep = prepare_pure(&s, "test", root, &current, 501, FIXED_NOW).unwrap();

        // Tamper with the file between prepare and apply.
        let doc2 = serde_json::json!({
            "name": "test",
            "denied-remote-domains": ["a.example", "b.example", "c.example"]
        });
        write_lsrules_file(root, "test", &doc2);

        let err = apply_pure("test", prep.token, root, &current, &s, 501, FIXED_NOW).unwrap_err();
        assert!(matches!(
            err,
            ApplyLsrulesError::Token(TokenError::DiffDrift)
        ));
    }

    #[test]
    fn replay_rejected() {
        let s = session();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let doc = serde_json::json!({
            "name": "test",
            "denied-remote-domains": ["x.example"]
        });
        write_lsrules_file(root, "test", &doc);
        let current = empty_model();
        let prep = prepare_pure(&s, "test", root, &current, 501, FIXED_NOW).unwrap();

        apply_pure(
            "test",
            prep.token.clone(),
            root,
            &current,
            &s,
            501,
            FIXED_NOW,
        )
        .unwrap();
        let err = apply_pure("test", prep.token, root, &current, &s, 501, FIXED_NOW).unwrap_err();
        assert!(matches!(err, ApplyLsrulesError::Token(TokenError::Replay)));
    }

    #[test]
    fn rules_to_add_count_matches_translated_length() {
        let s = session();
        let dir = tempfile::tempdir().unwrap();
        let doc = serde_json::json!({
            "name": "test",
            "rules": [
                {"action": "allow", "process": "/bin/ls", "remote": "any"},
                {"action": "deny", "process": "any", "remote-domains": "x.example"}
            ],
            "denied-remote-domains": ["a.example", "b.example"],
            "denied-remote-hosts": ["h.example"]
        });
        write_lsrules_file(dir.path(), "test", &doc);
        let current = empty_model();
        let prep = prepare_pure(&s, "test", dir.path(), &current, 501, FIXED_NOW).unwrap();
        assert_eq!(prep.rules_to_add, 2 + 2 + 1); // 2 rules + 2 domain shorthand + 1 host shorthand
    }
}
