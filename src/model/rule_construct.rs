//! Construct a fresh [`Rule`] from a caller-supplied spec.
//!
//! This module owns the policy that translates "operator wants to add
//! a rule" into the exact JSON shape that `restore-model -t` accepts.
//! The shape itself is empirically locked by smoke-3 in
//! [docs/feasibility-report.md](../../../docs/feasibility-report.md).
//!
//! # What we enforce
//!
//! - **Required fields fill from the spec or from server state.** `action`,
//!   `process` (or `requires_trusted_signature_for_any_process`), exactly
//!   one remote shape, `origin: "frontend"`, `uid` (caller-supplied — see
//!   note), `creation_date`/`modification_date` (now, ISO-8601 UTC).
//! - **Optional fields are passed through as-is**, with one omission rule:
//!   `direction == Outgoing` and `priority == Regular` are dropped to
//!   match LS's own export shape (which omits the defaults).
//! - **Forbidden fields are never set.** The seven LS-managed fields
//!   (`factory_id`, `protected`, `owner`, `last_used`, `use_count`,
//!   `approved`, `hidden`) are unreachable from the spec — the type
//!   doesn't carry them — so the constructor cannot produce them.
//! - **Process-path validation guard ([ADR-0004 §10](../../../docs/adr/0004-safety-permissions-and-confirmation.md)).**
//!   - `ProcessMatcher::Path(p)` is refused when `p` is not the literal
//!     string `"any"` and does not exist on disk.
//!   - The combination `ProcessMatcher::Any` + `Action::Allow` +
//!     `Remote::Any` is refused unconditionally — an "allow everything
//!     to anywhere for any process" rule has no legitimate use and
//!     unambiguously weakens security.
//! - **Single-vs-array normalization.** `remote-domains/hosts/addresses`
//!   serialize as a string for one entry, an array for multiple, per
//!   the `StringOrVec` type — preserving LS's own emit shape so a
//!   round-trip diff is byte-identical to LS's export.
//!
//! # Why `uid` is required, not auto-detected
//!
//! Auto-detecting "current user's uid" requires either a runtime syscall
//! (`libc::getuid`, `nix::unistd::getuid`) — which we'd need to add as a
//! dependency — or a shell-out (`id -u`) — which is fragile under tests.
//! The constructor stays pure by accepting `uid` from the caller; the
//! tool that consumes the constructor (#59 `add_rule_to_live_model`)
//! caches the uid in its server state, fetched once at startup by
//! whatever mechanism that tool prefers.

use std::path::Path;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::model::rule::{Action, Direction, Origin, Priority, Rule, StringOrVec};
use crate::time_fmt::iso8601_utc as format_iso8601_utc;

/// Process side of the rule — exactly one variant must be supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProcessMatcher {
    /// Exact path on disk. The constructor refuses if the path doesn't
    /// exist (per ADR-0004 §10).
    Path(String),
    /// Match any process. May still be subject to the blanket-allow
    /// guard depending on action/remote.
    Any,
    /// Match any process whose code signature is trusted. Encodes as
    /// `requires_trusted_signature_for_any_process: true` in the rule.
    RequiresTrustedSignature,
    /// Match by `code-id` (TEAMID/identifier). Not file-existence
    /// checked; the constructor accepts the string verbatim and lets
    /// LS validate format.
    CodeId(String),
}

/// Remote side of the rule — exactly one variant must be supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Remote {
    /// One or more domains.
    Domains(Vec<String>),
    /// One or more hostnames.
    Hosts(Vec<String>),
    /// One or more IP addresses or CIDR ranges.
    Addresses(Vec<String>),
    /// LS special string (`"any"`, `"local-net"`, `"multicast"`,
    /// `"broadcast"`, `"bonjour"`, `"dns-servers"`).
    Special(String),
    /// Match any remote. Subject to the blanket-allow guard.
    Any,
}

/// Specification the operator hands to [`construct`].
///
/// All optional fields are `Option`-wrapped at the spec level; the
/// constructor decides whether to emit them or omit them per LS's
/// export shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRuleSpec {
    pub action: Action,
    pub process: ProcessMatcher,
    pub remote: Remote,
    pub uid: u32,

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

/// Errors the constructor can return.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConstructError {
    #[error(
        "INVALID_PROCESS_PATH: refused to construct rule — process path {path:?} does not exist on disk \
         (per ADR-0004 §10). Pass an existing path, the literal string \"any\", or a code-id rule."
    )]
    InvalidProcessPath { path: String },

    #[error(
        "BLANKET_ALLOW_REFUSED: refused to construct rule — the combination process=any + \
         action=allow + remote=any has no legitimate use and unambiguously weakens security \
         (per ADR-0004 §10). Scope the rule to a specific process or remote."
    )]
    BlanketAllowRefused,

    #[error(
        "EMPTY_REMOTE_LIST: refused to construct rule — `remote::{kind}` was given an empty list. \
         Provide at least one entry or use Remote::Any if intent is truly unrestricted."
    )]
    EmptyRemoteList { kind: &'static str },

    #[error(
        "EMPTY_CODE_ID: refused to construct rule — process::code_id was given an empty string."
    )]
    EmptyCodeId,
}

/// Build a [`Rule`] from `spec`, sourcing the timestamp from
/// `now_unix_secs`. Pure — no I/O except the path-existence check.
///
/// Filesystem check is intentionally inside this function (not the
/// caller's responsibility) so the ADR-0004 §10 guard is impossible
/// to forget.
pub fn construct_at(spec: NewRuleSpec, now_unix_secs: u64) -> Result<Rule, ConstructError> {
    // ADR-0004 §10: blanket-allow refusal.
    if matches!(spec.process, ProcessMatcher::Any)
        && spec.action == Action::Allow
        && matches!(spec.remote, Remote::Any)
    {
        return Err(ConstructError::BlanketAllowRefused);
    }

    // Process-side fields.
    let (process, requires_trusted_signature_for_any_process) = match spec.process {
        ProcessMatcher::Path(p) => {
            // ADR-0004 §10: refuse non-existent paths (the literal
            // string "any" is not a path; route it through the Any
            // variant instead).
            if p != "any" && !Path::new(&p).exists() {
                return Err(ConstructError::InvalidProcessPath { path: p });
            }
            (Some(p), None)
        }
        ProcessMatcher::Any => (Some("any".to_string()), None),
        ProcessMatcher::RequiresTrustedSignature => (None, Some(true)),
        ProcessMatcher::CodeId(id) => {
            if id.is_empty() {
                return Err(ConstructError::EmptyCodeId);
            }
            // LS's own `code-id` rules go in the `process` field as the
            // identifier string; LS distinguishes them by content shape.
            (Some(id), None)
        }
    };

    // Remote-side fields. Single entry → string form; multiple → array;
    // empty → refused.
    let (remote, remote_domains, remote_hosts, remote_addresses) = match spec.remote {
        Remote::Domains(v) => {
            if v.is_empty() {
                return Err(ConstructError::EmptyRemoteList { kind: "domains" });
            }
            (None, Some(string_or_vec(v)), None, None)
        }
        Remote::Hosts(v) => {
            if v.is_empty() {
                return Err(ConstructError::EmptyRemoteList { kind: "hosts" });
            }
            (None, None, Some(string_or_vec(v)), None)
        }
        Remote::Addresses(v) => {
            if v.is_empty() {
                return Err(ConstructError::EmptyRemoteList { kind: "addresses" });
            }
            (None, None, None, Some(string_or_vec(v)))
        }
        Remote::Special(s) => (Some(s), None, None, None),
        Remote::Any => (Some("any".to_string()), None, None, None),
    };

    // Direction: omit when outgoing (LS default).
    let direction = match spec.direction {
        Some(Direction::Outgoing) | None => None,
        Some(d) => Some(d),
    };

    // Priority: omit when regular (LS default).
    let priority = match spec.priority {
        Some(Priority::Regular) | None => None,
        Some(p) => Some(p),
    };

    let now = format_iso8601_utc(now_unix_secs);

    Ok(Rule {
        action: spec.action,
        creation_date: now.clone(),
        modification_date: now,
        origin: Origin::frontend(),
        uid: Some(spec.uid),

        process,
        requires_trusted_signature_for_any_process,
        remote,
        remote_domains,
        remote_hosts,
        remote_addresses,
        direction,
        priority,
        protocol: spec.protocol,
        ports: spec.ports,
        via: spec.via,
        notes: spec.notes,
        group: spec.group,

        // Forbidden fields — must remain unset on user-created rules.
        // The type doesn't expose setters here; these stay None always.
        factory_id: None,
        factory_help_text: None,
        protected: None,
        last_used: None,
        use_count: None,
        approved: None,
        hidden: None,
        owner: None,

        extra: HashMap::new(),
    })
}

/// Convenience wrapper that sources `now` from the system clock.
///
/// Production paths use this; tests use [`construct_at`] with a fixed
/// timestamp so fixtures are stable.
pub fn construct(spec: NewRuleSpec) -> Result<Rule, ConstructError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    construct_at(spec, now)
}

fn string_or_vec(v: Vec<String>) -> StringOrVec {
    if v.len() == 1 {
        StringOrVec::One(v.into_iter().next().unwrap())
    } else {
        StringOrVec::Many(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-3 timestamp: 2026-04-25T17:43:37Z = 1777139017 unix secs.
    /// This is the exact rule shape LS round-tripped successfully in
    /// scripts/smoke-3-corrected-construction.sh.
    const SMOKE_3_NOW_UNIX: u64 = 1_777_139_017;
    const SMOKE_3_TIMESTAMP_ISO: &str = "2026-04-25T17:43:37Z";

    fn smoke_3_spec() -> NewRuleSpec {
        NewRuleSpec {
            action: Action::Ask,
            // /bin/test exists on every macOS / Linux system smoke-3 ran on.
            process: ProcessMatcher::Path("/bin/test".into()),
            remote: Remote::Domains(vec!["lsmcp-smoke3-1777139017.invalid".into()]),
            uid: 501,
            direction: None,
            priority: None,
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
        }
    }

    #[test]
    fn iso8601_formatter_matches_smoke_3_timestamp() {
        assert_eq!(format_iso8601_utc(SMOKE_3_NOW_UNIX), SMOKE_3_TIMESTAMP_ISO);
    }

    #[test]
    fn smoke_3_round_trip_shape_is_reproduced_exactly() {
        let rule = construct_at(smoke_3_spec(), SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.action, Action::Ask);
        assert_eq!(rule.process.as_deref(), Some("/bin/test"));
        match rule.remote_domains.as_ref().unwrap() {
            StringOrVec::One(s) => assert_eq!(s, "lsmcp-smoke3-1777139017.invalid"),
            StringOrVec::Many(_) => panic!("single domain must serialize as string, not array"),
        }
        assert_eq!(rule.creation_date, SMOKE_3_TIMESTAMP_ISO);
        assert_eq!(rule.modification_date, SMOKE_3_TIMESTAMP_ISO);
        assert_eq!(rule.uid, Some(501));
        assert_eq!(rule.origin.0, Origin::FRONTEND);
        // No LS-managed fields set on a user-created rule (smoke-3 finding):
        assert_eq!(rule.factory_id, None);
        assert_eq!(rule.protected, None);
        assert_eq!(rule.last_used, None);
        assert_eq!(rule.use_count, None);
        // No direction injected (smoke-3 finding):
        assert_eq!(rule.direction, None);
        // No remote_hosts / remote_addresses / remote contention:
        assert_eq!(rule.remote, None);
        assert_eq!(rule.remote_hosts, None);
        assert_eq!(rule.remote_addresses, None);
    }

    #[test]
    fn smoke_3_serializes_with_only_seven_fields() {
        let rule = construct_at(smoke_3_spec(), SMOKE_3_NOW_UNIX).unwrap();
        let json = serde_json::to_value(&rule).unwrap();
        let obj = json.as_object().unwrap();
        // Smoke-3 sent exactly 7 keys; we should match.
        let keys: std::collections::BTreeSet<_> = obj.keys().cloned().collect();
        let expected: std::collections::BTreeSet<String> = [
            "action",
            "process",
            "remote-domains",
            "origin",
            "creationDate",
            "modificationDate",
            "uid",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            keys, expected,
            "rule must serialize to exactly the smoke-3 7-key shape"
        );
    }

    // ---------- ADR-0004 §10 path validation ----------

    #[test]
    fn process_path_must_exist_on_disk() {
        let mut spec = smoke_3_spec();
        spec.process = ProcessMatcher::Path("/definitely/not/a/path/lsmcp-test".into());
        let err = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap_err();
        match err {
            ConstructError::InvalidProcessPath { path } => {
                assert_eq!(path, "/definitely/not/a/path/lsmcp-test");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn process_path_literal_any_passes_through_as_any() {
        // A caller who passes "any" as a Path string should be treated
        // as the Any variant — the ADR refusal is for non-existent paths,
        // not for the well-known "any" sentinel.
        let mut spec = smoke_3_spec();
        spec.process = ProcessMatcher::Path("any".into());
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.process.as_deref(), Some("any"));
    }

    #[test]
    fn process_any_variant_emits_any_string() {
        let mut spec = smoke_3_spec();
        spec.process = ProcessMatcher::Any;
        spec.action = Action::Deny;
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.process.as_deref(), Some("any"));
        assert_eq!(rule.requires_trusted_signature_for_any_process, None);
    }

    #[test]
    fn requires_trusted_signature_emits_no_process_field() {
        let mut spec = smoke_3_spec();
        spec.process = ProcessMatcher::RequiresTrustedSignature;
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.process, None);
        assert_eq!(rule.requires_trusted_signature_for_any_process, Some(true));
    }

    #[test]
    fn code_id_emits_the_id_in_process_field() {
        let mut spec = smoke_3_spec();
        spec.process = ProcessMatcher::CodeId("ABCD1234/com.example".into());
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.process.as_deref(), Some("ABCD1234/com.example"));
    }

    #[test]
    fn code_id_must_not_be_empty() {
        let mut spec = smoke_3_spec();
        spec.process = ProcessMatcher::CodeId(String::new());
        assert_eq!(
            construct_at(spec, SMOKE_3_NOW_UNIX).unwrap_err(),
            ConstructError::EmptyCodeId
        );
    }

    #[test]
    fn blanket_allow_any_any_is_refused() {
        let spec = NewRuleSpec {
            action: Action::Allow,
            process: ProcessMatcher::Any,
            remote: Remote::Any,
            uid: 501,
            direction: None,
            priority: None,
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
        };
        assert_eq!(
            construct_at(spec, SMOKE_3_NOW_UNIX).unwrap_err(),
            ConstructError::BlanketAllowRefused
        );
    }

    #[test]
    fn blanket_deny_any_any_is_allowed() {
        // The refusal is specifically for blanket-ALLOW; a blanket deny
        // is the user's prerogative and is harmless to LS's safety
        // posture.
        let spec = NewRuleSpec {
            action: Action::Deny,
            process: ProcessMatcher::Any,
            remote: Remote::Any,
            uid: 501,
            direction: None,
            priority: None,
            protocol: None,
            ports: None,
            via: None,
            notes: None,
            group: None,
        };
        assert!(construct_at(spec, SMOKE_3_NOW_UNIX).is_ok());
    }

    // ---------- single vs array normalization ----------

    #[test]
    fn single_remote_domain_serializes_as_string() {
        let spec = smoke_3_spec();
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json["remote-domains"],
            serde_json::json!("lsmcp-smoke3-1777139017.invalid")
        );
    }

    #[test]
    fn multiple_remote_domains_serialize_as_array() {
        let mut spec = smoke_3_spec();
        spec.remote = Remote::Domains(vec!["a.invalid".into(), "b.invalid".into()]);
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json["remote-domains"],
            serde_json::json!(["a.invalid", "b.invalid"])
        );
    }

    #[test]
    fn empty_remote_domains_list_is_refused() {
        let mut spec = smoke_3_spec();
        spec.remote = Remote::Domains(vec![]);
        assert_eq!(
            construct_at(spec, SMOKE_3_NOW_UNIX).unwrap_err(),
            ConstructError::EmptyRemoteList { kind: "domains" }
        );
    }

    #[test]
    fn empty_remote_hosts_list_is_refused() {
        let mut spec = smoke_3_spec();
        spec.remote = Remote::Hosts(vec![]);
        assert_eq!(
            construct_at(spec, SMOKE_3_NOW_UNIX).unwrap_err(),
            ConstructError::EmptyRemoteList { kind: "hosts" }
        );
    }

    #[test]
    fn empty_remote_addresses_list_is_refused() {
        let mut spec = smoke_3_spec();
        spec.remote = Remote::Addresses(vec![]);
        assert_eq!(
            construct_at(spec, SMOKE_3_NOW_UNIX).unwrap_err(),
            ConstructError::EmptyRemoteList { kind: "addresses" }
        );
    }

    #[test]
    fn special_remote_serializes_as_string() {
        let mut spec = smoke_3_spec();
        spec.remote = Remote::Special("local-net".into());
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.remote.as_deref(), Some("local-net"));
    }

    // ---------- omit-default discipline ----------

    #[test]
    fn outgoing_direction_is_omitted() {
        let mut spec = smoke_3_spec();
        spec.direction = Some(Direction::Outgoing);
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.direction, None);
    }

    #[test]
    fn explicit_incoming_direction_is_kept() {
        let mut spec = smoke_3_spec();
        spec.direction = Some(Direction::Incoming);
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.direction, Some(Direction::Incoming));
    }

    #[test]
    fn regular_priority_is_omitted() {
        let mut spec = smoke_3_spec();
        spec.priority = Some(Priority::Regular);
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.priority, None);
    }

    #[test]
    fn explicit_high_priority_is_kept() {
        let mut spec = smoke_3_spec();
        spec.priority = Some(Priority::High);
        let rule = construct_at(spec, SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.priority, Some(Priority::High));
    }

    // ---------- forbidden fields stay unset ----------

    #[test]
    fn no_construction_path_sets_forbidden_fields() {
        let rule = construct_at(smoke_3_spec(), SMOKE_3_NOW_UNIX).unwrap();
        assert_eq!(rule.factory_id, None);
        assert_eq!(rule.factory_help_text, None);
        assert_eq!(rule.protected, None);
        assert_eq!(rule.last_used, None);
        assert_eq!(rule.use_count, None);
        assert_eq!(rule.approved, None);
        assert_eq!(rule.hidden, None);
        assert_eq!(rule.owner, None);
    }

    // ---------- public wrapper smoke ----------

    #[test]
    fn construct_wrapper_uses_real_clock() {
        // Just confirm it doesn't panic and produces a parseable timestamp.
        let rule = construct(smoke_3_spec()).unwrap();
        assert!(rule.creation_date.starts_with("20"));
        assert!(rule.creation_date.ends_with('Z'));
        assert_eq!(rule.creation_date.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
    }

    // ---------- iso8601 helper edge cases ----------

    #[test]
    fn iso8601_unix_epoch_is_1970_01_01() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_handles_leap_year_month_boundaries() {
        // 2024-02-29T12:00:00Z = 1709208000
        assert_eq!(format_iso8601_utc(1_709_208_000), "2024-02-29T12:00:00Z");
        // 2025-03-01T00:00:00Z (post-non-leap-year Feb)
        assert_eq!(format_iso8601_utc(1_740_787_200), "2025-03-01T00:00:00Z");
    }
}
