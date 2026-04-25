//! Rule and rule-related types for the Little Snitch live model.
//!
//! Empirically reverse-engineered from a real user-created LS 6.3.3 rule —
//! see [docs/feasibility-report.md](../../../docs/feasibility-report.md).
//!
//! # Process and remote matchers
//!
//! A rule has at most one *process matcher* and at most one *remote matcher*.
//! These are kept as flat optional fields rather than discriminated enums so
//! that round-trip preservation is mechanically obvious — every JSON key has
//! a direct field or lands in `extra`. Construction-time validation ("exactly
//! one matcher set") happens in the rule constructor, not the type.
//!
//! # LS-managed fields
//!
//! Fields marked `LS-managed` (`factory_id`, `protected`, `last_used`,
//! `use_count`, `approved`, `hidden`, `factory_help_text`, `owner`) MUST NOT
//! be set on rules the MCP creates from scratch. They appear on factory and
//! aged rules and are managed by LS itself; manipulating them risks corrupting
//! LS's factory-update path. Round-trip preserves them verbatim.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// What action a rule takes when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Ask,
}

/// Connection direction. Absent in JSON means [`Direction::Outgoing`] (LS
/// default); the constructor omits the field when set to outgoing to match
/// LS's own emit shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}

/// Rule priority. Absent means [`Priority::Regular`] (LS default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Regular,
    High,
}

/// Where the rule came from.
///
/// Empirically observed values so far: `frontend` (GUI-created),
/// `factory` (presumed for factory-shipped rules; not in fixture set).
/// Other values may exist; we round-trip unknown values via `String` rather
/// than locking down a strict enum prematurely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Origin(pub String);

impl Origin {
    pub const FRONTEND: &'static str = "frontend";
    pub const FACTORY: &'static str = "factory";

    pub fn frontend() -> Self {
        Self(Self::FRONTEND.into())
    }
}

/// A value that may be a single string or an array of strings.
///
/// LS stores `remote-domains` (and friends) as a bare string when there is
/// exactly one entry, and as an array when there are multiple. The constructor
/// for new rules picks the form based on entry count to match LS's emit shape.
///
/// `serde(untagged)` deserializes either form; serialization preserves the
/// variant we originally parsed (or constructed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    /// Build the canonical form: bare string for a single entry, array
    /// otherwise. Empty inputs return `Many(vec![])` rather than panic.
    pub fn from_entries<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let items: Vec<String> = entries.into_iter().map(Into::into).collect();
        if items.len() == 1 {
            Self::One(items.into_iter().next().expect("len == 1"))
        } else {
            Self::Many(items)
        }
    }

    /// View as a slice-like iterator regardless of underlying form.
    pub fn iter(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::One(s) => Box::new(std::iter::once(s.as_str())),
            Self::Many(v) => Box::new(v.iter().map(String::as_str)),
        }
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.iter().any(|s| s == needle)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An entry in one of the `disabled*InLists` overlay arrays.
///
/// Empirically these arrays are empty on a fresh install; the exact element
/// shape is not yet captured. Modeling as a free-form JSON value keeps the
/// round-trip safe until a real fixture is available.
pub type RemoteOverlayEntry = serde_json::Value;

/// A single rule from `Model::rules`.
///
/// All fields except `action` are optional from a deserialization standpoint;
/// constructor functions in the safety layer enforce "exactly one process
/// matcher" and "exactly one remote matcher" at construction time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub action: Action,

    /// ISO-8601 UTC ("YYYY-MM-DDThh:mm:ssZ"). NOT NSDate seconds.
    #[serde(rename = "creationDate")]
    pub creation_date: String,

    #[serde(rename = "modificationDate")]
    pub modification_date: String,

    /// Where the rule came from (e.g., `"frontend"` for GUI / MCP-authored).
    pub origin: Origin,

    /// User UID for per-user-scoped rules. Required for rules the MCP creates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    // ── process matcher (one of) ──────────────────────────────────────────
    /// Path to executable, or the literal string `"any"`, or code-id format
    /// `TEAMID/identifier`. Mutually exclusive with
    /// [`Rule::requires_trusted_signature_for_any_process`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,

    /// Match any process bearing a valid code signature. Used for system-level
    /// rules (e.g., DNS resolver). Mutually exclusive with `process`.
    #[serde(
        rename = "requiresTrustedSignatureForAnyProcess",
        skip_serializing_if = "Option::is_none"
    )]
    pub requires_trusted_signature_for_any_process: Option<bool>,

    // ── remote matcher (one of) ───────────────────────────────────────────
    /// Special remote values: `"any"`, `"local-net"`, `"multicast"`,
    /// `"broadcast"`, `"bonjour"`, `"dns-servers"`, `"bpf"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,

    #[serde(rename = "remote-domains", skip_serializing_if = "Option::is_none")]
    pub remote_domains: Option<StringOrVec>,

    #[serde(rename = "remote-hosts", skip_serializing_if = "Option::is_none")]
    pub remote_hosts: Option<StringOrVec>,

    #[serde(rename = "remote-addresses", skip_serializing_if = "Option::is_none")]
    pub remote_addresses: Option<StringOrVec>,

    // ── refinements ───────────────────────────────────────────────────────
    /// Absent means outgoing (LS default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,

    /// Absent means regular (LS default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,

    /// Numeric (`"6"`) or named (`"tcp"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// `"any"`, single (`"443"`), or range (`"123-456"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,

    /// Helper-process scope: rule applies only when the process is invoked
    /// via the named helper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,

    /// User-supplied annotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// ID of the [`crate::model::Group`] this rule belongs to.
    /// Loose rules omit this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    // ── LS-managed (must NOT be set on MCP-created rules) ─────────────────
    /// Set by LS for factory-shipped rules. Mutating breaks
    /// `update-rule-groups`. Round-trip preserves verbatim.
    #[serde(rename = "factoryID", skip_serializing_if = "Option::is_none")]
    pub factory_id: Option<String>,

    #[serde(rename = "factoryHelpText", skip_serializing_if = "Option::is_none")]
    pub factory_help_text: Option<String>,

    /// LS's "don't accidentally delete" guard. Mutation refused without strong
    /// ack at the tool layer (per ADR-0004 §10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,

    #[serde(rename = "lastUsed", skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,

    #[serde(rename = "useCount", skip_serializing_if = "Option::is_none")]
    pub use_count: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    // ── forward-compat ────────────────────────────────────────────────────
    /// Any LS-emitted fields not yet known to this version of the MCP.
    /// Preserved verbatim across round-trip.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Rule {
    /// Number of process matchers set. Construction is valid iff this returns
    /// exactly 1; the safety layer enforces this when building new rules.
    pub fn process_matcher_count(&self) -> usize {
        let mut n = 0;
        if self.process.is_some() {
            n += 1;
        }
        if self.requires_trusted_signature_for_any_process == Some(true) {
            n += 1;
        }
        n
    }

    /// Number of remote matchers set. Same construction invariant applies.
    pub fn remote_matcher_count(&self) -> usize {
        let mut n = 0;
        if self.remote.is_some() {
            n += 1;
        }
        if self.remote_domains.is_some() {
            n += 1;
        }
        if self.remote_hosts.is_some() {
            n += 1;
        }
        if self.remote_addresses.is_some() {
            n += 1;
        }
        n
    }

    /// True if mutating this rule should require strong acknowledgement —
    /// per ADR-0004 §8 (rule-level guards).
    pub fn requires_strong_ack_to_mutate(&self) -> bool {
        self.protected == Some(true)
            || self.factory_id.is_some()
            || self.requires_trusted_signature_for_any_process == Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_or_vec_canonicalizes_single_to_one() {
        match StringOrVec::from_entries(["only.example"]) {
            StringOrVec::One(s) => assert_eq!(s, "only.example"),
            StringOrVec::Many(_) => panic!("single entry should be One"),
        }
    }

    #[test]
    fn string_or_vec_canonicalizes_multi_to_many() {
        match StringOrVec::from_entries(["a", "b"]) {
            StringOrVec::Many(v) => assert_eq!(v, vec!["a", "b"]),
            StringOrVec::One(_) => panic!("multi entry should be Many"),
        }
    }

    #[test]
    fn string_or_vec_iter_works_for_both_variants() {
        let one = StringOrVec::One("x".into());
        let many = StringOrVec::Many(vec!["a".into(), "b".into()]);
        assert_eq!(one.iter().collect::<Vec<_>>(), vec!["x"]);
        assert_eq!(many.iter().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn process_matcher_count_zero_one_two() {
        let rule = sample();
        assert_eq!(rule.process_matcher_count(), 1);

        let mut both = rule.clone();
        both.requires_trusted_signature_for_any_process = Some(true);
        assert_eq!(both.process_matcher_count(), 2);

        let mut none = rule;
        none.process = None;
        assert_eq!(none.process_matcher_count(), 0);
    }

    #[test]
    fn requires_strong_ack_for_protected() {
        let mut r = sample();
        r.protected = Some(true);
        assert!(r.requires_strong_ack_to_mutate());
    }

    #[test]
    fn requires_strong_ack_for_factory_id() {
        let mut r = sample();
        r.factory_id = Some("AcmeFactory".into());
        assert!(r.requires_strong_ack_to_mutate());
    }

    fn sample() -> Rule {
        Rule {
            action: Action::Ask,
            creation_date: "2026-04-25T17:34:31Z".into(),
            modification_date: "2026-04-25T17:34:31Z".into(),
            origin: Origin::frontend(),
            uid: Some(501),
            process: Some("/bin/test".into()),
            requires_trusted_signature_for_any_process: None,
            remote: None,
            remote_domains: Some(StringOrVec::One("lsmcp-test.invalid".into())),
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
}
