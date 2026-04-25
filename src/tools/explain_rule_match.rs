//! `explain_rule_match` — given a connection query, return the rule
//! LS would have matched and why.
//!
//! Wraps [`crate::model::matcher::match_rule`]. The tool's response
//! carries an explicit `simulator_status` field so callers know the
//! answer is provisional pending live-LS verification (see the
//! matcher module's docs).

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::matcher::{ConnectionQuery, DecidingKey, RuleMatch, match_rule};
use crate::model::{Action, Direction, Model, Priority};

/// Tool input.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplainRuleMatchArgs {
    /// Process initiating the would-be connection (absolute path).
    pub process: String,
    /// Remote hostname (resolved from IP if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_hostname: Option<String>,
    /// Remote IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Destination port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `"outgoing"` (default), `"incoming"`, or `"both"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// `"tcp"`, `"udp"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Tool response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainRuleMatchResult {
    /// **Read this first.** The simulator implements the spike-#6
    /// algorithm but its specificity weights and tiebreakers have
    /// NOT been verified against live LS behavior. For production
    /// decisions, validate the answer against `little-snitch` itself.
    pub simulator_status: &'static str,
    /// Provenance warning, surfaced verbatim in every response.
    pub warning: &'static str,
    /// Whether a rule matched.
    pub matched: bool,
    /// Index of the matched rule in `model.rules`. None if no match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    /// Action LS would take. None if no match (LS falls back to its default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Human-readable explanation.
    pub explanation: String,
}

const SIMULATOR_STATUS: &str = "unverified-against-live-ls";
const SIMULATOR_WARNING: &str = "This answer is computed by a simulator implementing the documented LS rule-matching \
     algorithm. The specificity weights and tiebreakers have NOT been verified against \
     live LS behavior — for production decisions, run `little-snitch rules-list` and \
     validate manually. Track verification at https://github.com/torsday/little-snitch-mcp/issues/29.";

/// Run the tool. `model` is the snapshot the operator wants to query
/// against (typically the live model from `littlesnitch://model`).
pub fn run(args: ExplainRuleMatchArgs, model: &Model) -> ExplainRuleMatchResult {
    let direction = parse_direction(args.direction.as_deref());
    let query = ConnectionQuery {
        process: &args.process,
        remote_hostname: args.remote_hostname.as_deref(),
        remote_ip: args.remote_ip.as_deref(),
        port: args.port,
        direction,
        protocol: args.protocol.as_deref(),
    };

    match match_rule(model, &query) {
        Some(m) => ExplainRuleMatchResult {
            simulator_status: SIMULATOR_STATUS,
            warning: SIMULATOR_WARNING,
            matched: true,
            rule_index: Some(m.index),
            action: Some(action_str(m.action).to_string()),
            explanation: explain(&m, &args),
        },
        None => ExplainRuleMatchResult {
            simulator_status: SIMULATOR_STATUS,
            warning: SIMULATOR_WARNING,
            matched: false,
            rule_index: None,
            action: None,
            explanation: format!(
                "No rule applied to the query: process={:?}, remote_hostname={:?}, \
                 remote_ip={:?}, port={:?}, direction={:?}. LS would fall back to its \
                 default policy (typically: ask, then deny if unanswered).",
                args.process, args.remote_hostname, args.remote_ip, args.port, args.direction
            ),
        },
    }
}

fn parse_direction(s: Option<&str>) -> Direction {
    match s {
        Some("incoming") => Direction::Incoming,
        Some("both") => Direction::Both,
        _ => Direction::Outgoing,
    }
}

fn action_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Ask => "ask",
    }
}

fn priority_str(p: Priority) -> &'static str {
    match p {
        Priority::High => "high",
        Priority::Regular => "regular",
    }
}

fn deciding_key_str(k: DecidingKey) -> &'static str {
    match k {
        DecidingKey::PriorityTier => "priority tier",
        DecidingKey::SpecificityScore => "specificity score",
        DecidingKey::GroupPrecedence => "group precedence",
        DecidingKey::DeclarationOrder => "declaration order (earlier rule wins)",
    }
}

fn explain(m: &RuleMatch, args: &ExplainRuleMatchArgs) -> String {
    let mut s = format!(
        "Rule at index {} matched. Action: {}.\n\nWhy:\n  - Priority tier: {}\n  - Specificity score: {}",
        m.index,
        action_str(m.action),
        priority_str(m.why.priority),
        m.why.specificity_score,
    );
    if let Some(key) = m.why.deciding_key {
        s.push_str(&format!(
            "\n  - Decided over the next-best rule by: {}",
            deciding_key_str(key)
        ));
    } else {
        s.push_str("\n  - No other rule was applicable to this query.");
    }
    s.push_str(&format!(
        "\n\nQuery: process={}, remote_hostname={:?}, remote_ip={:?}, port={:?}",
        args.process, args.remote_hostname, args.remote_ip, args.port
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Origin, Rule, StringOrVec};
    use std::collections::HashMap;

    fn empty_model() -> Model {
        serde_json::from_value(serde_json::json!({
            "bundleVersion": 1, "factoryRuleSetVersion": 1,
            "rules": [], "groups": {}, "profiles": {},
            "noProfilePseudoProfile": null, "globalDefaults": {},
            "users": [], "codeRequirements": {}, "developerTeamNames": {},
            "lastSeenExecutableByCodeIdentifier": {}, "networkTriggers": [],
            "blocklistStatistics": null, "disabledDomainsInLists": [],
            "disabledHostNamesInLists": [], "disabledIPAddressRangesInLists": []
        }))
        .unwrap()
    }

    fn allow_any_rule() -> Rule {
        Rule {
            action: Action::Allow,
            creation_date: "2026-01-01T00:00:00Z".into(),
            modification_date: "2026-01-01T00:00:00Z".into(),
            origin: Origin::frontend(),
            uid: Some(501),
            process: Some("any".into()),
            requires_trusted_signature_for_any_process: None,
            remote: Some("any".into()),
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

    fn args(process: &str, remote: &str) -> ExplainRuleMatchArgs {
        ExplainRuleMatchArgs {
            process: process.into(),
            remote_hostname: Some(remote.into()),
            remote_ip: None,
            port: None,
            direction: None,
            protocol: None,
        }
    }

    #[test]
    fn match_returns_provisional_status() {
        let mut m = empty_model();
        m.rules.push(allow_any_rule());
        let r = run(args("/usr/bin/curl", "example.com"), &m);
        assert_eq!(r.simulator_status, "unverified-against-live-ls");
        assert!(r.warning.contains("NOT been verified against"));
        assert!(r.matched);
        assert_eq!(r.action.as_deref(), Some("allow"));
    }

    #[test]
    fn no_match_still_carries_provenance_warning() {
        let m = empty_model();
        let r = run(args("/usr/bin/curl", "example.com"), &m);
        assert_eq!(r.simulator_status, "unverified-against-live-ls");
        assert!(r.warning.contains("NOT been verified against"));
        assert!(!r.matched);
        assert!(r.action.is_none());
        assert!(r.explanation.contains("No rule applied"));
    }

    #[test]
    fn explanation_names_the_priority_tier_and_score() {
        let mut m = empty_model();
        m.rules.push(allow_any_rule());
        let r = run(args("/usr/bin/curl", "example.com"), &m);
        assert!(r.explanation.contains("Priority tier: regular"));
        assert!(r.explanation.contains("Specificity score:"));
    }

    #[test]
    fn explanation_names_deciding_key_when_multiple_apply() {
        let mut m = empty_model();
        // Two equivalent allow-any rules — declaration order decides.
        m.rules.push(allow_any_rule());
        m.rules.push(allow_any_rule());
        let r = run(args("/usr/bin/curl", "example.com"), &m);
        assert_eq!(r.rule_index, Some(0));
        assert!(r.explanation.contains("declaration order"));
    }

    #[test]
    fn explanation_says_no_other_when_only_one_applies() {
        let mut m = empty_model();
        m.rules.push(allow_any_rule());
        let r = run(args("/usr/bin/curl", "example.com"), &m);
        assert!(r.explanation.contains("No other rule was applicable"));
    }

    #[test]
    fn warning_links_to_verification_issue() {
        let m = empty_model();
        let r = run(args("/usr/bin/curl", "example.com"), &m);
        assert!(
            r.warning.contains("issues/29"),
            "warning must point operators at the verification ticket: {}",
            r.warning
        );
    }

    #[test]
    fn parse_direction_defaults_to_outgoing() {
        assert_eq!(parse_direction(None), Direction::Outgoing);
        assert_eq!(parse_direction(Some("garbage")), Direction::Outgoing);
        assert_eq!(parse_direction(Some("incoming")), Direction::Incoming);
        assert_eq!(parse_direction(Some("both")), Direction::Both);
    }

    #[test]
    fn explain_handles_remote_addresses_match() {
        let mut m = empty_model();
        let mut r = allow_any_rule();
        r.remote = None;
        r.remote_addresses = Some(StringOrVec::One("10.0.0.1".into()));
        m.rules.push(r);

        let mut a = args("/usr/bin/curl", "ignored");
        a.remote_hostname = None;
        a.remote_ip = Some("10.0.0.1".into());

        let result = run(a, &m);
        assert!(result.matched);
        assert_eq!(result.action.as_deref(), Some("allow"));
    }
}
