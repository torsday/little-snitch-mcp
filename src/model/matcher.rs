//! Rule-matching simulator: given a model and a connection query,
//! return the rule LS would have matched.
//!
//! Implements the algorithm settled by spike #6
//! ([docs/spikes/2026-04-rule-matching-simulator.md](../../../docs/spikes/2026-04-rule-matching-simulator.md))
//! — filter-then-rank pipeline with a 4-key total order:
//!
//! 1. **Priority tier** (`high` > absent/`regular` > `low`)
//! 2. **Specificity score** (sum of contributions from 11 dimensions)
//! 3. **Group precedence** (lower `position` wins; for now, every group
//!    treated as equal precedence — see "What's not yet pinned")
//! 4. **Declaration order** (earlier `model.rules` index wins)
//!
//! # PROVENANCE — important
//!
//! **The specificity weights and tiebreakers in this module have NOT
//! been verified against live LS behavior.** Spike #6 enumerated the
//! design and the 20-fixture validation set; this module implements
//! the design and covers ~half of those fixtures with synthetic
//! assertions (no LS round-trip). Consumers (`tools::explain_rule_match`)
//! surface this status in their response so an operator using the
//! tool for a production decision knows the answer is provisional.
//!
//! Live verification is its own follow-up ticket. Once the verification
//! work runs, this module's docs flip from "unverified" to
//! "verified against LS X.Y.Z".
//!
//! # What's not yet pinned
//!
//! - Group precedence weight is currently a no-op (all rules equal at
//!   key 3). LS's actual group ordering needs probing against a model
//!   with multiple non-default groups.
//! - The 11 specificity dimensions have integer weights chosen so that
//!   "process specificity dominates remote specificity" holds at the
//!   examples in spike #6, but the absolute integers are educated
//!   guesses that may need tuning.
//! - Domain parent-matching is implemented as suffix-with-label-boundary
//!   (`example.com` matches `api.example.com` but not `notexample.com`)
//!   per the spike's rumored-but-unverified semantics.

use crate::model::{Action, Direction, Priority, Rule, StringOrVec};

/// What we're asking about: would-be connection details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionQuery<'a> {
    /// Process initiating the connection — match against `Rule.process`.
    /// Pass the absolute path; "any" is reserved for the rule side.
    pub process: &'a str,
    /// Remote hostname (resolved from the IP if available).
    pub remote_hostname: Option<&'a str>,
    /// Remote IP as a string (for `remote-addresses` matching).
    pub remote_ip: Option<&'a str>,
    /// Destination port (for `Rule.ports` matching). None = "don't filter".
    pub port: Option<u16>,
    /// Direction of the would-be connection.
    pub direction: Direction,
    /// Protocol (`tcp`, `udp`, etc.). None = "don't filter".
    pub protocol: Option<&'a str>,
}

/// A rule that matched the query, with the metadata callers need to
/// explain why.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatch<'a> {
    /// Index into `model.rules` of the matched rule.
    pub index: usize,
    /// The matched rule itself (borrowed from the model).
    pub rule: &'a Rule,
    /// The action LS would take.
    pub action: Action,
    /// Human-readable explanation: which guards passed, what the
    /// specificity score was, which tiebreaker decided.
    pub why: MatchWhy,
}

/// Structured explanation of why this rule won.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchWhy {
    /// Sum of specificity contributions (key 2 of the rank order).
    pub specificity_score: i32,
    /// Priority tier of the matched rule.
    pub priority: Priority,
    /// Which key of the 4-key total order decided over the next
    /// candidate. `None` if no other rule was applicable.
    pub deciding_key: Option<DecidingKey>,
}

/// Which key in the 4-key total order broke the tie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecidingKey {
    PriorityTier,
    SpecificityScore,
    GroupPrecedence,
    DeclarationOrder,
}

/// Run the matcher. Returns `None` when no rule applies (LS would
/// fall back to its default policy).
pub fn match_rule<'a>(
    model: &'a crate::model::Model,
    query: &ConnectionQuery,
) -> Option<RuleMatch<'a>> {
    // Step 1: filter to applicable rules.
    let mut applicable: Vec<(usize, &Rule, i32)> = model
        .rules
        .iter()
        .enumerate()
        .filter_map(|(idx, r)| {
            if rule_applies(r, query, model) {
                Some((idx, r, specificity_score(r)))
            } else {
                None
            }
        })
        .collect();

    if applicable.is_empty() {
        return None;
    }

    // Step 2: rank. Stable sort so equal keys preserve declaration order.
    // We sort descending: higher score = better.
    applicable.sort_by(|a, b| {
        rank_key(a.1, a.2, a.0)
            .cmp(&rank_key(b.1, b.2, b.0))
            .reverse()
    });

    let (winner_idx, winner_rule, winner_score) = applicable[0];
    let deciding_key = if applicable.len() > 1 {
        Some(deciding_key_between(
            (winner_rule, winner_score, winner_idx),
            (applicable[1].1, applicable[1].2, applicable[1].0),
        ))
    } else {
        None
    };

    Some(RuleMatch {
        index: winner_idx,
        rule: winner_rule,
        action: winner_rule.action,
        why: MatchWhy {
            specificity_score: winner_score,
            priority: winner_rule.priority.unwrap_or(Priority::Regular),
            deciding_key,
        },
    })
}

/// True if `rule` could match `query` per the per-field rules from
/// spike #6.
fn rule_applies(rule: &Rule, query: &ConnectionQuery, model: &crate::model::Model) -> bool {
    // disabled rules never apply
    if let Some(g) = &rule.group {
        if let Some(group) = model.groups.get(g) {
            if group.is_active == Some(false) {
                return false;
            }
        }
    }

    // process match
    if !process_matches(rule, query.process) {
        return false;
    }

    // remote match — at least one remote field must agree
    if !remote_matches(rule, query) {
        return false;
    }

    // direction match (absent → outgoing default per LS)
    let rule_direction = rule.direction.unwrap_or(Direction::Outgoing);
    match (rule_direction, query.direction) {
        (Direction::Both, _) | (_, Direction::Both) => {}
        (a, b) if a == b => {}
        _ => return false,
    }

    // protocol match (absent → any)
    if let Some(rule_proto) = &rule.protocol {
        if let Some(query_proto) = query.protocol {
            if rule_proto != query_proto {
                return false;
            }
        }
    }

    // ports match (absent → any). Format support is minimal: exact match
    // or comma-separated list. Range support would require LS-specific
    // parsing; not pinned by spike #6.
    if let Some(rule_ports) = &rule.ports {
        let Some(qport) = query.port else {
            // rule constrains ports but query doesn't supply one — refuse.
            return false;
        };
        if !ports_match(rule_ports, qport) {
            return false;
        }
    }

    true
}

fn process_matches(rule: &Rule, query_process: &str) -> bool {
    if rule.requires_trusted_signature_for_any_process == Some(true) {
        // We don't have signature info in the query — be permissive.
        // A real implementation would consult the binary's signing.
        // Returning true here means "this rule MIGHT match"; production
        // verification would tighten.
        return true;
    }
    match rule.process.as_deref() {
        Some("any") => true,
        Some(p) if p == query_process => true,
        Some(_) => false,
        None => false,
    }
}

fn remote_matches(rule: &Rule, query: &ConnectionQuery) -> bool {
    if rule.remote.as_deref() == Some("any") {
        return true;
    }
    if let Some(special) = rule.remote.as_deref() {
        // Special strings like local-net, multicast, broadcast, bonjour,
        // dns-servers — each needs its own classifier. For now, anything
        // unrecognized is conservatively non-matching (the operator should
        // know if their query targets one of these special categories,
        // and the simulator's job is to flag the gap).
        let _ = special;
        return false;
    }
    if let Some(domains) = &rule.remote_domains {
        if let Some(host) = query.remote_hostname {
            if string_or_vec_iter(domains).any(|d| domain_matches(d, host)) {
                return true;
            }
        }
    }
    if let Some(hosts) = &rule.remote_hosts {
        if let Some(host) = query.remote_hostname {
            if string_or_vec_iter(hosts).any(|h| h.eq_ignore_ascii_case(host)) {
                return true;
            }
        }
    }
    if let Some(addresses) = &rule.remote_addresses {
        if let Some(ip) = query.remote_ip {
            if string_or_vec_iter(addresses).any(|a| a == ip) {
                return true;
            }
        }
    }
    false
}

/// Spike #6: parent-domain matching with label boundary.
/// `example.com` matches `api.example.com` but not `notexample.com`.
fn domain_matches(rule_domain: &str, query_host: &str) -> bool {
    let rule = rule_domain.trim_start_matches('.').to_ascii_lowercase();
    let query = query_host.to_ascii_lowercase();
    if rule == query {
        return true;
    }
    if let Some(suffix) = query.strip_suffix(&rule) {
        suffix.ends_with('.')
    } else {
        false
    }
}

fn ports_match(rule_ports: &str, query_port: u16) -> bool {
    rule_ports
        .split(',')
        .map(str::trim)
        .any(|p| p.parse::<u16>().ok() == Some(query_port))
}

fn string_or_vec_iter(s: &StringOrVec) -> Box<dyn Iterator<Item = &str> + '_> {
    match s {
        StringOrVec::One(s) => Box::new(std::iter::once(s.as_str())),
        StringOrVec::Many(v) => Box::new(v.iter().map(|s| s.as_str())),
    }
}

fn specificity_score(rule: &Rule) -> i32 {
    let mut score = 0;

    // Process side.
    if rule.requires_trusted_signature_for_any_process == Some(true) {
        score += 3;
    } else {
        match rule.process.as_deref() {
            Some("any") => {}
            Some(_) => score += 5,
            None => {}
        }
    }

    // Remote side — the most-specific matching field wins, but we sum
    // all populated fields' baseline scores so a multi-field rule
    // (e.g. both remote-domains and remote-addresses) ranks above a
    // single-field one of equal type.
    if let Some(_v) = &rule.remote_addresses {
        score += 5;
    }
    if let Some(_v) = &rule.remote_hosts {
        score += 4;
    }
    if let Some(_v) = &rule.remote_domains {
        score += 3;
    }
    if let Some(rem) = rule.remote.as_deref() {
        if rem != "any" {
            score += 1;
        }
    }

    // Constraint dimensions.
    if rule.ports.is_some() {
        score += 1;
    }
    if rule.protocol.is_some() {
        score += 1;
    }
    if rule.direction.is_some() {
        score += 1;
    }

    score
}

/// 4-key total order, packed into a tuple for `cmp`-friendly sorting.
fn rank_key(rule: &Rule, score: i32, declaration_idx: usize) -> (i32, i32, i32, i32) {
    let priority_tier = match rule.priority.unwrap_or(Priority::Regular) {
        Priority::High => 2,
        Priority::Regular => 1,
    };
    // Group precedence is currently a no-op (all rules equal). When LS's
    // group ordering is pinned, lookup `model.groups[rule.group].position`
    // and feed it here negated (lower position wins).
    let group_precedence = 0;
    // Declaration order: lower index wins, so we negate.
    let dec_key = -(declaration_idx as i32);
    (priority_tier, score, group_precedence, dec_key)
}

fn deciding_key_between(a: (&Rule, i32, usize), b: (&Rule, i32, usize)) -> DecidingKey {
    let ka = rank_key(a.0, a.1, a.2);
    let kb = rank_key(b.0, b.1, b.2);
    if ka.0 != kb.0 {
        DecidingKey::PriorityTier
    } else if ka.1 != kb.1 {
        DecidingKey::SpecificityScore
    } else if ka.2 != kb.2 {
        DecidingKey::GroupPrecedence
    } else {
        DecidingKey::DeclarationOrder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Model, Origin, Rule};
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

    fn rule(action: Action) -> Rule {
        Rule {
            action,
            creation_date: "2026-01-01T00:00:00Z".into(),
            modification_date: "2026-01-01T00:00:00Z".into(),
            origin: Origin::frontend(),
            uid: Some(501),
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

    fn allow_any() -> Rule {
        let mut r = rule(Action::Allow);
        r.process = Some("any".into());
        r.remote = Some("any".into());
        r
    }

    fn outgoing_query<'a>(process: &'a str, host: &'a str) -> ConnectionQuery<'a> {
        ConnectionQuery {
            process,
            remote_hostname: Some(host),
            remote_ip: None,
            port: None,
            direction: Direction::Outgoing,
            protocol: None,
        }
    }

    // ---------- spike-#6 fixture set (synthetic, unverified-against-LS) ----------

    /// Fixture 1: trivial allow.
    #[test]
    fn fixture_01_trivial_allow() {
        let mut m = empty_model();
        m.rules.push(allow_any());
        let q = outgoing_query("/usr/bin/curl", "example.com");
        let result = match_rule(&m, &q).unwrap();
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.index, 0);
    }

    /// Fixture 2: trivial deny.
    #[test]
    fn fixture_02_trivial_deny() {
        let mut m = empty_model();
        let mut r = rule(Action::Deny);
        r.process = Some("any".into());
        r.remote = Some("any".into());
        m.rules.push(r);
        let q = outgoing_query("/usr/bin/curl", "example.com");
        let result = match_rule(&m, &q).unwrap();
        assert_eq!(result.action, Action::Deny);
    }

    /// Fixture 3: empty model returns None.
    #[test]
    fn fixture_03_empty_model_no_match() {
        let m = empty_model();
        let q = outgoing_query("/usr/bin/curl", "example.com");
        assert!(match_rule(&m, &q).is_none());
    }

    /// Fixture 4: priority tier — high deny beats regular allow on same target.
    #[test]
    fn fixture_04_priority_tier_high_deny_wins() {
        let mut m = empty_model();

        let mut allow = rule(Action::Allow);
        allow.process = Some("any".into());
        allow.remote_domains = Some(StringOrVec::One("mail.example".into()));
        m.rules.push(allow);

        let mut deny = rule(Action::Deny);
        deny.process = Some("any".into());
        deny.remote_domains = Some(StringOrVec::One("mail.example".into()));
        deny.priority = Some(Priority::High);
        m.rules.push(deny);

        let q = outgoing_query("/usr/bin/curl", "mail.example");
        let result = match_rule(&m, &q).unwrap();
        assert_eq!(result.action, Action::Deny);
        assert_eq!(result.why.deciding_key, Some(DecidingKey::PriorityTier));
    }

    /// Fixture 6 (spike #6 numbering): process specificity wins over remote
    /// specificity for a process-specific allow vs. broad-deny scenario.
    #[test]
    fn fixture_06_process_specific_allow_beats_broad_deny() {
        let mut m = empty_model();

        let mut process_allow = rule(Action::Allow);
        process_allow.process = Some("/Applications/Mail.app/Contents/MacOS/Mail".into());
        process_allow.remote = Some("any".into());
        m.rules.push(process_allow);

        let mut broad_deny = rule(Action::Deny);
        broad_deny.process = Some("any".into());
        broad_deny.remote_domains = Some(StringOrVec::One("mail.example".into()));
        m.rules.push(broad_deny);

        // Mail.app reaching mail.example.
        let q = outgoing_query("/Applications/Mail.app/Contents/MacOS/Mail", "mail.example");
        let result = match_rule(&m, &q).unwrap();
        assert_eq!(
            result.action,
            Action::Allow,
            "process-specific allow should win for Mail.app: {result:?}"
        );

        // A different process reaching the same domain — broad-deny applies.
        let q2 = outgoing_query("/usr/bin/curl", "mail.example");
        let result2 = match_rule(&m, &q2).unwrap();
        assert_eq!(result2.action, Action::Deny);
    }

    /// Fixture 8: remote-domains parent matching.
    #[test]
    fn fixture_08_remote_domains_parent_matching() {
        let mut m = empty_model();
        let mut r = rule(Action::Allow);
        r.process = Some("any".into());
        r.remote_domains = Some(StringOrVec::One("example.com".into()));
        m.rules.push(r);
        // api.example.com should match.
        let q = outgoing_query("/usr/bin/curl", "api.example.com");
        assert_eq!(match_rule(&m, &q).unwrap().action, Action::Allow);
        // notexample.com should NOT match (parent matching requires label boundary).
        let q2 = outgoing_query("/usr/bin/curl", "notexample.com");
        assert!(match_rule(&m, &q2).is_none());
    }

    /// Fixture 9: direction filter.
    #[test]
    fn fixture_09_direction_filter() {
        let mut m = empty_model();
        let mut incoming_deny = rule(Action::Deny);
        incoming_deny.process = Some("any".into());
        incoming_deny.remote = Some("any".into());
        incoming_deny.direction = Some(Direction::Incoming);
        m.rules.push(incoming_deny);

        let mut outgoing_allow = rule(Action::Allow);
        outgoing_allow.process = Some("any".into());
        outgoing_allow.remote = Some("any".into());
        m.rules.push(outgoing_allow);

        let q_out = outgoing_query("/usr/bin/curl", "example.com");
        assert_eq!(match_rule(&m, &q_out).unwrap().action, Action::Allow);

        let mut q_in = outgoing_query("/usr/bin/curl", "example.com");
        q_in.direction = Direction::Incoming;
        assert_eq!(match_rule(&m, &q_in).unwrap().action, Action::Deny);
    }

    /// Fixture 10: ports constrain the match.
    #[test]
    fn fixture_10_ports_constrain() {
        let mut m = empty_model();
        let mut allow_587 = rule(Action::Allow);
        allow_587.process = Some("any".into());
        allow_587.remote_domains = Some(StringOrVec::One("mail.example".into()));
        allow_587.ports = Some("587".into());
        m.rules.push(allow_587);

        let mut deny_else = rule(Action::Deny);
        deny_else.process = Some("any".into());
        deny_else.remote_domains = Some(StringOrVec::One("mail.example".into()));
        m.rules.push(deny_else);

        let mut q = outgoing_query("/usr/bin/curl", "mail.example");
        q.port = Some(587);
        assert_eq!(match_rule(&m, &q).unwrap().action, Action::Allow);

        q.port = Some(25);
        assert_eq!(match_rule(&m, &q).unwrap().action, Action::Deny);
    }

    /// Fixture 13: disabled rule never matches.
    #[test]
    fn fixture_13_disabled_group_rule_never_matches() {
        // The serde model doesn't expose a per-rule `disabled` field; LS
        // achieves "disabled rule" via group is_active=false. Test the
        // group-disabled path which spike #6 fixture 14 also covers.
        let mut m = empty_model();
        let mut r = rule(Action::Allow);
        r.process = Some("any".into());
        r.remote = Some("any".into());
        r.group = Some("g1".into());
        m.rules.push(r);

        m.groups.insert(
            "g1".into(),
            crate::model::Group {
                name: Some("disabled-group".into()),
                kind: None,
                kind_legacy: None,
                is_active: Some(false),
                update_interval: None,
                last_update_invalid_domains_count: None,
                extra: HashMap::new(),
            },
        );

        let q = outgoing_query("/usr/bin/curl", "example.com");
        assert!(
            match_rule(&m, &q).is_none(),
            "rule in is_active=false group must not match"
        );
    }

    /// Fixture 16: declaration-order tiebreaker.
    #[test]
    fn fixture_16_declaration_order_tiebreaker() {
        let mut m = empty_model();
        // Two identical rules — the first wins.
        let mut a = rule(Action::Allow);
        a.process = Some("any".into());
        a.remote = Some("any".into());
        m.rules.push(a);

        let mut b = rule(Action::Deny);
        b.process = Some("any".into());
        b.remote = Some("any".into());
        m.rules.push(b);

        let q = outgoing_query("/usr/bin/curl", "example.com");
        let result = match_rule(&m, &q).unwrap();
        assert_eq!(result.index, 0);
        assert_eq!(result.why.deciding_key, Some(DecidingKey::DeclarationOrder));
    }

    // ---------- additional algorithmic invariants ----------

    #[test]
    fn deciding_key_is_none_when_only_one_applies() {
        let mut m = empty_model();
        m.rules.push(allow_any());
        let q = outgoing_query("/usr/bin/curl", "example.com");
        assert_eq!(match_rule(&m, &q).unwrap().why.deciding_key, None);
    }

    #[test]
    fn specificity_score_increases_with_more_constraints() {
        let bare_any = allow_any();
        let mut with_ports = bare_any.clone();
        with_ports.ports = Some("443".into());
        assert!(
            specificity_score(&with_ports) > specificity_score(&bare_any),
            "adding a port constraint must increase specificity"
        );
    }

    #[test]
    fn process_path_specificity_dominates_remote_special() {
        // path-specific rule should have higher score than special-remote rule.
        let mut path_rule = rule(Action::Allow);
        path_rule.process = Some("/Applications/Mail.app".into());
        path_rule.remote = Some("any".into());

        let mut special_rule = rule(Action::Allow);
        special_rule.process = Some("any".into());
        special_rule.remote = Some("local-net".into());

        assert!(
            specificity_score(&path_rule) > specificity_score(&special_rule),
            "process-specific should outrank a special-remote rule"
        );
    }

    #[test]
    fn domain_matches_label_boundary_only() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("example.com", "api.example.com"));
        assert!(!domain_matches("example.com", "notexample.com"));
        assert!(!domain_matches("example.com", "exampleXcom"));
    }

    #[test]
    fn domain_matches_is_case_insensitive() {
        assert!(domain_matches("Example.COM", "API.example.com"));
    }

    #[test]
    fn ports_match_handles_comma_list() {
        assert!(ports_match("443", 443));
        assert!(ports_match("80,443,8080", 443));
        assert!(!ports_match("443", 80));
        assert!(!ports_match("80,443", 8080));
    }
}
