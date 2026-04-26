//! `find_rules_for_remote` — return all rules whose remote matcher covers
//! a given IP address, CIDR, hostname, or domain.
//!
//! Classification: SafeRead — loads the live model via `export-model` and
//! returns a read-only projection; no mutation of LS state.

use ipnet::IpNet;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

use crate::cli::adapter::LsCli;
use crate::model::{Model, Rule, StringOrVec};
use crate::safety::resolver::SEED_KIND_MAP;

// ─── public types ────────────────────────────────────────────────────────────

/// Input for `find_rules_for_remote`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindRulesForRemoteArgs {
    /// Remote to look up. Accepts:
    /// - IPv4 or IPv6 address: `"1.2.3.4"`, `"::1"`
    /// - CIDR range: `"10.0.0.0/8"`, `"2001:db8::/32"`
    /// - Hostname: `"api.example.com"` (exact match against `remote-hosts`)
    /// - Domain: `"example.com"` (suffix match against `remote-domains` — a
    ///   stored domain of `"example.com"` matches `"api.example.com"` and
    ///   `"example.com"` itself)
    pub remote: String,

    /// When true, also return rules whose `remote` field is a special value
    /// (`"any"`, `"local-net"`, `"multicast"`, `"broadcast"`, `"bonjour"`,
    /// `"dns-servers"`, `"bpf"`) — these catch-all rules apply regardless of
    /// remote. Defaults to `false` so the result stays focused.
    #[serde(default)]
    pub include_catch_all: bool,
}

/// How the remote field of a rule matched the query.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Rule's `remote-addresses` contained the queried IP, or the queried IP
    /// fell within a CIDR stored in `remote-addresses`.
    Address,
    /// Rule's `remote-hosts` contained the queried hostname (exact).
    Host,
    /// Rule's `remote-domains` is a suffix of the queried hostname (or an
    /// exact match), or the queried domain is a suffix of a stored domain.
    Domain,
    /// Rule's `remote` field is a special catch-all value (`"any"`, etc.).
    CatchAll,
}

/// A single matched rule, augmented with match metadata and group context.
#[derive(Debug, Serialize)]
pub struct MatchedRule {
    /// Index of the rule in `model.rules` (useful for cross-referencing with
    /// other tools like `get_rules_for_process`).
    pub global_index: usize,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// The raw remote value from the rule that produced the match.
    pub matched_remote: String,
    /// How this rule's remote field matched the query.
    pub match_kind: MatchKind,
    /// Process this rule governs, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    pub creation_date: String,
    pub modification_date: String,
    /// Whether the rule's group is currently active.
    pub group_active: bool,
}

/// A group bucket grouping matched rules.
#[derive(Debug, Serialize)]
pub struct GroupBucket {
    pub group_id: String,
    pub display_name: String,
    pub is_active: bool,
    pub rules: Vec<MatchedRule>,
}

/// Return value of `find_rules_for_remote`.
#[derive(Debug, Serialize)]
pub struct FindRulesForRemoteResult {
    /// The input remote that was queried.
    pub remote: String,
    /// Total number of matching rules across all groups.
    pub total_count: usize,
    /// Rules grouped by assigned group, sorted by display name.
    pub groups: Vec<GroupBucket>,
}

// ─── matching helpers ─────────────────────────────────────────────────────────

/// Parsed form of the query string.
enum QueryKind {
    /// A single IP address.
    Ip(IpAddr),
    /// A CIDR network.
    Net(IpNet),
    /// A hostname or domain (not parseable as an IP/CIDR).
    Name(String),
}

fn parse_query(s: &str) -> QueryKind {
    if let Ok(addr) = IpAddr::from_str(s) {
        return QueryKind::Ip(addr);
    }
    if let Ok(net) = IpNet::from_str(s) {
        return QueryKind::Net(net);
    }
    QueryKind::Name(s.to_ascii_lowercase())
}

/// True if `stored` (an entry from `remote-addresses`) covers the query IP.
///
/// `stored` may be a bare IP (`"1.2.3.4"`) or a CIDR (`"10.0.0.0/8"`).
fn address_covers_ip(stored: &str, query_ip: IpAddr) -> bool {
    if let Ok(net) = IpNet::from_str(stored) {
        return net.contains(&query_ip);
    }
    if let Ok(addr) = IpAddr::from_str(stored) {
        return addr == query_ip;
    }
    false
}

/// True if `stored` (an entry from `remote-addresses`) overlaps with the query
/// CIDR. Covers: subnet of, supernet of, or equal.
fn address_covers_net(stored: &str, query_net: &IpNet) -> bool {
    if let Ok(stored_net) = IpNet::from_str(stored) {
        return stored_net.contains(query_net)
            || query_net.contains(&stored_net)
            || stored_net == *query_net;
    }
    if let Ok(addr) = IpAddr::from_str(stored) {
        // A single IP from the rule: matches if it falls inside the query CIDR.
        return query_net.contains(&addr);
    }
    false
}

/// True if the stored domain suffix covers the query name.
///
/// Little Snitch's domain matching: a stored domain `example.com` covers
/// `example.com` itself and any subdomain (`api.example.com`).
fn domain_covers(stored_domain: &str, query_name: &str) -> bool {
    let d = stored_domain.trim_start_matches('.');
    let q = query_name.trim_start_matches('.');
    q == d || q.ends_with(&format!(".{d}"))
}

/// True if the query domain covers the stored domain (inverse direction:
/// user queries `example.com`, stored is `api.example.com`).
fn query_covers_stored_domain(stored_domain: &str, query_name: &str) -> bool {
    domain_covers(query_name, stored_domain)
}

/// Check whether a rule matches the query, returning the `MatchKind` and the
/// matched remote string if it does.
fn rule_matches(
    rule: &Rule,
    query: &QueryKind,
    include_catch_all: bool,
) -> Option<(MatchKind, String)> {
    match query {
        QueryKind::Ip(ip) => {
            // remote-addresses
            if let Some(addrs) = &rule.remote_addresses {
                for stored in addrs.iter() {
                    if address_covers_ip(stored, *ip) {
                        return Some((MatchKind::Address, stored.to_string()));
                    }
                }
            }
        }
        QueryKind::Net(net) => {
            // remote-addresses
            if let Some(addrs) = &rule.remote_addresses {
                for stored in addrs.iter() {
                    if address_covers_net(stored, net) {
                        return Some((MatchKind::Address, stored.to_string()));
                    }
                }
            }
        }
        QueryKind::Name(name) => {
            // remote-hosts: exact match
            if let Some(hosts) = &rule.remote_hosts {
                for stored in hosts.iter() {
                    if stored.to_ascii_lowercase() == *name {
                        return Some((MatchKind::Host, stored.to_string()));
                    }
                }
            }
            // remote-domains: stored domain covers query, or query covers stored
            if let Some(domains) = &rule.remote_domains {
                for stored in domains.iter() {
                    let stored_lc = stored.to_ascii_lowercase();
                    if domain_covers(&stored_lc, name) || query_covers_stored_domain(&stored_lc, name) {
                        return Some((MatchKind::Domain, stored.to_string()));
                    }
                }
            }
        }
    }

    // catch-all: remote is a special string value
    if include_catch_all {
        if let Some(rem) = &rule.remote {
            return Some((MatchKind::CatchAll, rem.clone()));
        }
    }

    None
}

// ─── group display-name resolution ───────────────────────────────────────────

fn display_name_for(group_id: &str, model: &Model) -> (String, bool) {
    let g = model.groups.get(group_id);
    let name = g
        .and_then(|g| g.name.as_deref())
        .map(|n| n.to_string())
        .or_else(|| {
            g.and_then(|g| g.kind.as_deref().or(g.kind_legacy.as_deref()))
                .and_then(|k| {
                    SEED_KIND_MAP
                        .iter()
                        .find(|(kk, _)| *kk == k)
                        .map(|(_, v)| v.to_string())
                        .or_else(|| Some(k.to_string()))
                })
        })
        .unwrap_or_else(|| group_id.to_string());
    let active = g.and_then(|g| g.is_active).unwrap_or(true);
    (name, active)
}

// ─── public API ───────────────────────────────────────────────────────────────

/// Run the tool against the live model.
pub fn run(args: FindRulesForRemoteArgs) -> Result<FindRulesForRemoteResult, String> {
    if args.remote.is_empty() {
        return Err("remote must not be empty".into());
    }
    let cli = LsCli::resolve().map_err(|e| format!("littlesnitch binary not found: {e}"))?;
    let output = cli
        .run(&["export-model"])
        .map_err(|e| format!("export-model failed: {e}"))?;
    let json_str = String::from_utf8_lossy(&output.stdout);
    let model: Model =
        serde_json::from_str(&json_str).map_err(|e| format!("model JSON invalid: {e}"))?;
    Ok(run_with_model(args, &model))
}

/// Inner implementation — accepts a pre-loaded model for testing.
pub fn run_with_model(args: FindRulesForRemoteArgs, model: &Model) -> FindRulesForRemoteResult {
    let query = parse_query(&args.remote);
    let include_catch_all = args.include_catch_all;

    // Collect (global_index, rule, match_kind, matched_remote).
    let mut matched: Vec<(usize, &Rule, MatchKind, String)> = model
        .rules
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            rule_matches(r, &query, include_catch_all).map(|(kind, rem)| (i, r, kind, rem))
        })
        .collect();

    let total_count = matched.len();

    // Group by group_id.
    let mut by_group: std::collections::HashMap<String, Vec<(usize, &Rule, MatchKind, String)>> =
        std::collections::HashMap::new();
    for item in matched.drain(..) {
        let key = item.1.group.clone().unwrap_or_else(|| "<no-group>".into());
        by_group.entry(key).or_default().push(item);
    }

    let mut groups: Vec<GroupBucket> = by_group
        .into_iter()
        .map(|(group_id, items)| {
            let (display_name, is_active) = if group_id == "<no-group>" {
                ("<no-group>".to_string(), true)
            } else {
                display_name_for(&group_id, model)
            };

            let rules: Vec<MatchedRule> = items
                .into_iter()
                .map(|(global_index, r, match_kind, matched_remote)| MatchedRule {
                    global_index,
                    action: format!("{:?}", r.action).to_lowercase(),
                    direction: r.direction.map(|d| format!("{:?}", d).to_lowercase()),
                    matched_remote,
                    match_kind,
                    process: r.process.clone(),
                    creation_date: r.creation_date.clone(),
                    modification_date: r.modification_date.clone(),
                    group_active: is_active,
                })
                .collect();

            GroupBucket { group_id, display_name, is_active, rules }
        })
        .collect();

    groups.sort_by(|a, b| a.display_name.cmp(&b.display_name));

    FindRulesForRemoteResult {
        remote: args.remote,
        total_count,
        groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_model() -> Model {
        serde_json::from_value(json!({
            "bundleVersion": 7172,
            "factoryRuleSetVersion": 424,
            "rules": [
                // remote-addresses exact IP
                {
                    "action": "deny",
                    "process": "/usr/bin/curl",
                    "remote-addresses": "1.2.3.4",
                    "creationDate": "2026-01-01T00:00:00Z",
                    "modificationDate": "2026-01-01T00:00:00Z",
                    "origin": "frontend",
                    "group": "grp-a"
                },
                // remote-addresses CIDR
                {
                    "action": "allow",
                    "process": "/usr/bin/curl",
                    "remote-addresses": "10.0.0.0/8",
                    "creationDate": "2026-01-02T00:00:00Z",
                    "modificationDate": "2026-01-02T00:00:00Z",
                    "origin": "frontend",
                    "group": "grp-a"
                },
                // remote-hosts exact
                {
                    "action": "allow",
                    "process": "/usr/bin/ssh",
                    "remote-hosts": "api.example.com",
                    "creationDate": "2026-01-03T00:00:00Z",
                    "modificationDate": "2026-01-03T00:00:00Z",
                    "origin": "frontend",
                    "group": "grp-b"
                },
                // remote-domains (stored domain covers subdomain queries)
                {
                    "action": "deny",
                    "process": "/usr/bin/curl",
                    "remote-domains": "example.com",
                    "creationDate": "2026-01-04T00:00:00Z",
                    "modificationDate": "2026-01-04T00:00:00Z",
                    "origin": "frontend"
                },
                // remote = "any" (catch-all)
                {
                    "action": "allow",
                    "process": "/usr/bin/curl",
                    "remote": "any",
                    "creationDate": "2026-01-05T00:00:00Z",
                    "modificationDate": "2026-01-05T00:00:00Z",
                    "origin": "frontend"
                },
                // remote-addresses array (IPv6)
                {
                    "action": "deny",
                    "process": "/usr/bin/curl",
                    "remote-addresses": ["::1", "fe80::/10"],
                    "creationDate": "2026-01-06T00:00:00Z",
                    "modificationDate": "2026-01-06T00:00:00Z",
                    "origin": "frontend",
                    "group": "grp-a"
                }
            ],
            "groups": {
                "grp-a": {"name": "Group A", "isActive": true},
                "grp-b": {"name": "Group B", "isActive": false}
            },
            "profiles": {},
            "noProfilePseudoProfile": {},
            "globalDefaults": {},
            "users": [],
            "codeRequirements": {},
            "developerTeamNames": {},
            "lastSeenExecutableByCodeIdentifier": {},
            "networkTriggers": [],
            "blocklistStatistics": {},
            "disabledDomainsInLists": [],
            "disabledHostNamesInLists": [],
            "disabledIPAddressRangesInLists": []
        }))
        .unwrap()
    }

    fn run(remote: &str, catch_all: bool) -> FindRulesForRemoteResult {
        run_with_model(
            FindRulesForRemoteArgs { remote: remote.into(), include_catch_all: catch_all },
            &fixture_model(),
        )
    }

    // ── address matching ──────────────────────────────────────────────────────

    #[test]
    fn exact_ip_matches_address_rule() {
        let r = run("1.2.3.4", false);
        assert_eq!(r.total_count, 1);
        let rule = &r.groups[0].rules[0];
        assert_eq!(rule.match_kind, MatchKind::Address);
        assert_eq!(rule.matched_remote, "1.2.3.4");
    }

    #[test]
    fn ip_inside_cidr_matches() {
        let r = run("10.0.0.55", false);
        assert_eq!(r.total_count, 1);
        assert_eq!(r.groups[0].rules[0].match_kind, MatchKind::Address);
    }

    #[test]
    fn ip_outside_cidr_does_not_match() {
        let r = run("192.168.1.1", false);
        assert_eq!(r.total_count, 0);
    }

    #[test]
    fn cidr_query_overlapping_stored_cidr_matches() {
        // 10.1.0.0/16 ⊂ 10.0.0.0/8 → should match
        let r = run("10.1.0.0/16", false);
        assert_eq!(r.total_count, 1);
        assert_eq!(r.groups[0].rules[0].match_kind, MatchKind::Address);
    }

    #[test]
    fn cidr_query_no_overlap_does_not_match() {
        let r = run("192.168.0.0/16", false);
        assert_eq!(r.total_count, 0);
    }

    #[test]
    fn ipv6_exact_matches_array_entry() {
        let r = run("::1", false);
        assert_eq!(r.total_count, 1);
        assert_eq!(r.groups[0].rules[0].match_kind, MatchKind::Address);
    }

    #[test]
    fn ipv6_inside_link_local_cidr_matches() {
        let r = run("fe80::1", false);
        assert_eq!(r.total_count, 1);
        assert_eq!(r.groups[0].rules[0].match_kind, MatchKind::Address);
    }

    // ── host matching ─────────────────────────────────────────────────────────

    #[test]
    fn exact_hostname_matches_remote_hosts() {
        let r = run("api.example.com", false);
        // Should match remote-hosts (exact) AND remote-domains (api.example.com is subdomain of example.com)
        assert!(r.total_count >= 1);
        let has_host = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::Host);
        assert!(has_host, "should have at least one Host match");
    }

    #[test]
    fn hostname_not_in_hosts_list_doesnt_match_host_kind() {
        let r = run("other.example.com", false);
        let has_host = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::Host);
        assert!(!has_host, "other.example.com is not in remote-hosts");
    }

    // ── domain matching ───────────────────────────────────────────────────────

    #[test]
    fn stored_domain_covers_subdomain_query() {
        // stored: example.com → should match api.example.com
        let r = run("api.example.com", false);
        let has_domain = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::Domain);
        assert!(has_domain, "stored domain should cover subdomain");
    }

    #[test]
    fn exact_domain_matches() {
        let r = run("example.com", false);
        let has_domain = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::Domain);
        assert!(has_domain, "exact domain match should work");
    }

    #[test]
    fn unrelated_domain_does_not_match() {
        let r = run("notexample.com", false);
        let has_domain = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::Domain);
        assert!(!has_domain);
    }

    // ── catch-all ─────────────────────────────────────────────────────────────

    #[test]
    fn catch_all_excluded_by_default() {
        let r = run("1.2.3.4", false);
        let has_catch_all = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::CatchAll);
        assert!(!has_catch_all, "catch-all must be opt-in");
    }

    #[test]
    fn catch_all_included_when_requested() {
        let r = run("1.2.3.4", true);
        let has_catch_all = r.groups.iter().flat_map(|g| &g.rules).any(|r| r.match_kind == MatchKind::CatchAll);
        assert!(has_catch_all, "catch-all rule must appear when include_catch_all=true");
    }

    // ── group bucketing / sorting ─────────────────────────────────────────────

    #[test]
    fn groups_sorted_by_display_name() {
        let r = run("1.2.3.4", true);
        let names: Vec<&str> = r.groups.iter().map(|g| g.display_name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn disabled_group_flagged_in_result() {
        // grp-b is disabled; remote-hosts "api.example.com" is in grp-b
        let r = run("api.example.com", false);
        let grp_b = r.groups.iter().find(|g| g.group_id == "grp-b");
        assert!(grp_b.is_some(), "grp-b must appear");
        let grp_b = grp_b.unwrap();
        assert!(!grp_b.is_active);
        assert!(grp_b.rules.iter().all(|r| !r.group_active));
    }

    #[test]
    fn no_group_bucket_appears_for_ungrouped_rules() {
        // The remote-domains "example.com" rule has no group
        let r = run("example.com", false);
        assert!(r.groups.iter().any(|g| g.group_id == "<no-group>"));
    }

    // ── edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_remote_propagates_from_live_run() {
        let result = run_with_model(
            FindRulesForRemoteArgs { remote: String::new(), include_catch_all: false },
            &fixture_model(),
        );
        // empty remote won't match anything — just verify it doesn't panic
        assert_eq!(result.total_count, 0);
    }

    #[test]
    fn total_count_matches_sum_of_rule_counts() {
        let r = run("10.0.0.1", true);
        let sum: usize = r.groups.iter().map(|g| g.rules.len()).sum();
        assert_eq!(r.total_count, sum);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn domain_covers_exact_and_subdomain() {
        assert!(domain_covers("example.com", "example.com"));
        assert!(domain_covers("example.com", "api.example.com"));
        assert!(domain_covers("example.com", "deep.api.example.com"));
        assert!(!domain_covers("example.com", "notexample.com"));
        assert!(!domain_covers("example.com", "xexample.com"));
    }

    #[test]
    fn address_covers_ip_exact_and_cidr() {
        assert!(address_covers_ip("1.2.3.4", "1.2.3.4".parse().unwrap()));
        assert!(!address_covers_ip("1.2.3.4", "1.2.3.5".parse().unwrap()));
        assert!(address_covers_ip("10.0.0.0/8", "10.0.0.1".parse().unwrap()));
        assert!(!address_covers_ip("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
    }
}
