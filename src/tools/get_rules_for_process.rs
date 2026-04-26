//! `get_rules_for_process` — return all rules matching a process string.
//!
//! Classification: SafeRead — loads the live model via `export-model` and
//! returns a read-only projection; no mutation of LS state.

use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cli::adapter::LsCli;
use crate::model::{Model, Rule};
use crate::safety::resolver::SEED_KIND_MAP;

// ─── public types ────────────────────────────────────────────────────────────

/// Input for `get_rules_for_process`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRulesForProcessArgs {
    /// Process path (`/usr/bin/curl`), the literal `"any"`, or code-id
    /// format `TEAMID/identifier` (e.g. `"59GAB85EFG/com.apple.Safari"`).
    pub process: String,
}

/// A single rule entry in the output, augmented with group display name and
/// active state.
#[derive(Debug, Serialize)]
pub struct RuleEntry {
    /// Index of this rule within its group in the output (0-based).
    pub index: usize,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// Human-readable remote selector string (whatever LS stored).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    pub creation_date: String,
    pub modification_date: String,
    /// Whether this rule's group is currently active in LS. `true` means
    /// the rule is effectively enforced; `false` means its group is disabled.
    pub group_active: bool,
}

/// A group bucket containing matching rules.
#[derive(Debug, Serialize)]
pub struct GroupBucket {
    /// Group ID (the key from `model.groups`), or `"<no-group>"` for rules
    /// not assigned to any group.
    pub group_id: String,
    /// Human-readable display name resolved via the S4 chain.
    pub display_name: String,
    /// Whether this group is currently active.
    pub is_active: bool,
    /// Matching rules within this group.
    pub rules: Vec<RuleEntry>,
}

/// Return value of `get_rules_for_process`.
#[derive(Debug, Serialize)]
pub struct GetRulesForProcessResult {
    /// The input process string that was queried.
    pub process: String,
    /// Total number of matching rules across all groups.
    pub total_count: usize,
    /// Rules grouped by their assigned group, sorted by display name.
    /// Groups with no matching rules are omitted.
    pub groups: Vec<GroupBucket>,
}

// ─── implementation ──────────────────────────────────────────────────────────

/// Run the tool against the live model.
pub fn run(args: GetRulesForProcessArgs) -> Result<GetRulesForProcessResult, String> {
    if args.process.is_empty() {
        return Err("process must not be empty".into());
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
pub fn run_with_model(args: GetRulesForProcessArgs, model: &Model) -> GetRulesForProcessResult {
    let process = &args.process;

    // Collect matching rules.
    let matching: Vec<&Rule> = model
        .rules
        .iter()
        .filter(|r| r.process.as_deref() == Some(process.as_str()))
        .collect();

    let total_count = matching.len();

    // Group matching rules by group_id.
    let mut by_group: std::collections::HashMap<String, Vec<&Rule>> =
        std::collections::HashMap::new();
    for rule in &matching {
        let key = rule
            .group
            .clone()
            .unwrap_or_else(|| "<no-group>".to_string());
        by_group.entry(key).or_default().push(rule);
    }

    // Build GroupBucket for each group that has matching rules.
    let mut groups: Vec<GroupBucket> = by_group
        .into_iter()
        .map(|(group_id, rules)| {
            let (display_name, is_active) = if group_id == "<no-group>" {
                ("<no-group>".to_string(), true)
            } else {
                let g = model.groups.get(&group_id);
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
                    .unwrap_or_else(|| group_id.clone());
                let active = g.and_then(|g| g.is_active).unwrap_or(true);
                (name, active)
            };

            let rule_entries: Vec<RuleEntry> = rules
                .iter()
                .enumerate()
                .map(|(index, r)| {
                    let remote_str = r
                        .remote
                        .as_deref()
                        .map(|s| s.to_string())
                        .or_else(|| {
                            r.remote_domains
                                .as_ref()
                                .map(|v| v.iter().collect::<Vec<_>>().join(", "))
                        })
                        .or_else(|| {
                            r.remote_hosts
                                .as_ref()
                                .map(|v| v.iter().collect::<Vec<_>>().join(", "))
                        })
                        .or_else(|| {
                            r.remote_addresses
                                .as_ref()
                                .map(|v| v.iter().collect::<Vec<_>>().join(", "))
                        });
                    RuleEntry {
                        index,
                        action: format!("{:?}", r.action).to_lowercase(),
                        direction: r.direction.map(|d| format!("{:?}", d).to_lowercase()),
                        remote: remote_str,
                        creation_date: r.creation_date.clone(),
                        modification_date: r.modification_date.clone(),
                        group_active: is_active,
                    }
                })
                .collect();

            GroupBucket {
                group_id,
                display_name,
                is_active,
                rules: rule_entries,
            }
        })
        .collect();

    groups.sort_by(|a, b| a.display_name.cmp(&b.display_name));

    GetRulesForProcessResult {
        process: process.clone(),
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
                {
                    "action": "allow", "process": "/usr/bin/curl", "remote": "any",
                    "creationDate": "2026-01-01T00:00:00Z",
                    "modificationDate": "2026-01-01T00:00:00Z",
                    "origin": "frontend",
                    "group": "group-active"
                },
                {
                    "action": "deny", "process": "/usr/bin/curl", "remote": "api.example.com",
                    "creationDate": "2026-01-02T00:00:00Z",
                    "modificationDate": "2026-01-02T00:00:00Z",
                    "origin": "frontend",
                    "group": "group-disabled"
                },
                {
                    "action": "allow", "process": "/usr/bin/ssh", "remote": "any",
                    "creationDate": "2026-01-01T00:00:00Z",
                    "modificationDate": "2026-01-01T00:00:00Z",
                    "origin": "frontend"
                },
                {
                    "action": "allow", "process": "/usr/bin/curl", "remote": "any",
                    "creationDate": "2026-01-03T00:00:00Z",
                    "modificationDate": "2026-01-03T00:00:00Z",
                    "origin": "frontend"
                }
            ],
            "groups": {
                "group-active": {"name": "Active Group", "isActive": true},
                "group-disabled": {"name": "Disabled Group", "isActive": false}
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

    #[test]
    fn matches_by_exact_process_path() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/curl".into(),
            },
            &model,
        );
        assert_eq!(result.total_count, 3);
        assert_eq!(result.process, "/usr/bin/curl");
    }

    #[test]
    fn non_matching_process_returns_empty() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/wget".into(),
            },
            &model,
        );
        assert_eq!(result.total_count, 0);
        assert!(result.groups.is_empty());
    }

    #[test]
    fn groups_sorted_by_display_name() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/curl".into(),
            },
            &model,
        );
        // Groups should be: "<no-group>", "Active Group", "Disabled Group" sorted
        let names: Vec<&str> = result
            .groups
            .iter()
            .map(|g| g.display_name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "groups must be sorted by display name");
    }

    #[test]
    fn disabled_group_flagged() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/curl".into(),
            },
            &model,
        );
        let disabled = result
            .groups
            .iter()
            .find(|g| g.display_name == "Disabled Group")
            .expect("disabled group must appear");
        assert!(!disabled.is_active);
        assert!(
            disabled.rules.iter().all(|r| !r.group_active),
            "all rules in disabled group must have group_active=false"
        );
    }

    #[test]
    fn active_group_flagged_correctly() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/curl".into(),
            },
            &model,
        );
        let active = result
            .groups
            .iter()
            .find(|g| g.display_name == "Active Group")
            .expect("active group must appear");
        assert!(active.is_active);
        assert!(active.rules.iter().all(|r| r.group_active));
    }

    #[test]
    fn no_group_bucket_present() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/curl".into(),
            },
            &model,
        );
        assert!(
            result.groups.iter().any(|g| g.group_id == "<no-group>"),
            "ungrouped rule must land in <no-group>"
        );
    }

    #[test]
    fn empty_process_returns_error() {
        let result = run(GetRulesForProcessArgs {
            process: String::new(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn ssh_rules_dont_appear_in_curl_query() {
        let model = fixture_model();
        let result = run_with_model(
            GetRulesForProcessArgs {
                process: "/usr/bin/curl".into(),
            },
            &model,
        );
        for g in &result.groups {
            for r in &g.rules {
                // All rules have action "allow" or "deny"; no ssh-specific remote
                let _ = r; // structural check — just verify totals
            }
        }
        assert_eq!(result.total_count, 3, "only curl rules, not ssh");
    }
}
