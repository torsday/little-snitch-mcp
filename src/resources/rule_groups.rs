//! Derived resources projecting rule-group data from the live model.
//!
//! - `littlesnitch://model/rule-groups` — array of group summaries.
//! - `littlesnitch://model/rule-groups/{id}` — single group with its rule list.

use serde::Serialize;

pub const URI: &str = "littlesnitch://model/rule-groups";
pub const URI_TEMPLATE: &str = "littlesnitch://model/rule-groups/{id}";

const URI_ITEM_PREFIX: &str = "littlesnitch://model/rule-groups/";

/// Return `Some(id)` when `uri` matches `littlesnitch://model/rule-groups/{id}`.
pub fn match_item_uri(uri: &str) -> Option<&str> {
    uri.strip_prefix(URI_ITEM_PREFIX)
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

/// Summary of a single rule group as returned by the listing resource.
#[derive(Debug, Serialize)]
pub struct GroupSummary {
    pub id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub is_active: bool,
    pub rule_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<f64>,
}

/// Full detail for a single rule group.
#[derive(Debug, Serialize)]
pub struct GroupDetail {
    pub id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub is_active: bool,
    pub rules: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<f64>,
}

/// Derive a display name for a group.
///
/// Resolution priority: explicit `name` field → SEED_KIND_MAP lookup for
/// `kind` → `kind` value verbatim → group ID.
fn display_name_for(id: &str, group: &crate::model::Group) -> String {
    if let Some(name) = &group.name {
        return name.clone();
    }
    let kind = group
        .kind
        .as_deref()
        .or(group.kind_legacy.as_deref());
    if let Some(k) = kind {
        if let Some(mapped) = crate::safety::resolver::SEED_KIND_MAP
            .iter()
            .find(|(kk, _)| *kk == k)
            .map(|(_, v)| *v)
        {
            return mapped.to_string();
        }
        return k.to_string();
    }
    id.to_string()
}

/// Build the listing of all groups from `model`, sorted by display name.
pub fn list_groups(model: &crate::model::Model) -> Vec<GroupSummary> {
    let mut summaries: Vec<GroupSummary> = model
        .groups
        .iter()
        .map(|(id, group)| {
            let rule_count = model
                .rules
                .iter()
                .filter(|r| r.group.as_deref() == Some(id.as_str()))
                .count();
            GroupSummary {
                id: id.clone(),
                display_name: display_name_for(id, group),
                kind: group.kind.clone().or_else(|| group.kind_legacy.clone()),
                is_active: group.is_active.unwrap_or(true),
                rule_count,
                update_interval: group.update_interval,
            }
        })
        .collect();

    summaries.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    summaries
}

/// Build the detail for a single group identified by `id`, or `None` if the
/// group does not exist.
pub fn get_group(id: &str, model: &crate::model::Model) -> Option<GroupDetail> {
    let group = model.groups.get(id)?;
    let rules: Vec<serde_json::Value> = model
        .rules
        .iter()
        .filter(|r| r.group.as_deref() == Some(id))
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    Some(GroupDetail {
        id: id.to_string(),
        display_name: display_name_for(id, group),
        kind: group.kind.clone().or_else(|| group.kind_legacy.clone()),
        is_active: group.is_active.unwrap_or(true),
        rules,
        update_interval: group.update_interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_model() -> crate::model::Model {
        serde_json::from_value(json!({
            "bundleVersion": 7172,
            "factoryRuleSetVersion": 424,
            "rules": [
                {"action": "allow", "process": "/usr/bin/curl", "remote": "any",
                 "creationDate": "2026-01-01T00:00:00Z", "modificationDate": "2026-01-01T00:00:00Z", "origin": "frontend", "group": "group-1"},
                {"action": "deny", "process": "/usr/bin/curl", "remote": "any",
                 "creationDate": "2026-01-01T00:00:00Z", "modificationDate": "2026-01-01T00:00:00Z", "origin": "frontend", "group": "group-2"},
                {"action": "allow", "process": "any", "remote": "any",
                 "creationDate": "2026-01-01T00:00:00Z", "modificationDate": "2026-01-01T00:00:00Z", "origin": "frontend"}
            ],
            "groups": {
                "group-1": {"name": "My Rules", "isActive": true},
                "group-2": {"kind": "builtinMacOSServices", "isActive": false},
                "group-3": {"name": "Empty Group", "isActive": true}
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
    fn list_groups_count() {
        let model = fixture_model();
        let summaries = list_groups(&model);
        assert_eq!(summaries.len(), 3);
    }

    #[test]
    fn list_groups_sorted_by_display_name() {
        let model = fixture_model();
        let summaries = list_groups(&model);
        let names: Vec<&str> = summaries.iter().map(|s| s.display_name.as_str()).collect();
        assert_eq!(names, vec!["Empty Group", "My Rules", "macOS Services"]);
    }

    #[test]
    fn list_groups_rule_counts() {
        let model = fixture_model();
        let summaries = list_groups(&model);
        let by_name: std::collections::HashMap<&str, usize> =
            summaries.iter().map(|s| (s.display_name.as_str(), s.rule_count)).collect();
        assert_eq!(by_name["My Rules"], 1);
        assert_eq!(by_name["macOS Services"], 1);
        assert_eq!(by_name["Empty Group"], 0);
    }

    #[test]
    fn list_groups_is_active() {
        let model = fixture_model();
        let summaries = list_groups(&model);
        let by_name: std::collections::HashMap<&str, bool> =
            summaries.iter().map(|s| (s.display_name.as_str(), s.is_active)).collect();
        assert!(by_name["My Rules"]);
        assert!(!by_name["macOS Services"]);
    }

    #[test]
    fn get_group_by_id() {
        let model = fixture_model();
        let detail = get_group("group-1", &model).unwrap();
        assert_eq!(detail.display_name, "My Rules");
        assert_eq!(detail.rules.len(), 1);
        assert!(detail.is_active);
    }

    #[test]
    fn get_group_builtin_resolved() {
        let model = fixture_model();
        let detail = get_group("group-2", &model).unwrap();
        assert_eq!(detail.display_name, "macOS Services");
        assert!(!detail.is_active);
    }

    #[test]
    fn get_group_unknown_id_returns_none() {
        let model = fixture_model();
        assert!(get_group("nonexistent", &model).is_none());
    }

    #[test]
    fn match_item_uri_valid() {
        assert_eq!(
            match_item_uri("littlesnitch://model/rule-groups/group-1"),
            Some("group-1")
        );
    }

    #[test]
    fn match_item_uri_listing_uri_rejected() {
        assert_eq!(match_item_uri("littlesnitch://model/rule-groups"), None);
    }

    #[test]
    fn match_item_uri_nested_rejected() {
        assert_eq!(
            match_item_uri("littlesnitch://model/rule-groups/a/b"),
            None
        );
    }
}
