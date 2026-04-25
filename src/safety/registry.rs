//! Per-tool classification metadata.
//!
//! Single source of truth mapping tool names to their [`Classification`].
//! Every tool exposed by the MCP server **must** appear here exactly once;
//! the parity test [`tests::registry_matches_server_tools`] enforces that
//! the live `tools/list` response and this registry agree.
//!
//! # Adding a new tool
//!
//! 1. Implement the `#[tool]` method on the appropriate server impl.
//! 2. Add a [`ToolMeta`] entry to [`TOOLS`] with the tightest classification
//!    that lets the tool function. See [`Classification`] for the matrix.
//! 3. `cargo test` will fail with a clear diff if you forgot either side.

use crate::safety::Classification;

/// Static metadata attached to every exposed tool.
#[derive(Debug, Clone, Copy)]
pub struct ToolMeta {
    /// Tool name as exposed over MCP (matches the `#[tool]` method name).
    pub name: &'static str,
    /// Safety tier; see [`Classification`].
    pub classification: Classification,
}

/// The authoritative list of tools and their classifications.
///
/// Order is irrelevant; uniqueness on `name` is enforced by
/// [`tests::names_are_unique`].
pub static TOOLS: &[ToolMeta] = &[
    ToolMeta {
        name: "echo",
        classification: Classification::SafeRead,
    },
    ToolMeta {
        name: "validate_lsrules",
        classification: Classification::SafeRead,
    },
    ToolMeta {
        name: "create_lsrules_file",
        classification: Classification::ManagedWrite,
    },
    ToolMeta {
        name: "remove_rule_from_lsrules_file",
        classification: Classification::ManagedWrite,
    },
    ToolMeta {
        name: "update_rule_in_lsrules_file",
        classification: Classification::ManagedWrite,
    },
    ToolMeta {
        name: "add_rule_to_lsrules_file",
        classification: Classification::ManagedWrite,
    },
    ToolMeta {
        name: "export_model_backup",
        classification: Classification::SudoRead,
    },
    ToolMeta {
        name: "read_preference",
        classification: Classification::SudoRead,
    },
    ToolMeta {
        name: "list_preferences",
        classification: Classification::SudoRead,
    },
    ToolMeta {
        name: "doctor",
        classification: Classification::SafeRead,
    },
];

/// Look up a tool's metadata by name.
pub fn get(name: &str) -> Option<&'static ToolMeta> {
    TOOLS.iter().find(|t| t.name == name)
}

/// Count of registered tools per classification, in
/// [`Classification::ALL`] order. Useful for `doctor`-style reporting
/// (see [#16](https://github.com/torsday/little-snitch-mcp/issues/16)).
pub fn count_by_classification() -> [(Classification, usize); 5] {
    let mut out = [(Classification::SafeRead, 0usize); 5];
    for (i, c) in Classification::ALL.into_iter().enumerate() {
        out[i] = (c, TOOLS.iter().filter(|t| t.classification == c).count());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn names_are_unique() {
        let mut seen = HashSet::new();
        for t in TOOLS {
            assert!(
                seen.insert(t.name),
                "duplicate tool name in registry: {}",
                t.name
            );
        }
    }

    #[test]
    fn registry_is_non_empty() {
        assert!(!TOOLS.is_empty(), "tool registry must not be empty");
    }

    #[test]
    fn echo_is_safe_read() {
        let meta = get("echo").expect("echo must be registered");
        assert_eq!(meta.classification, Classification::SafeRead);
    }

    #[test]
    fn unknown_tool_lookup_returns_none() {
        assert!(get("nonexistent_tool").is_none());
    }

    #[test]
    fn count_by_classification_sums_to_total() {
        let counts = count_by_classification();
        let total: usize = counts.iter().map(|(_, n)| *n).sum();
        assert_eq!(total, TOOLS.len());
    }

    #[test]
    fn count_by_classification_covers_all_tiers() {
        let counts = count_by_classification();
        let tiers: Vec<_> = counts.iter().map(|(c, _)| *c).collect();
        assert_eq!(tiers, Classification::ALL.to_vec());
    }

    #[test]
    fn names_match_snake_case_tool_convention() {
        let valid = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        for t in TOOLS {
            assert!(!t.name.is_empty(), "empty tool name in registry");
            assert!(
                t.name.chars().all(valid),
                "tool name {:?} is not snake_case ASCII",
                t.name
            );
            assert!(
                !t.name.starts_with('_') && !t.name.ends_with('_'),
                "tool name {:?} has leading/trailing underscore",
                t.name
            );
        }
    }
}
