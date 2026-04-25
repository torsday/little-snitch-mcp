//! Tool classification taxonomy.
//!
//! Every MCP tool exposed by `little-snitch-mcp` carries exactly one
//! [`Classification`]. The classification is the load-bearing input to every
//! safety guard: it determines whether sudo is required, whether a managed
//! `.lsrules` file is the only acceptable target, whether a confirmation
//! token must accompany the call, and what diagnostics the dispatcher emits.
//!
//! See [ADR-0004 — Safety, Permissions, and Confirmation](../../../docs/adr/0004-safety-permissions-and-confirmation.md)
//! for the full rule matrix. The variants here mirror the tiers defined there.
//!
//! Adding a new tool:
//!   1. Pick the tightest classification that still lets the tool do its job.
//!   2. Register it in [`crate::safety::registry::TOOLS`].
//!   3. The parity test in [`crate::safety::registry`] enforces that every
//!      tool exposed by the server has a registry entry.

use std::fmt;

/// The five safety tiers a tool may belong to.
///
/// Tiers are ordered from least to most dangerous. Comparisons (`<`, `>`)
/// are meaningful: a tool of `LiveWriteStrong` is strictly more dangerous
/// than one of `SafeRead`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    /// Pure read with no privileged input. Safe to expose unconditionally.
    /// Examples: `echo`, `list_rule_groups` (when reading a managed file).
    SafeRead,

    /// Read that requires `sudo` (e.g. `little-snitch read-model`). No
    /// mutation, but capability gating applies because sudo is required.
    SudoRead,

    /// Mutation confined to a managed `.lsrules` file under the configured
    /// managed directory. No live-model effect. Reversible by editing the
    /// file or removing the subscription.
    ManagedWrite,

    /// Live mutation of the running Little Snitch model via
    /// `restore-model -t`. Effective immediately. Requires a confirmation
    /// token from a prior `prepare_*` call.
    LiveWrite,

    /// Live mutation that would touch a high-blast-radius surface
    /// (kill-switch, factory rule, builtin group). Requires the
    /// confirmation-token protocol *plus* an explicit user acknowledgement
    /// string per ADR-0004 §9.
    LiveWriteStrong,
}

impl Classification {
    /// Stable, snake_case identifier for serialization, logging, and
    /// matching against the configured allow/deny lists in
    /// [ADR-0004 §4](../../../docs/adr/0004-safety-permissions-and-confirmation.md).
    pub const fn as_str(self) -> &'static str {
        match self {
            Classification::SafeRead => "safe_read",
            Classification::SudoRead => "sudo_read",
            Classification::ManagedWrite => "managed_write",
            Classification::LiveWrite => "live_write",
            Classification::LiveWriteStrong => "live_write_strong",
        }
    }

    /// True if invoking the tool can change the live Little Snitch model.
    pub const fn is_live_write(self) -> bool {
        matches!(
            self,
            Classification::LiveWrite | Classification::LiveWriteStrong
        )
    }

    /// True if a confirmation token from a `prepare_*` call is required.
    pub const fn requires_confirmation_token(self) -> bool {
        self.is_live_write()
    }

    /// True if the tier requires `sudo` to actuate (read or write).
    pub const fn requires_sudo(self) -> bool {
        matches!(
            self,
            Classification::SudoRead | Classification::LiveWrite | Classification::LiveWriteStrong
        )
    }

    /// All variants in declaration order. Useful for exhaustive iteration
    /// (e.g. `doctor` reporting counts per tier).
    pub const ALL: [Classification; 5] = [
        Classification::SafeRead,
        Classification::SudoRead,
        Classification::ManagedWrite,
        Classification::LiveWrite,
        Classification::LiveWriteStrong,
    ];
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_reflects_danger() {
        assert!(Classification::SafeRead < Classification::SudoRead);
        assert!(Classification::SudoRead < Classification::ManagedWrite);
        assert!(Classification::ManagedWrite < Classification::LiveWrite);
        assert!(Classification::LiveWrite < Classification::LiveWriteStrong);
    }

    #[test]
    fn live_write_predicates() {
        assert!(!Classification::SafeRead.is_live_write());
        assert!(!Classification::SudoRead.is_live_write());
        assert!(!Classification::ManagedWrite.is_live_write());
        assert!(Classification::LiveWrite.is_live_write());
        assert!(Classification::LiveWriteStrong.is_live_write());
    }

    #[test]
    fn confirmation_token_required_iff_live_write() {
        for c in Classification::ALL {
            assert_eq!(c.requires_confirmation_token(), c.is_live_write());
        }
    }

    #[test]
    fn sudo_required_for_sudo_read_and_live_writes() {
        assert!(!Classification::SafeRead.requires_sudo());
        assert!(Classification::SudoRead.requires_sudo());
        assert!(!Classification::ManagedWrite.requires_sudo());
        assert!(Classification::LiveWrite.requires_sudo());
        assert!(Classification::LiveWriteStrong.requires_sudo());
    }

    #[test]
    fn as_str_is_stable_snake_case() {
        assert_eq!(Classification::SafeRead.as_str(), "safe_read");
        assert_eq!(Classification::SudoRead.as_str(), "sudo_read");
        assert_eq!(Classification::ManagedWrite.as_str(), "managed_write");
        assert_eq!(Classification::LiveWrite.as_str(), "live_write");
        assert_eq!(
            Classification::LiveWriteStrong.as_str(),
            "live_write_strong"
        );
    }

    #[test]
    fn all_contains_every_variant_exactly_once() {
        let mut seen: Vec<_> = Classification::ALL.into_iter().collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 5);
    }
}
