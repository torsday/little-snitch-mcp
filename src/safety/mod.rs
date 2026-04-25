//! Safety primitives shared across every tool dispatcher.
//!
//! The submodules here express the static, declarative half of the safety
//! contract documented in
//! [ADR-0004](../../docs/adr/0004-safety-permissions-and-confirmation.md):
//! what each tool is *allowed* to do, and what runtime checks gate it. The
//! dynamic half — confirmation tokens, rule-level refusals — will land in
//! sibling submodules as the relevant issues ([#43], [#44], [#46]) close.
//!
//! [#43]: https://github.com/torsday/little-snitch-mcp/issues/43
//! [#44]: https://github.com/torsday/little-snitch-mcp/issues/44
//! [#46]: https://github.com/torsday/little-snitch-mcp/issues/46

pub mod classification;
pub mod prefs;
pub mod registry;

pub use classification::Classification;
pub use prefs::{HARD_DENY_KEYS, KillSwitchRefusal, is_kill_switch_key, refuse_if_kill_switch};
pub use registry::{TOOLS, ToolMeta};
