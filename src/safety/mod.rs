//! Safety primitives shared across every tool dispatcher.
//!
//! The submodules here express the static, declarative half of the safety
//! contract documented in
//! [ADR-0004](../../docs/adr/0004-safety-permissions-and-confirmation.md):
//! what each tool is *allowed* to do, and what runtime checks gate it. The
//! dynamic half — confirmation tokens, kill-switch guards, rule-level
//! refusals — will land in sibling submodules as the relevant issues
//! ([#43], [#44], [#46], [#47]) close.
//!
//! [#43]: https://github.com/torsday/little-snitch-mcp/issues/43
//! [#44]: https://github.com/torsday/little-snitch-mcp/issues/44
//! [#46]: https://github.com/torsday/little-snitch-mcp/issues/46
//! [#47]: https://github.com/torsday/little-snitch-mcp/issues/47

pub mod classification;
pub mod registry;

pub use classification::Classification;
pub use registry::{TOOLS, ToolMeta};
