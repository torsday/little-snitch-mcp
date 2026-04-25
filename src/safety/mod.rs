//! Safety primitives shared across every tool dispatcher.
//!
//! The submodules here express the safety contract documented in
//! [ADR-0004](../../docs/adr/0004-safety-permissions-and-confirmation.md):
//! what each tool is *allowed* to do, and what runtime checks gate it.
//! Rule-level refusals will land in a sibling submodule as
//! [#46](https://github.com/torsday/little-snitch-mcp/issues/46) closes.

pub mod classification;
pub mod prefs;
pub mod registry;
pub mod token;

pub use classification::Classification;
pub use prefs::{HARD_DENY_KEYS, KillSwitchRefusal, is_kill_switch_key, refuse_if_kill_switch};
pub use registry::{TOOLS, ToolMeta};
pub use token::{Session, Token, TokenError, TokenPayload, VerifiedToken, VerifyContext};
