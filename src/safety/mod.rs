//! Safety primitives shared across every tool dispatcher.
//!
//! The submodules here express the safety contract documented in
//! [ADR-0004](../../docs/adr/0004-safety-permissions-and-confirmation.md):
//! what each tool is *allowed* to do, and what runtime checks gate it.
//! Rule-level refusals will land in a sibling submodule as
//! [#46](https://github.com/torsday/little-snitch-mcp/issues/46) closes.

pub mod classification;
pub mod cli;
pub mod prefs;
pub mod registry;
pub mod schema;
pub mod secret_prefs;
pub mod token;
pub mod touchid;

pub use classification::Classification;
pub use cli::RESTORE_MODEL_TERMINAL_GUARD_FLAG;
pub use prefs::{
    ALLOWLIST_KEYS, HARD_DENY_KEYS, KillSwitchRefusal, WriteRefusal, WriteStatus,
    is_kill_switch_key, is_writable, refuse_if_kill_switch, require_writable,
};
pub use registry::{TOOLS, ToolMeta};
pub use schema::{SchemaMismatch, check_bundle_version, extract_bundle_version};
pub use token::{Session, Token, TokenError, TokenPayload, VerifiedToken, VerifyContext};
pub use touchid::{TouchIdSudoStatus, detect as detect_touchid_sudo};
