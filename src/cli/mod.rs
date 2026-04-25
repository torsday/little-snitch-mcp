//! Little Snitch CLI adapter layer.
//!
//! Submodules here wrap the `littlesnitch` binary: locating it
//! ([`binary`]) and mapping its subprocess output to typed errors ([`adapter`]).

pub mod adapter;
pub mod binary;

pub use adapter::{LsCli, LsCliError};
pub use binary::{LsBinaryNotFound, resolve_binary};
