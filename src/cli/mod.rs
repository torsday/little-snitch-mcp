//! Little Snitch CLI adapter layer.
//!
//! Submodules here wrap the `littlesnitch` binary: locating it
//! ([`binary`]) and mapping its stderr to typed errors ([`adapter`],
//! landing with [#13](https://github.com/torsday/little-snitch-mcp/issues/13)).

pub mod binary;

pub use binary::{LsBinaryNotFound, resolve_binary};
