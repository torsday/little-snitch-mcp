//! CLI invocation safety constants.
//!
//! [`RESTORE_MODEL_TERMINAL_GUARD_FLAG`] is the `-t` flag that
//! `little-snitch restore-model` requires to *prevent* the restore
//! payload from disabling Terminal access ("if `-t` is omitted, a
//! malicious payload that flips the `allowCommandLineAccess` pref
//! locks the CLI out until a human fixes it via the GUI"). ADR-0004 §3
//! commits us to passing `-t` on **every** invocation, with no escape
//! hatch.
//!
//! # The convention
//!
//! Every place the codebase spawns `little-snitch restore-model` MUST
//! reference this constant — either as a literal `-t` adjacent to the
//! `restore-model` argument, or by routing through a CLI adapter that
//! does so. The integration test
//! `tests/no_unsafe_restore_model.rs` walks `src/` and fails the
//! build if any source line invokes `restore-model` without `-t`
//! present somewhere in the same expression (see the test for the
//! exact rule).
//!
//! # Why a constant rather than just a literal
//!
//! Two reasons:
//! 1. **Searchability.** `grep RESTORE_MODEL_TERMINAL_GUARD_FLAG` is
//!    unambiguous; `grep '"-t"'` is not.
//! 2. **Documentation gravity.** A reviewer who hovers the constant
//!    sees the rationale; a reviewer who sees a bare `"-t"` does not.
//!
//! There is no `--no-t` and no overrideable wrapper. The flag is part
//! of the safety contract, not a configuration knob.

/// The Terminal-access guard flag for `little-snitch restore-model`.
///
/// Without this flag, a `restore-model` payload that includes
/// `allowCommandLineAccess: false` in `globalDefaults` would lock LS's
/// CLI out — including this MCP server itself — until repaired via the
/// LS GUI. With this flag, LS refuses to apply any change that would
/// disable Terminal access regardless of payload contents.
///
/// See ADR-0004 §3 ("Hard guards") for the full rationale.
pub const RESTORE_MODEL_TERMINAL_GUARD_FLAG: &str = "-t";
