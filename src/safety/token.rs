//! Confirmation-token protocol for `live_write` tool gating.
//!
//! Implements [ADR-0004 §9](../../../docs/adr/0004-safety-permissions-and-confirmation.md)
//! verbatim. Every tool whose [`Classification`](super::Classification) is
//! `LiveWrite` or `LiveWriteStrong` MUST verify a token through this module
//! before mutating the live model.
//!
//! # Lifecycle
//!
//! 1. A `prepare_*` tool computes the proposed diff, calls
//!    [`Session::issue`] with a [`TokenPayload`] describing the operation,
//!    and returns the resulting [`Token`] string to the LLM.
//! 2. The LLM presents the token to the user, who approves it.
//! 3. The corresponding `apply_*` / `add_*` / `update_*` tool re-exports
//!    the live model, recomputes the diff, and calls [`Session::verify`]
//!    with the precomputed `current_diff_sha256`. On `Ok(VerifiedToken)`
//!    the token is marked consumed and the mutation may proceed.
//!
//! # What this module is *not*
//!
//! Diff computation, model re-export, and tool dispatch live elsewhere.
//! This module is pure: every input is in the call signature, every
//! decision is deterministic given those inputs (modulo the fresh
//! random session key).

use hmac::{Hmac, Mac};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Current protocol version. Bumped if `TokenPayload` ever changes shape.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default token TTL per ADR-0004 §9.
pub const DEFAULT_TTL_SECS: u64 = 60;

/// The signed payload carried inside a [`Token`].
///
/// Field names mirror ADR-0004 §9 verbatim — they appear in the wire
/// format consumed by the LLM and may end up in user-facing diff
/// summaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenPayload {
    /// Protocol version. Always [`PROTOCOL_VERSION`] for new tokens.
    pub v: u32,
    /// Per-MCP-process random; generated at startup, never persisted.
    pub session_id: String,
    /// Tool name the token authorizes (must match the consumer's tool).
    pub tool: String,
    /// Operation-specific identifier (e.g. file path + managed-dir
    /// signature). Opaque to this module; serialized as JSON.
    pub target: serde_json::Value,
    /// SHA-256 of the canonicalized diff JSON, hex-encoded lowercase.
    pub diff_sha256: String,
    /// `bundleVersion` of the live model at issue time (for SCHEMA_DRIFT).
    pub bundle_version: String,
    /// Unix-seconds issuance timestamp.
    pub issued_at_unix: u64,
    /// Unix-seconds expiry timestamp (typically issued_at + 60).
    pub expires_at_unix: u64,
}

/// Wire format: `<base16(payload_json)>.<base16(hmac)>`.
///
/// Base16 (hex) keeps the token JSON-RPC-safe with zero escaping. The
/// payload is round-tripped verbatim so the verifier sees exactly the
/// bytes the issuer signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Borrow as `&str` for transport.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the underlying `String`.
    pub fn into_string(self) -> String {
        self.0
    }

    fn split(&self) -> Option<(&str, &str)> {
        self.0.split_once('.')
    }
}

impl From<String> for Token {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the verifier needs to know about the *current* world state.
///
/// The caller computes these by re-exporting the live model and
/// re-running the proposed operation. The verifier is pure given them.
#[derive(Debug, Clone)]
pub struct VerifyContext<'a> {
    /// Tool actually being called (TOOL_MISMATCH if this differs from
    /// the token's `tool`).
    pub tool: &'a str,
    /// SHA-256 (hex, lowercase) of the diff as it would execute *now*.
    /// DIFF_DRIFT if this differs from the token's `diff_sha256`.
    pub current_diff_sha256: &'a str,
    /// `bundleVersion` of the live model at verify time. SCHEMA_DRIFT if
    /// this differs from the token's `bundle_version`.
    pub current_bundle_version: &'a str,
}

/// Successful verification result. Holding one of these is the sole
/// proof that the corresponding mutation may proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    pub payload: TokenPayload,
}

/// All seven reject reasons from ADR-0004 §9. Stable variants — the
/// wire-format strings are the audit log's identifying tags.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("INVALID_SIGNATURE: token signature failed HMAC verification")]
    InvalidSignature,
    #[error("CROSS_SESSION_REUSE: token's session_id does not match the current session")]
    CrossSessionReuse,
    #[error("EXPIRED: token's expires_at_unix has passed")]
    Expired,
    #[error("REPLAY: token has already been consumed in this session")]
    Replay,
    #[error("DIFF_DRIFT: live model changed since the token was issued")]
    DiffDrift,
    #[error("TOOL_MISMATCH: token was issued for a different tool")]
    ToolMismatch,
    #[error("SCHEMA_DRIFT: live model's bundleVersion changed since the token was issued")]
    SchemaDrift,
    #[error("MALFORMED: token could not be parsed: {0}")]
    Malformed(String),
}

/// Per-MCP-process token authority. Owns the HMAC key, the session id,
/// and the consumed-token set.
///
/// Construct exactly once at server startup with [`Session::new`]. The
/// key never leaves this object — it has no accessor.
pub struct Session {
    session_id: String,
    hmac_key: [u8; 32],
    consumed: Mutex<HashMap<String, u64>>, // hex(hmac) -> expires_at_unix
}

impl Session {
    /// Generate a new session with fresh randomness.
    ///
    /// # Errors
    ///
    /// Returns the underlying RNG error if the OS RNG is unavailable.
    /// Practically infallible on macOS; surfaced rather than panicked
    /// because it's the kind of failure that should abort startup, not
    /// crash mid-request.
    pub fn new() -> Result<Self, getrandom_error::Error> {
        let mut sid_bytes = [0u8; 32];
        let mut key = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut sid_bytes)
            .map_err(getrandom_error::wrap)?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut key)
            .map_err(getrandom_error::wrap)?;
        Ok(Self {
            session_id: hex::encode(sid_bytes),
            hmac_key: key,
            consumed: Mutex::new(HashMap::new()),
        })
    }

    /// Build a session with caller-supplied randomness. Test-only —
    /// production paths must use [`Session::new`].
    #[doc(hidden)]
    pub fn from_raw(session_id: [u8; 32], hmac_key: [u8; 32]) -> Self {
        Self {
            session_id: hex::encode(session_id),
            hmac_key,
            consumed: Mutex::new(HashMap::new()),
        }
    }

    /// Hex-encoded session id, suitable for embedding in `TokenPayload`.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Sign and return a token for `payload`. The caller fills every
    /// field of `payload` *except* `session_id`, which this method
    /// overwrites with the session's own id.
    pub fn issue(&self, mut payload: TokenPayload) -> Token {
        payload.session_id = self.session_id.clone();
        payload.v = PROTOCOL_VERSION;
        let payload_json =
            serde_json::to_vec(&payload).expect("TokenPayload is always serializable as JSON");
        let mac = self.compute_mac(&payload_json);
        Token(format!(
            "{}.{}",
            hex::encode(&payload_json),
            hex::encode(mac)
        ))
    }

    /// Run all seven verifier checks against `token`. On success the
    /// token is recorded in the consumed-set and a [`VerifiedToken`] is
    /// returned. On any failure the consumed-set is untouched.
    pub fn verify(
        &self,
        token: &Token,
        ctx: &VerifyContext<'_>,
    ) -> Result<VerifiedToken, TokenError> {
        self.verify_at(token, ctx, now_unix())
    }

    /// Same as [`Session::verify`] but with caller-supplied "now" — used
    /// by tests to drive the EXPIRED check deterministically.
    #[doc(hidden)]
    pub fn verify_at(
        &self,
        token: &Token,
        ctx: &VerifyContext<'_>,
        now_unix: u64,
    ) -> Result<VerifiedToken, TokenError> {
        // 1. Parse + signature (constant-time compare).
        let (payload_hex, mac_hex) = token
            .split()
            .ok_or_else(|| TokenError::Malformed("missing '.' separator".into()))?;
        let payload_bytes = hex::decode(payload_hex)
            .map_err(|e| TokenError::Malformed(format!("payload not hex: {e}")))?;
        let mac_bytes =
            hex::decode(mac_hex).map_err(|e| TokenError::Malformed(format!("mac not hex: {e}")))?;
        let expected_mac = self.compute_mac(&payload_bytes);
        if expected_mac.ct_eq(&mac_bytes).unwrap_u8() != 1 {
            return Err(TokenError::InvalidSignature);
        }
        let payload: TokenPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| TokenError::Malformed(format!("payload JSON: {e}")))?;

        // 2. Session id binding.
        if payload.session_id != self.session_id {
            return Err(TokenError::CrossSessionReuse);
        }

        // 3. Expiry.
        if payload.expires_at_unix <= now_unix {
            return Err(TokenError::Expired);
        }

        // 4. Replay.
        let mac_key = hex::encode(&mac_bytes);
        {
            let mut consumed = self.consumed.lock().expect("token consumed-set poisoned");
            prune_expired(&mut consumed, now_unix);
            if consumed.contains_key(&mac_key) {
                return Err(TokenError::Replay);
            }
        }

        // 6. Tool match. (ADR-0004 step 6.)
        if payload.tool != ctx.tool {
            return Err(TokenError::ToolMismatch);
        }

        // 7. Schema drift. (ADR-0004 step 7.)
        if payload.bundle_version != ctx.current_bundle_version {
            return Err(TokenError::SchemaDrift);
        }

        // 5. Diff drift. Done last among "data" checks so wrong-shape
        //    inputs surface their specific error first; ordering does
        //    not weaken any guarantee.
        if payload.diff_sha256 != ctx.current_diff_sha256 {
            return Err(TokenError::DiffDrift);
        }

        // All checks passed: consume the token.
        {
            let mut consumed = self.consumed.lock().expect("token consumed-set poisoned");
            consumed.insert(mac_key, payload.expires_at_unix);
        }
        Ok(VerifiedToken { payload })
    }

    fn compute_mac(&self, payload: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).expect("32-byte key always valid");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }
}

fn prune_expired(consumed: &mut HashMap<String, u64>, now_unix: u64) {
    consumed.retain(|_, &mut expires| expires > now_unix);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Helper to build a `TokenPayload` for tests / call sites that don't
/// want to manage timestamps by hand. The session id is filled in by
/// [`Session::issue`].
pub fn payload(
    tool: impl Into<String>,
    target: serde_json::Value,
    diff_sha256: impl Into<String>,
    bundle_version: impl Into<String>,
    issued_at_unix: u64,
    ttl_secs: u64,
) -> TokenPayload {
    TokenPayload {
        v: PROTOCOL_VERSION,
        session_id: String::new(), // overwritten by Session::issue
        tool: tool.into(),
        target,
        diff_sha256: diff_sha256.into(),
        bundle_version: bundle_version.into(),
        issued_at_unix,
        expires_at_unix: issued_at_unix + ttl_secs,
    }
}

/// Wrapper for the `getrandom` error so callers don't need to depend on it directly.
pub mod getrandom_error {
    use std::fmt;

    #[derive(Debug)]
    pub struct Error(String);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}

    pub(crate) fn wrap(e: rand::rand_core::OsError) -> Error {
        Error(format!("OS RNG failure: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixed_session() -> Session {
        Session::from_raw([1u8; 32], [9u8; 32])
    }

    fn sample_payload(tool: &str) -> TokenPayload {
        payload(
            tool,
            json!({"file": "/managed/x.lsrules"}),
            "diff-abc",
            "6.3.3",
            1_000_000,
            60,
        )
    }

    fn sample_ctx<'a>(tool: &'a str) -> VerifyContext<'a> {
        VerifyContext {
            tool,
            current_diff_sha256: "diff-abc",
            current_bundle_version: "6.3.3",
        }
    }

    // ---------- ADR-0004 §9 test matrix (8 cases) ----------

    #[test]
    fn happy_path_accepts_fresh_token() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        let result = s.verify_at(
            &token,
            &sample_ctx("apply_lsrules_file_to_live_model"),
            1_000_030,
        );
        assert!(result.is_ok(), "got: {result:?}");
    }

    #[test]
    fn invalid_signature_when_one_byte_flipped() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        // Flip the last hex char — that's part of the MAC.
        let raw = token.into_string();
        let mut bytes: Vec<char> = raw.chars().collect();
        let last = bytes.last_mut().unwrap();
        *last = if *last == '0' { '1' } else { '0' };
        let mutated = Token(bytes.into_iter().collect());
        assert_eq!(
            s.verify_at(
                &mutated,
                &sample_ctx("apply_lsrules_file_to_live_model"),
                1_000_030
            ),
            Err(TokenError::InvalidSignature)
        );
    }

    #[test]
    fn cross_session_reuse_when_token_from_different_session() {
        let issuer = Session::from_raw([1u8; 32], [9u8; 32]);
        let verifier = Session::from_raw([2u8; 32], [9u8; 32]); // same key, different session_id
        let token = issuer.issue(sample_payload("apply_lsrules_file_to_live_model"));
        assert_eq!(
            verifier.verify_at(
                &token,
                &sample_ctx("apply_lsrules_file_to_live_model"),
                1_000_030
            ),
            Err(TokenError::CrossSessionReuse)
        );
    }

    #[test]
    fn expired_when_now_past_expires_at() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        // payload expires at issued_at + 60 = 1_000_060
        assert_eq!(
            s.verify_at(
                &token,
                &sample_ctx("apply_lsrules_file_to_live_model"),
                1_000_999
            ),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn replay_rejected_on_second_consume() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        let ctx = sample_ctx("apply_lsrules_file_to_live_model");
        assert!(s.verify_at(&token, &ctx, 1_000_030).is_ok());
        assert_eq!(
            s.verify_at(&token, &ctx, 1_000_031),
            Err(TokenError::Replay)
        );
    }

    #[test]
    fn diff_drift_when_current_diff_differs() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        let mut ctx = sample_ctx("apply_lsrules_file_to_live_model");
        ctx.current_diff_sha256 = "diff-DIFFERENT";
        assert_eq!(
            s.verify_at(&token, &ctx, 1_000_030),
            Err(TokenError::DiffDrift)
        );
    }

    #[test]
    fn tool_mismatch_when_called_for_different_tool() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        assert_eq!(
            s.verify_at(&token, &sample_ctx("add_rule_to_live_model"), 1_000_030),
            Err(TokenError::ToolMismatch)
        );
    }

    #[test]
    fn schema_drift_when_bundle_version_differs() {
        let s = fixed_session();
        let token = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        let mut ctx = sample_ctx("apply_lsrules_file_to_live_model");
        ctx.current_bundle_version = "6.4.0";
        assert_eq!(
            s.verify_at(&token, &ctx, 1_000_030),
            Err(TokenError::SchemaDrift)
        );
    }

    // ---------- additional invariants ----------

    #[test]
    fn issue_overwrites_payload_session_id() {
        let s = fixed_session();
        let mut p = sample_payload("apply_lsrules_file_to_live_model");
        p.session_id = "attacker-supplied".into();
        let token = s.issue(p);
        let (payload_hex, _) = token.split().unwrap();
        let bytes = hex::decode(payload_hex).unwrap();
        let parsed: TokenPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.session_id, s.session_id());
    }

    #[test]
    fn issue_sets_protocol_version() {
        let s = fixed_session();
        let mut p = sample_payload("apply_lsrules_file_to_live_model");
        p.v = 999;
        let token = s.issue(p);
        let (payload_hex, _) = token.split().unwrap();
        let bytes = hex::decode(payload_hex).unwrap();
        let parsed: TokenPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.v, PROTOCOL_VERSION);
    }

    #[test]
    fn malformed_token_no_dot_separator() {
        let s = fixed_session();
        let bad = Token("abcdef".into());
        let err = s.verify_at(&bad, &sample_ctx("x"), 1_000_030).unwrap_err();
        assert!(matches!(err, TokenError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn malformed_token_non_hex_payload() {
        let s = fixed_session();
        let bad = Token("not-hex.aabbcc".into());
        let err = s.verify_at(&bad, &sample_ctx("x"), 1_000_030).unwrap_err();
        assert!(matches!(err, TokenError::Malformed(_)));
    }

    #[test]
    fn fresh_session_has_unique_session_id() {
        let s1 = Session::new().expect("OS RNG");
        let s2 = Session::new().expect("OS RNG");
        assert_ne!(s1.session_id(), s2.session_id());
        assert_eq!(s1.session_id().len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn consumed_set_pruning_removes_expired_entries() {
        let s = fixed_session();
        let token1 = s.issue(sample_payload("apply_lsrules_file_to_live_model"));
        let ctx = sample_ctx("apply_lsrules_file_to_live_model");
        s.verify_at(&token1, &ctx, 1_000_030).unwrap();
        assert_eq!(s.consumed.lock().unwrap().len(), 1);

        // Issue a second, fresh token whose payload's issued_at is far enough
        // in the future that token1 has expired by the time we verify it.
        let token2 = s.issue(payload(
            "apply_lsrules_file_to_live_model",
            json!({"file": "/managed/y.lsrules"}),
            "diff-xyz",
            "6.3.3",
            2_000_000,
            60,
        ));
        let mut ctx2 = sample_ctx("apply_lsrules_file_to_live_model");
        ctx2.current_diff_sha256 = "diff-xyz";
        s.verify_at(&token2, &ctx2, 2_000_010).unwrap();

        // Pruning during token2's replay check removed expired token1;
        // only token2 remains.
        let consumed = s.consumed.lock().unwrap();
        assert_eq!(consumed.len(), 1);
    }

    #[test]
    fn token_error_messages_carry_stable_tags() {
        // The wire-format tag is part of the audit log contract.
        for (err, tag) in [
            (TokenError::InvalidSignature, "INVALID_SIGNATURE"),
            (TokenError::CrossSessionReuse, "CROSS_SESSION_REUSE"),
            (TokenError::Expired, "EXPIRED"),
            (TokenError::Replay, "REPLAY"),
            (TokenError::DiffDrift, "DIFF_DRIFT"),
            (TokenError::ToolMismatch, "TOOL_MISMATCH"),
            (TokenError::SchemaDrift, "SCHEMA_DRIFT"),
        ] {
            assert!(
                err.to_string().starts_with(tag),
                "{err:?} message must start with {tag}"
            );
        }
    }
}
