# Spike — Confirmation-token protocol (2026-04)

Tracks [#3](https://github.com/torsday/little-snitch-mcp/issues/3). **Outcome: spike realized directly by the production implementation in [#43](https://github.com/torsday/little-snitch-mcp/issues/43) (PR [#85](https://github.com/torsday/little-snitch-mcp/pull/85)).** No separate prototype was built; the design risk the spike was meant to surface turned out to be low enough that the production module shipped on the first pass.

## What the spike was meant to validate

ADR-0004 §9 specifies an HMAC-SHA256 confirmation-token protocol with seven reject conditions guarding every `live_write` tool. Before committing the design across 10+ tools, the spike asked us to:

1. Build a per-session HMAC key and ensure it never persists or logs.
2. Prove all eight verifier checks (happy path + 7 reject reasons) in dedicated tests.
3. Verify constant-time signature compare ergonomics.
4. Verify in-memory consumed-set behaviour with TTL pruning.

## What actually shipped

The implementation in [`src/safety/token.rs`](../../src/safety/token.rs) covers every spike AC item byte-for-byte:

| Spike AC | Production realization |
|----------|------------------------|
| Per-session HMAC key, never persisted/logged | `Session::new` generates a 32-byte OS-RNG key; field is private; no accessor; never serialized |
| Token payload includes session_id, tool, target, diff_sha256, issued_at, expires_at | `TokenPayload` struct; field names mirror ADR-0004 §9 verbatim |
| HMAC-SHA256, constant-time signing | `hmac` + `sha2` crates; `subtle::ConstantTimeEq` for verify-side compare |
| happy path → accept | `tests::happy_path_accepts_fresh_token` |
| INVALID_SIGNATURE | `tests::invalid_signature_when_one_byte_flipped` |
| CROSS_SESSION_REUSE | `tests::cross_session_reuse_when_token_from_different_session` |
| EXPIRED | `tests::expired_when_now_past_expires_at` |
| REPLAY | `tests::replay_rejected_on_second_consume` |
| DIFF_DRIFT | `tests::diff_drift_when_current_diff_differs` |
| TOOL_MISMATCH | `tests::tool_mismatch_when_called_for_different_tool` |
| SCHEMA_DRIFT | `tests::schema_drift_when_bundle_version_differs` |

## Findings worth recording

1. **Design held without iteration.** The ADR §9 protocol shape was correct at first implementation. No protocol-level changes were required after writing tests.

2. **`ServerInfo`-style `#[non_exhaustive]` patterns are common in the safety domain.** None tripped here, but the `Token` wire format chose `<base16(payload)>.<base16(hmac)>` over JSON object framing specifically to avoid the JSON-RPC-level escaping cost. Worth keeping in mind for future security envelopes.

3. **Verifier check ordering matters less than expected.** ADR-0004 §9 numbers the checks 1–7. The implementation reorders 5 (DIFF_DRIFT) to last among data checks so wrong-shape inputs surface their specific error first. This does not weaken any guarantee — DIFF_DRIFT is informational, not a security boundary on its own — but it makes audit logs more useful.

4. **Diff hashing was deliberately externalized.** The verifier accepts a precomputed `current_diff_sha256` in `VerifyContext` rather than computing it itself. This keeps `safety::token` pure (testable without a live LS), and aligns the responsibility boundary with the future dispatcher that will own model re-export + diff computation anyway.

5. **One forward-compatibility hook was added.** `PROTOCOL_VERSION = 1` is enforced by `Session::issue` overwriting the caller-supplied `v` field. Bumping the protocol later is a code change in one place.

## What this unblocks

- All `live_write` and `live_write_strong` tools can now wire to `Session::verify` directly: #44 (`prepare_live_model_change`), #59, #60, #62, #63.
- The `prepare_*`/`apply_*` symmetry across the M3 mutation surface is concrete: a `prepare_*` calls `Session::issue`, the matching `apply_*` calls `Session::verify` with the recomputed `current_diff_sha256` and `current_bundle_version`.
