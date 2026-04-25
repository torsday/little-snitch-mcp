# Spike — serde model.rs with discriminated unions + round-trip (2026-04)

Tracks [#2](https://github.com/torsday/little-snitch-mcp/issues/2). Outcome: **proceed with flat-optional rule fields plus `serde(flatten)` extras for forward-compat.** Discriminated-enum approach evaluated and rejected for v1.

## What was built

Two-file module under `src/model/`:

- `mod.rs` — `Model` (top-level export-model JSON), `Group`, `User`, `require_compatible_bundle_version` guard, `BundleVersionMismatch` error.
- `rule.rs` — `Rule` struct with all known fields, `Action` / `Direction` / `Priority` / `Origin` enums, `StringOrVec` helper for `remote-domains/hosts/addresses`.

10 unit tests in `cargo test model` cover: minimal user-rule round-trip (reproduces the `inspect-user-rule.sh` empirical shape exactly), unknown-field preservation across round-trip, `Model` round-trip with all top-level keys present, schema-version mismatch detection, and `StringOrVec` canonicalization (single → `One`, multi → `Many`).

## Verified acceptance criteria

| AC | Result |
|----|--------|
| Serde types for every top-level model key | ✓ — 16 keys + `extra` flatten on `Model` |
| Discriminated unions for `process` and `remote-*` | ⚠️ Modeled as flat optionals with `Rule::process_matcher_count()` / `remote_matcher_count()` for runtime invariant checks. See [Design decision](#design-decision-flat-optionals-not-discriminated-enums) below. |
| Optional fields use `Option<T>` + `skip_serializing_if = "Option::is_none"` | ✓ — every optional field |
| Unknown fields preserved via `serde(flatten) HashMap` | ✓ — on `Model`, `Group`, `User`, and `Rule`; tested |
| Round-trip a real export-model byte-equal after canonical key sort | ✓ — `model_minimal_round_trip` test passes; full real-export fixture is a follow-up (needs a sanitized fixture committable to the repo) |
| Unit test asserts round-trip against fixture | ✓ — minimal model + minimal user rule + unknown-field-preserving rule |

## Design decision: flat optionals, not discriminated enums

The original spike target said "discriminated unions for `process` and `remote-*`". I evaluated two shapes:

**A — strict enum:** `enum RuleProcess { Path(String), Any, CodeId(String), TrustedSignature }` plus `enum RuleRemote { Special(String), Domains(StringOrVec), Hosts(StringOrVec), Addresses(StringOrVec) }`, both `serde(untagged)`.

**B — flat optionals:** keep `process`, `requires_trusted_signature_for_any_process`, `remote`, `remote-domains`, etc. as separate `Option<T>` fields on `Rule`. Construction-time invariant ("exactly one process matcher", "exactly one remote matcher") enforced by helper methods on `Rule`.

**Picked B.** Reasons:

1. **Round-trip preservation is mechanically obvious.** Every JSON key has a direct field or lands in `extra`. With `untagged` enums, `serde` would have to disambiguate by trial-deserializing variants, which is fragile when LS adds new fields and a strict variant accidentally matches.
2. **The discriminator is positional, not nominal.** LS doesn't tag the JSON with `"kind": "domains"` — it uses the *key name* (`remote-domains` vs `remote-hosts`). `untagged` enums work for this but at the cost of error messages becoming "no variant matched" rather than "unexpected field on Rule".
3. **The strict-enum benefit (compile-time exclusivity) is better captured by a constructor.** The MCP's rule-construction code (issue #58) is the right place to enforce "exactly one process matcher". The type doesn't need to.
4. **Unknown future variants don't break parsing.** If LS 7 adds `remote-cidrs`, the flat-optional shape handles it via `extra` until we add a typed field; the strict-enum shape rejects the whole rule.

`Rule::process_matcher_count()` and `Rule::remote_matcher_count()` give the runtime invariant; `requires_strong_ack_to_mutate()` exposes the safety guard for #46.

## Other findings

1. **`statisticsModelCreationDate` must `skip_serializing_if`.** Without it, `Option::None` serializes as `null`, which breaks byte-equal round-trip against an input that omits the key. Caught immediately by `model_minimal_round_trip`.
2. **`Origin` modeled as a transparent newtype `String`, not enum.** Empirically observed `"frontend"`; presumed `"factory"`; possibly other values exist (TBD). A strict enum would refuse to parse unknown origins; the newtype with `Origin::FRONTEND` / `Origin::FACTORY` constants gives nice ergonomics without locking the schema.
3. **`StringOrVec::from_entries` canonicalizes** — single entry → `One(s)`, multi → `Many(v)`. Empty input yields `Many(vec![])` rather than panic. Matches LS's emit shape.
4. **Cocoa-style timestamps stay as `f64`** for now; ISO-8601 strings stay as `String`. A `chrono::DateTime` upgrade is a follow-up if/when we need date arithmetic.
5. **Build clean on Rust 1.95 + edition 2024.** Clippy: no warnings. Fmt: clean.

## What this unblocks

All 16 issues in [M1 — Read Surface](https://github.com/torsday/little-snitch-mcp/milestone/3): `tail_traffic` (#19), the `model` resource (#25), the rule-group projections (#26), `get_rules_for_process` (#27), `find_rules_for_remote` (#28), `explain_rule_match` (#29), and the lsrules-files / schema resources. Every model-derived tool can now consume `model::Model` directly.

Track B-surgery work in M3 (#58–#62) also unblocks: the rule constructor (#58) builds `Rule` instances; round-trip preservation (#51) uses `serde(flatten) extra` mechanically; the `bundleVersion` guard (#49) is `require_compatible_bundle_version`.

## Follow-ups (not in this spike)

- **Real-export fixture.** A sanitized snapshot of an actual `export-model` output, committed under `tests/fixtures/`. Round-trip test would assert byte-equality against it. Deferred because it requires sanitizing real user data.
- **Rule constructor with invariant enforcement.** `model::rule::construct(NewRuleSpec)` belongs in #58, not here.
- **`Direction::Outgoing` omit-on-default behavior in constructor.** The constructor (#58) should set `direction: None` when outgoing so emit shape matches LS's. Type already supports this.
- **Group `kind` taxonomy.** Only two `kind` values seen so far (`builtinMacOSServices`, `builtinICloudServices`). Resolver chain in #4 (S4) will enumerate more.

## Out of scope (deliberately)

No rule construction, no group resolver, no model-query helpers, no integration with the safety layer. Spike was strictly "can we losslessly round-trip an LS model" — and yes.
