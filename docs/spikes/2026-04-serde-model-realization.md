# Realization note — model serde types (2026-04)

Tracks [#24](https://github.com/torsday/little-snitch-mcp/issues/24). **Outcome: realized by spike [#2](https://github.com/torsday/little-snitch-mcp/issues/2)'s production commit `2f7437c` ("feat(model): add serde types for live model JSON with forward-compat extras").** This note documents the per-AC mapping and one deliberate design deviation so the closure is auditable.

## Why this is closed without a separate PR

Spike #2 was time-boxed to validate the serde shape against a real `export-model`; the validated shape is exactly the production code. There was nothing left for #24 to add — it was the implementation ticket for the same work. The close-out on #2's PR mentioned only #2, not #24, leaving #24 as drift. Same shape as the [#3-realized-by-#43](https://github.com/torsday/little-snitch-mcp/issues/3) cycle.

## Per-AC realization

| AC | Implementation site |
|----|---------------------|
| `model::Model` covers all top-level keys (rules, groups, profiles, noProfilePseudoProfile, users, globalDefaults, codeRequirements, developerTeamNames, lastSeenExecutableByCodeIdentifier, networkTriggers, blocklistStatistics, statisticsModelCreationDate, factoryRuleSetVersion, bundleVersion, disabledDomainsInLists, disabledHostNamesInLists, disabledIPAddressRangesInLists) | [`src/model/mod.rs`](../../src/model/mod.rs) `pub struct Model { … }` — every key present + `extra: HashMap<String, serde_json::Value>` for forward-compat |
| `Rule` enum/struct with discriminated unions: process variants (`Path` / `Any` / `RequiresTrustedSignature` / `CodeId`), remote variants (`Special` / `Domains` / `Hosts` / `Addresses`) | **Deviation** — see "Design deviation" below |
| Optional fields: `Option<T>` + `#[serde(skip_serializing_if = "Option::is_none")]` | [`src/model/rule.rs`](../../src/model/rule.rs) `Rule` struct fields use this pattern uniformly |
| Unknown fields: `#[serde(flatten)] HashMap<String, serde_json::Value>` per struct | Every emitting struct (Model, Rule, Group, User, RemoteOverlayEntry) carries an `extra` field with `#[serde(flatten)]` |
| Round-trip test: deserialize fixture model → serialize → byte-equal after canonical key sort | Cycle 15 added [`src/model/patch.rs`](../../src/model/patch.rs) `canonical_value` + tests pinning idempotence under serialize → reparse → re-canonicalize. Combined with the Rule preservation tests (`changing_only_action_preserves_every_other_field`), the round-trip property is empirically locked |
| Single-vs-array string normalization for `remote-domains`/`remote-hosts`/`remote-addresses` | [`src/model/rule.rs`](../../src/model/rule.rs) `pub enum StringOrVec { One(String), Many(Vec<String>) }` with `#[serde(untagged)]` deserialization. Construction discipline (single-element collapses to `One`) enforced by [`src/model/rule_construct.rs`](../../src/model/rule_construct.rs) `string_or_vec()` |

## Design deviation

The AC asked for "discriminated unions" on `Rule.process` and `Rule.remote-*`. The implementation uses **flat optional fields** (`process: Option<String>`, `requires_trusted_signature_for_any_process: Option<bool>`, `remote: Option<String>`, `remote_domains/hosts/addresses: Option<StringOrVec>`).

Spike #2's note records the reasoning: *"These are kept as flat optional fields rather than discriminated enums so that round-trip preservation is mechanically obvious — every JSON key has a direct field or lands in `extra`."* A discriminated enum at the storage layer would have to deserialize the JSON shape into a tagged variant and back, opening a path for serde to re-encode subtle field shapes (e.g. omitting an `Option::None` that LS itself emitted as `null`).

The discriminated-union shape *does* exist on the **construction** side: [`src/model/rule_construct.rs`](../../src/model/rule_construct.rs) defines `enum ProcessMatcher { Path(String), Any, RequiresTrustedSignature, CodeId(String) }` and `enum Remote { Domains(Vec<String>), Hosts(Vec<String>), Addresses(Vec<String>), Special(String), Any }`. These are the operator-facing types fed to `construct(spec)`. Cycle 16 (#44) hardened the serde tagging to `#[serde(tag = "kind", content = "value")]` so JSON in/out works.

**Net:** the spirit of the AC ("the type system distinguishes the variants the operator can construct") is satisfied at the constructor layer; the storage layer keeps the round-trip-safe flat shape.

## What this unblocks

Already realized: every model-touching tool from cycles 12 onward (rule constructor #58, patch + canonicalize #51, group resolver #52, all the apply-side prepare/apply pairs in #44/#59/#60/#62/#63, plus #46's rule-level guards and #49's bundleVersion check). #24 closing is paperwork — the dependents have been shipping against the realized types for the better part of a day.
