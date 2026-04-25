# Spike — Group-name resolver chain (2026-04)

Tracks [#4](https://github.com/torsday/little-snitch-mcp/issues/4). **Outcome: ship the four-step resolver chain below; track typed `Verified` vs `BestEffort` results; never silently reformat input.** Production implementation belongs to [#52](https://github.com/torsday/little-snitch-mcp/issues/52).

## Constraint we're solving

`little-snitch rulegroup -e/-d` accepts **only** the localized display name (smoke 1, [docs/feasibility-report.md](../feasibility-report.md) §"Smoke 1"). Group IDs, `kind` values, and arbitrary strings are all rejected with `Rule group or blocklist "X" not found.` and exit 1. Builtin groups have `name: null` in the model — display name is derived from `kind`. The MCP must accept whatever shape the LLM gives it (display name, kind, group ID, fuzzy partial) and resolve to the display name LS accepts, **without** silently rewriting input in a way that hides ambiguity.

## Resolver chain (in order)

Each step is a function that returns `Option<Resolved>` and stops the chain on first hit.

| # | Step | Source of truth | Result kind |
|---|------|------------------|-------------|
| 1 | **Display-name passthrough** | Input matches a non-null `name` field on any entry in `model.groups` | `Verified` |
| 2 | **Kind → display lookup** | Input matches a `kind` value; look up the display name in the shipped seed table | `Verified` |
| 3 | **ID → entry → name** | Input matches a `groups[].id`; recurse through steps 1–2 against the located entry's `name`/`kind` | `Verified` |
| 4 | **Best-effort passthrough** | None of the above matched; pass the input through verbatim and let LS judge | `BestEffort` |

The chain is **strict**: rule 4 never runs as a fallback for rule 1's success — it only fires when 1, 2, and 3 all returned `None`. Fuzzy match (Levenshtein, prefix) is intentionally **not** part of the chain — see "Considered and rejected" below.

## Result type

```rust
pub enum Resolved<'a> {
    /// Input mapped to a known display name with high confidence.
    /// `live_write` callers may proceed.
    Verified {
        /// The exact string to pass to `rulegroup -e/-d`.
        display_name: &'a str,
        /// Which step in the chain produced this result. Useful for
        /// audit logs and `doctor`.
        via: ResolverStep,
    },
    /// We can't prove this string maps to a known group, but we have
    /// no proof it doesn't either. `live_write` is *not* allowed; callers
    /// must escalate to `live_write_strong` and obtain explicit user
    /// acknowledgement before forwarding the string.
    BestEffort {
        /// The input string verbatim. We do not transform it.
        candidate: &'a str,
        /// Why we couldn't verify (no kind hit, no name hit, no id hit).
        reason: BestEffortReason,
    },
}

pub enum ResolverStep { DisplayName, Kind, Id }

pub enum BestEffortReason {
    /// Input doesn't match any known kind, name, or id.
    NoKnownMapping,
    /// Input matched a `kind` we don't have a seed entry for.
    /// `unknown_kind_warning` was logged.
    UnknownKind { kind: String },
}
```

The `Verified` / `BestEffort` distinction is **load-bearing**: the [`Classification`](../../src/safety/classification.rs) gate on `enable_rule_group` / `disable_rule_group` will refuse to run as `live_write` against a `BestEffort` result. The strong-ack flow lives in [#46](https://github.com/torsday/little-snitch-mcp/issues/46) / [#53](https://github.com/torsday/little-snitch-mcp/issues/53).

## Seed `kind → display` map (initial)

Empirically grounded against the smoke-1 results:

| kind | display name (en_US) |
|------|----------------------|
| `builtinMacOSServices` | `macOS Services` |
| `builtinICloudServices` | `iCloud Services` |

The map will grow as we encounter more `kind` values during dogfooding. Two operational rules:

1. **Locale assumption.** Display names are localized by LS. The seed table targets `en_US` because that's the only locale we've smoke-tested. Non-`en_US` users will hit step 4 (`BestEffort`) for builtin groups until we widen the table or support locale-aware lookup. Document this clearly in the tool description so the LLM can prompt the user appropriately.
2. **Read-side refusal.** When a `kind` not in the seed table appears in `model.groups`, the resolver emits `unknown_kind_warning` (see below) and returns `BestEffort`. This is by design — silently passing the kind through to LS would yield "not found" without an actionable error.

## Unknown-kind warning shape

```json
{
  "level": "warn",
  "event": "unknown_kind_warning",
  "kind": "builtinNewlyAddedThing",
  "groups_affected": ["aaaaaf", "aaaaag"],
  "remediation": "add to safety::group_resolver::SEED_KIND_MAP or report at https://github.com/torsday/little-snitch-mcp/issues"
}
```

`doctor` will surface this as a single line per unique `kind`, with the count of affected groups, so the operator sees the gap without reading raw logs.

## Test plan (for #52)

| Test | Input | Expected |
|------|-------|----------|
| display-name passthrough | `macOS Services` (exists in model) | `Verified { via: DisplayName }` |
| kind lookup, seeded | `builtinMacOSServices` | `Verified { via: Kind }` (resolves to `macOS Services`) |
| id lookup → name | `aaaaac` (group with `name: "macOS Services"`) | `Verified { via: Id }` |
| id lookup → kind | `aaaaae` (group with `name: null, kind: builtinICloudServices`) | `Verified { via: Id }` |
| unknown kind | `builtinNewlyAddedThing` | `BestEffort { reason: UnknownKind { ... } }` + warning logged |
| unknown id | `zzzz99` | `BestEffort { reason: NoKnownMapping }` |
| unknown name | `Some Random String` | `BestEffort { reason: NoKnownMapping }` |
| empty input | `""` | hard error (parse-time refusal, not a Resolver concern) |

## Considered and rejected

- **Fuzzy matching (Levenshtein, prefix).** Tempting because it improves "did you mean" UX, but it converts an LLM typo into a silent mutation of a *different* group. Rejected. The LLM should be forced to handle "not found" as a structured error, not get a guess back. If we want this later it goes behind an explicit `fuzzy: true` parameter and always returns `BestEffort`.
- **Auto-discovery of new kinds via web fetch / docs scrape.** Rejected for v1; opens a network surface and a third-party trust dependency for what is fundamentally a constant table.
- **Caching the resolved name across calls.** Rejected for v1; the model is small (typically <100 groups) and re-reading is cheap. Caching adds invalidation complexity for negligible win.
- **Returning a list of candidates on miss.** Considered. Decided the `BestEffort` path with `unknown_kind_warning` carries the same operator value at lower complexity. The `Backlog`/follow-up could revisit "structured candidates" if `doctor` reporting proves insufficient.

## Findings worth recording

1. **The `Verified` / `BestEffort` split came from the safety side, not the model side.** It's not "did we find it" — it's "are we willing to mutate live state on this match?". Keeping that framing in the type names makes downstream call sites self-documenting.
2. **Seed table maintenance is a dogfooding loop, not a one-shot translation.** We will discover new `kind`s in production. The `unknown_kind_warning` path is the keep-this-honest mechanism — without it the seed table silently rots.
3. **Step 4 (passthrough) is the part that earns `BestEffort` for almost everyone.** A user-created group will hit step 1; a builtin will hit step 2; an LLM-typed-it-wrong string will hit step 4. That distribution is the right shape: typos pay the safety tax, real groups don't.
