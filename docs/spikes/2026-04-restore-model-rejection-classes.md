# Spike — `restore-model` rejection classes (2026-04)

Tracks [#7](https://github.com/torsday/little-snitch-mcp/issues/7). **Outcome: ship the probe protocol below; defer empirical data collection to whoever next runs LS locally.** The categorization framework, per-probe template, and pre-flight rule template are separable design artifacts; running the probes is a 30-minute mechanical task once the implementer has a live LS instance.

## Why doc-only

The spike's data-collection half (`(probe, command, exit code, stderr, observed model state)` table) requires hands-on LS interaction. Authoring the table from documentation alone would manufacture data that downstream code (the pre-flight validator) would treat as authoritative — a worse outcome than no data. The protocol design is what unblocks the probing work; ship it now.

## Categorization framework

Each probe outcome is exactly one of:

| Category | Definition | Pre-flight stance |
|----------|------------|-------------------|
| **hard-reject** | LS exits non-zero; model is unchanged. The error is observable from the CLI. | **Refuse before invocation.** The MCP must catch this client-side or the LLM gets a useless "exit 1" with no context. |
| **silent-strip** | LS exits 0 but the offending field/rule is missing from a fresh `export-model`. The patch was partially accepted. | **Refuse before invocation, OR diff-and-warn after.** Silent stripping is the worst class — the user thinks they wrote a rule, but LS dropped it. The token-protocol diff binding from ADR-0004 §9 catches this *if* we always re-export-and-diff after every restore. |
| **accept-with-warning** | LS exits 0 and the rule is present, but stderr or LS's own logs flagged the issue. Useful but unreliable to depend on. | **Surface the warning** in the tool response. Don't refuse — LS chose to accept. |
| **silent-modify** | LS exits 0 and the rule is present but with one or more fields rewritten (`origin: "frontend"` → some default, dates normalized, etc.). | **Refuse before invocation, OR canonicalize before diffing.** This is what smoke-3 already taught us about the "corrected rule shape"; codify the canonical form so future surprises are caught by diff rather than by user complaints. |

The four categories are **mutually exclusive but not exhaustive**: a probe could fail in a way that doesn't fit (e.g. LS hangs, prompts for input, mutates an unrelated field). When a probe lands outside the framework, *that* is the finding worth recording — it means we need a fifth category.

## Per-probe template

Each probe contributes a row in the result table. Rows have this shape:

```markdown
### Probe N — <one-line description>

**Setup.** What the model looked like before the probe. If a fresh `export-model` is the baseline, say so explicitly.

**Patch.** The deliberately-wrong patch JSON, inline (or a path under `tests/fixtures/probes/`).

**Command.** The exact `little-snitch restore-model -t < patch.json` invocation, including any env vars.

**Observed.**
- Exit code: <integer>
- Stderr: <verbatim, or "empty">
- Diff against baseline (`diff <(export-model) <(saved baseline)`): <one of "no change", "patch applied verbatim", or a delta description>

**Categorized as.** <hard-reject / silent-strip / accept-with-warning / silent-modify / OTHER>

**Pre-flight rule.** What `safety::restore_model::preflight(patch)` should refuse before sending this kind of patch to LS, in one sentence.

**Audit-finding update.** Whether this downgrades or escalates the relevant ADR-0004 §3 hard-guard or ADR-0007 risk row.
```

## Probes (the 10 to run)

The first six come straight from the AC; the next four were added during this spike from cross-references with [ADR-0004 §3](../adr/0004-safety-permissions-and-confirmation.md), [ADR-0004 §10](../adr/0004-safety-permissions-and-confirmation.md), and the smoke-3 corrected-rule-construction findings.

| # | Probe | Hypothesis (to be confirmed) |
|---|-------|------------------------------|
| 1 | Conflicting rules (same process+remote, different action) | likely **accept** — LS uses ranking from spike #6 |
| 2 | Rule referencing a non-existent `group: "<missing-id>"` | likely **silent-strip** of the group ref or **hard-reject** of the rule |
| 3 | `uid` not present in `model.users` | likely **hard-reject** (uid validation was visible in earlier audits) |
| 4 | `process` path with null bytes / non-UTF-8 | **hard-reject** expected; verify the message names the field |
| 5 | Duplicate rule (identical to existing) | likely **silent-strip** of the duplicate or **accept** with two equal rules in `model.rules` |
| 6 | Rule missing a discovered-required field | likely **hard-reject** — but *which* fields are required is itself the finding |
| 7 | Rule with `origin` not in {`"frontend"`, `"factory"`, …} | smoke-3 showed `origin: "frontend"` works; probe other strings to learn the enum |
| 8 | Rule with `factoryID` set on a non-factory rule | per ADR-0004 §8 this should be **hard-reject** or **silent-strip**; confirm |
| 9 | Patch that re-introduces a `protected: true` rule the user previously deleted | per ADR-0004 §8; the smoke is whether LS resurrects a deleted protected rule from a stale backup |
| 10 | Patch that flips `globalDefaults.networkFilterEnabled` to `false` | should be **silent-modify** at minimum (the kill-switch); confirm whether `-t` blocks it |

For each row, the implementer fills `Hypothesis` first, then runs the probe and either confirms or contradicts. The contradicting cases are the spike's most valuable findings.

## Pre-flight validator template

Once the categorization table is filled, encode each `hard-reject` and `silent-strip` row as a function in `safety::restore_model::preflight`. Skeleton:

```rust
//! Pre-flight validation for restore-model patches.
//!
//! Empirically derived from spike #7. Each function refuses a patch
//! shape we have observed LS hard-reject or silently strip. Adding
//! a new check requires a probe row in
//! docs/spikes/2026-04-restore-model-rejection-classes.md cited
//! inline.

pub fn preflight(patch: &Model) -> Result<(), PreflightError> {
    refuse_unknown_uid(patch)?;            // probe 3
    refuse_invalid_process_path(patch)?;   // probe 4
    refuse_missing_required_fields(patch)?; // probe 6
    refuse_factory_id_on_non_factory(patch)?; // probe 8
    refuse_kill_switch_flip(patch)?;       // probe 10 — overlaps with safety::prefs HARD_DENY_KEYS
    Ok(())
}
```

The kill-switch check at the bottom **already exists** in [`safety::prefs`](../../src/safety/prefs.rs) — wire to it via the `is_kill_switch_key` helper rather than reimplementing.

## What this unblocks

[#62](https://github.com/torsday/little-snitch-mcp/issues/62) (`apply_lsrules_file_to_live_model`), [#59](https://github.com/torsday/little-snitch-mcp/issues/59) (`add_rule_to_live_model`), [#60](https://github.com/torsday/little-snitch-mcp/issues/60) (`update`/`remove_rule_in_live_model`) — every Track-B-surgery tool that calls `restore-model -t` should run pre-flight against a populated categorization table before invocation. Without the table the pre-flight is best-effort; with it, ADR-0007 risk R3 downgrades from 🔴 to 🟡.

## Out of scope (deliberate)

- **Auto-running the probes from CI.** Probes mutate the live LS model. Even with a `-t` flag the test rig is fragile and LS-version-coupled. The probes are a one-time-per-major-version mechanical task; document, don't automate.
- **Building a fixture library of pre-baked rejection cases.** Tempting but it ages with each LS release. The probe protocol is the durable artifact; the fixtures it produces are version-specific and live in the categorization table here.

## Findings worth recording (post-run, by the implementer)

When the probes run, three things go in this section:

1. **Any probe that lands outside the four categories** (the "OTHER" outcomes). These suggest the framework needs a fifth category.
2. **Any hypothesis above that the run contradicted.** Contradicted hypotheses are the spike's actual deliverable — they're things we previously assumed about LS that weren't true.
3. **Any new probe the run suggested.** Real probing tends to surface adjacent cases worth verifying ("if X is hard-rejected, what about Y?"); add them here for the next round.
