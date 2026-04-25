# ADR-0002 — CRUD strategy: declarative `.lsrules` first, gated model surgery second

- **Status:** Proposed
- **Date:** 2026-04-25
- **Deciders:** Project owner
- **Depends on:** ADR-0001

## Context

Little Snitch's `littlesnitch` CLI does not expose per-rule mutation. The two viable mechanisms for CRUD are:

1. **`.lsrules` files** — JSON rule-group documents with a documented schema. Designed to be authored, version-controlled, and either imported through the GUI once or subscribed via HTTPS. The MCP can author and edit these freely without touching the live LS daemon.
2. **`export-model` → edit JSON → `restore-model`** — a full-model round-trip. Powerful (mutates anything, including individual rules in existing groups), but high blast radius: a bad restore corrupts user or system rules, requires `sudo`, and `restore-model` can even disable command-line access if the backup had it disabled.

A naive design might pick one. A good design exposes both, scoped sharply, with a strong default toward the safer mechanism.

We want the MCP to feel like an opinionated assistant that defaults to "GitOps for rules" but can perform surgery when the user explicitly asks.

## Decision

Adopt a **three-track CRUD model**:

- **Track A — `.lsrules` authoring** is the default for *new* rule content. All "create a rule," "block these domains," "make a deny rule for evil.example" requests land here. The MCP writes/edits files inside a managed directory; the user reviews and imports/subscribes through normal LS mechanisms.
- **Track B-direct — dedicated CLI commands** for whole-object lifecycle operations exposed by LS6.3.3 directly: `rulegroup -e/-d` (enable/disable a rule group or blocklist), `profile -a/-d` (activate/deactivate profiles), `update-rule-groups` (refresh factory groups). These bypass `restore-model` entirely. Confirmation-gated but no model patching needed.
- **Track B-surgery — `export-model` + JSON edit + `restore-model -t`** is reserved for operations with no dedicated CLI: per-rule add/edit/delete inside an existing group, profile create/delete, full-backup restore. Always uses the `-t / --preserve-terminal-access` flag (LS6.3.3+) so a malformed restore cannot lock CLI access.

Read-side operations (Track C, observability) are unaffected by this split — see ADR-0003.

The original two-track design predated discovery of the `profile`, `rulegroup`, and `restrictions` commands and the `restore-model -t` flag (see [docs/feasibility-report.md](../feasibility-report.md)). Splitting Track B reflects the actual surface and meaningfully reduces the blast radius of common operations.

## Tracks in detail

### Track A — declarative `.lsrules`

- **Managed directory** (configurable, default `~/Library/Application Support/little-snitch-mcp/rules/`). The MCP owns this directory; the user is encouraged to make it a git repo.
- **Operations:** create file, add/update/remove rule by stable selector (process + remote + direction + ports tuple), set group metadata, validate against the LS5 `.lsrules` schema.
- **Output of every write:** structured diff that the LLM can present.
- **Subscription handoff:** the MCP does not auto-subscribe (LS subscriptions require HTTPS + GUI step). It surfaces a clear next-step message: "Open Little Snitch → Rules → Subscribe → file://… (manual import)" or "Host this file at https://… and subscribe."

### Track B-direct — dedicated CLI mutations (gated, no model surgery)

Confirmation-gated but trivial under the hood: each is one CLI call, no JSON patch, low blast radius.

- **Operations available:**
  - `enable_rule_group` — `littlesnitch rulegroup -e "<name>"`.
  - `disable_rule_group` — `littlesnitch rulegroup -d "<name>"`.
  - `activate_profile` — `littlesnitch profile -a "<name>"`.
  - `deactivate_all_profiles` — `littlesnitch profile -d`.
  - `update_factory_rule_groups` — `littlesnitch update-rule-groups [-a] [-t]`.
- **Always-on safeguards:**
  1. Confirmation token per call (same protocol as Track B-surgery).
  2. Refuse to disable factory rule groups unless a stronger acknowledgement is supplied.

### Track B-surgery — full-model round-trip (gated, last resort)

Used only when no dedicated CLI exists for the operation: per-rule edits, blocklist-overlay updates, profile create/delete, restore-from-backup.

- **Always-on safeguards** (enforced by the tool layer, see ADR-0004):
  1. Auto-`export-model` to a timestamped backup *before* every `restore-model`. Report the backup path.
  2. Always pass `restore-model -t / --preserve-terminal-access` so a bad payload cannot lock the CLI out. This single flag retires most of the original lockout hard-guard logic.
  3. Require an explicit confirmation token per call. No "remember this approval" flag.
  4. Default scope is the invoking user (`-u $USER`). System-wide writes require an additional, distinct confirmation.
  5. `bundleVersion` and `factoryRuleSetVersion` recorded at export time. `restore-model` refuses on mismatch unless explicit override flag is supplied.
  6. **Round-trip preservation:** when patching a single rule field, the MCP preserves all other fields (`factoryID`, `protected`, `creationDate`, `lastUsed`, etc.) verbatim. Stripping unknown fields would corrupt LS's factory-update path.
- **Operations available:**
  - **Top-level `rules` array** (rules live at top level, optionally `group`-linked):
    - `add_rule_to_live_model` — append to `model.rules`; if a `group` is specified, set the link.
    - `update_rule_in_live_model` / `remove_rule_from_live_model` — patch by rule selector. Refuses `protected: true` rules without strong ack.
  - **Deletion-overlay arrays** (the safe surface — additive only, can't corrupt):
    - `disable_blocklist_entry` — append to `disabledDomainsInLists` / `disabledHostNamesInLists` / `disabledIPAddressRangesInLists` based on entry type.
    - `enable_blocklist_entry` — remove from the matching array.
  - **Whole-file ingestion:**
    - `apply_lsrules_file_to_live_model` — read a Track A `.lsrules` file, fold its rules into `model.rules` and (if needed) create a `groups` entry.
  - **Escape hatch:**
    - `restore_model_from_file` — for advanced users who edited an exported JSON manually. Strongest confirmation.
- **Operations explicitly *not* offered in v1:**
  - Bulk delete of rules across groups.
  - Direct mutation of factory rule groups (those with `factoryID` or `kind: builtin*`). The only sanctioned path to refresh them is the Track B-direct `update_factory_rule_groups` tool.
  - Profile create/delete (defer until we have a real profile to model from).
  - Anything that flips a hard-deny preference (see ADR-0004 §4).

### Track C — read

Pure reads (`list-preferences`, `read-preference`, `export-model` for inspection, `log`, `log-traffic`, `capture-traffic`) flow through the MCP without confirmation, but inherit the sudo and "Allow access via Terminal" requirements documented per command. See ADR-0003 for the catalog and ADR-0004 for handling those preconditions.

## Options considered

- **Single-track: `.lsrules` only.** Rejected because users will reasonably want to disable a rule group or apply a freshly authored file without manual GUI dragging. Forcing GUI for every change makes the MCP feel like a glorified text editor.
- **Single-track: model surgery only.** Rejected because every change becomes a high-blast-radius operation. Newcomers would be one bad call from corruption.
- **Hybrid where Track A and B share tools (auto-promote files into the model).** Rejected because it hides the live-model write behind a "create rule" verb. We want the live-model write to be a deliberate, named action.

## Consequences

**Positive:**
- The default surface is safe: bad LLM output ends up as a JSON file the user can `git diff` and discard. No corruption path.
- The advanced surface is honest about its risk: every Track B tool's name and prompt makes clear it touches the live model.
- Backups before every surgery give the user a real undo without relying on Time Machine.

**Negative / accepted tradeoffs:**
- Two tracks mean two sets of similarly-named tools (`add_rule_to_file` vs `apply_lsrules_file_to_live_model`), which is more surface area for the LLM to reason about. Mitigation: clear tool descriptions and a few canonical prompts (ADR-0003).
- Subscriptions still require manual GUI work. The MCP cannot fully close the loop without either an HTTPS hosting helper or a documented manual step. We accept the manual step for v1.
- Backups will accumulate in the managed dir. Add a `prune_backups` admin tool later; out of scope for v1.

## References

- LS6 CLI overview: https://help.obdev.at/littlesnitch6/cmd-overview
- LS5 CLI reference (per-command flag detail still applies to LS6 for shared commands): https://help.obdev.at/littlesnitch5/adv-commandline
- `.lsrules` format (LS6 dev docs): https://developer.obdev.at/littlesnitch6/adv-lsrules-file-format
- Rule group concepts (LS6): https://help.obdev.at/littlesnitch6/concepts-rulegroups
- Reference implementation that does Track-B-style surgery: https://github.com/mlevin2/little-snitch-rule-manager
