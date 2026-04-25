# ADR-0003 — MCP tool surface (resources, tools, prompts)

- **Status:** Proposed
- **Date:** 2026-04-25
- **Deciders:** Project owner
- **Depends on:** ADR-0001, ADR-0002

## Context

ADR-0002 splits operations into three tracks: declarative `.lsrules` authoring (A), gated live-model surgery (B), and observability reads (C). This ADR turns those tracks into a concrete catalog of MCP **resources**, **tools**, and **prompts** so that implementation can begin against a fixed surface.

The primary design constraint is LLM legibility. Tools must be named so that an LLM picking from a tool list cannot confuse "draft a rule into a file" with "write a rule to the live firewall." Verbs and scopes are explicit.

## Decision

The MCP exposes the following surface. Names are normative.

### Resources (read-only, addressable, cacheable)

Each resource has a stable URI and a JSON body. Resources are read-cheap; tools mutate.

| URI | Body | Notes |
|---|---|---|
| `littlesnitch://doctor` | preflight report (LS version ≥ 6.3.3, CLI access, sudo availability, managed dir) | Always safe to read; uses no sudo. |
| `littlesnitch://preferences` | full key/value map (`list-preferences` output, normalized to JSON) | Sudo required. Cached briefly. |
| `littlesnitch://model` | full data model (output of `export-model`) | Sudo. Large. Cached with explicit TTL. |
| `littlesnitch://model/rule-groups` | array of rule group summaries derived from the model | Convenience projection. |
| `littlesnitch://model/rule-groups/{id}` | single rule group with full rule list | |
| `littlesnitch://lsrules-files` | listing of files in the managed directory | No sudo. |
| `littlesnitch://lsrules-files/{name}` | the parsed contents of one `.lsrules` file | |
| `littlesnitch://schema/lsrules` | the `.lsrules` JSON schema we validate against (LS6) | Static; useful for the LLM to consult before authoring. |

### Tools

Tools are grouped by track. Naming convention: `<verb>_<noun>[_in_<scope>]`. The scope suffix is mandatory for any tool that touches the live model.

#### Track C — observability (no confirmation; sudo as required by underlying CLI)

| Tool | Wraps | Notes |
|---|---|---|
| `doctor` | preflight checks | Returns structured `{ok, issues[]}`; no sudo. |
| `list_preferences` | `littlesnitch list-preferences` | Optional `scope: "global" \| "user" \| "all"`. |
| `read_preference` | `littlesnitch read-preference <key>` | Single key or array of keys. |
| `tail_log` | `littlesnitch log -l <duration> -j [-p <predicate>]` | Bounded duration. JSON output. **No sudo, no Allow-access requirement** (empirically verified). |
| `tail_traffic` | `littlesnitch log-traffic [-b/-e/-s]` | CSV → JSON conversion. Filterable by process/remote/direction post-fetch. Sudo. |
| `capture_process_traffic` | `littlesnitch capture-traffic [-v <via>] [-p] <process>` | LS6.3.3 flags: `-v` is the via/parent helper (was `-p` in LS5); `-p` is now pcap output (was `-c` in LS5). Bounded duration enforced by the tool layer. |
| `get_rules_for_process` | derived from `littlesnitch://model` | Finds every rule whose `process` matches. |
| `find_rules_for_remote` | derived from `littlesnitch://model` | Given an IP, host, or domain, returns every matching rule across all groups. |
| `explain_rule_match` | derived from `littlesnitch://model` | Given (process, remote, direction, port), returns the highest-priority matching rule and group. |
| `show_restrictions` | `littlesnitch restrictions` | Sudo + Allow access required. Read-only — the CLI does not expose a way to *set* restrictions. |

#### Track A — `.lsrules` authoring (no confirmation; only touches managed dir)

| Tool | Effect | Notes |
|---|---|---|
| `list_lsrules_files` | enumerate files in managed dir | |
| `read_lsrules_file` | parsed JSON of one file | |
| `validate_lsrules` | validate JSON against the schema | Accepts inline JSON or path; returns structured field errors. |
| `create_lsrules_file` | new file with name/description and either compact `denied-remote-*` keys or a `rules` array | Refuses overwrite unless `replace: true`. |
| `add_rule_to_lsrules_file` | append a rule object to a file | Idempotent: detects duplicate by (process, remote, direction, port, action) tuple. |
| `update_rule_in_lsrules_file` | edit a rule selected by index or selector | Returns a unified diff in the response. |
| `remove_rule_from_lsrules_file` | remove a rule selected by index or selector | |
| `set_lsrules_metadata` | update `name` / `description` of a group file | |
| `diff_lsrules_files` | diff two files in managed dir | For pre/post review. |

#### Track B-direct — dedicated CLI mutations (per-call confirmation; sudo; no model surgery)

These wrap commands LS6.3.3 exposes directly. Each is one CLI call. Confirmation tokens still apply, but the diff is a single named-object state change — fast and low-risk.

| Tool | Effect |
|---|---|
| `enable_rule_group` | `sudo littlesnitch rulegroup -e "<name>"`. **Open question:** what string the CLI accepts for builtin groups whose `name` is null in the model — likely the kind-derived display name or the group ID. To be resolved by an authorized no-op probe. |
| `disable_rule_group` | `sudo littlesnitch rulegroup -d "<name>"`. Refuses factory/builtin groups (`kind: builtin*`) unless `live_write_strong` ack supplied. |
| `activate_profile` | `sudo littlesnitch profile -a "<name>"`. |
| `deactivate_all_profiles` | `sudo littlesnitch profile -d`. |
| `update_factory_rule_groups` | `sudo littlesnitch update-rule-groups [-a apple-only] [-t third-party-only]`. Classified `live_write`; low blast radius but still gated. |
| `write_preference` | `sudo littlesnitch write-preference`; restricted to an allowlist of safe keys (see ADR-0004). |

#### Track B-surgery — live-model JSON round-trip (per-call confirmation; auto-backup; sudo; always uses `restore-model -t`)

Every Track B-surgery tool takes a `confirmation_token` parameter that the LLM must obtain by calling `prepare_live_model_change` first. The token encodes the exact intended diff; the live tool refuses any token whose diff doesn't match the change about to be made. Details in ADR-0004. **All `restore-model` invocations hard-code `-t / --preserve-terminal-access` so a malformed payload cannot lock the CLI out.**

| Tool | Effect |
|---|---|
| `prepare_live_model_change` | dry-run: produce the proposed model diff and a one-shot confirmation token. Surfaces the diff for the user to approve. |
| `export_model_backup` | `sudo littlesnitch export-model <path>`; returns the path for traceability. Also runs implicitly before every other Track B-surgery tool. |
| `apply_lsrules_file_to_live_model` | fold a Track A `.lsrules` file into the model as a new local rule group, then `sudo littlesnitch restore-model -t`. |
| `add_rule_to_live_model` | append a rule to top-level `model.rules`; optionally set its `group` link. Round-trips all other fields untouched. |
| `update_rule_in_live_model` | edit one rule by selector. Refuses `protected: true` or `factoryID`-bearing rules without `live_write_strong` ack. |
| `remove_rule_from_live_model` | remove one rule by selector. Same protection guards. |
| `disable_blocklist_entry` | append a single entry to `disabledDomainsInLists` / `disabledHostNamesInLists` / `disabledIPAddressRangesInLists` (auto-routed by entry type). Additive overlay — lowest blast radius of any Track B-surgery op. |
| `enable_blocklist_entry` | remove a matching entry from the same arrays. |
| `list_blocklist_overlays` | (read) returns the current contents of all three `disabled*InLists` arrays. |
| `restore_model_from_file` | escape hatch for user-edited model JSON. Strongest confirmation. |

#### Explicitly *not* offered in v1 (and why)

- `delete_rule_group` — high blast radius; rare in practice; defer until we see real demand.
- `subscribe_to_rule_group_url` — LS subscriptions are GUI-driven; we author files, we do not pretend to subscribe.
- `create_profile` / `delete_profile` — `profile` CLI only activates/deactivates; create/delete would need Track B-surgery and we defer.
- `set_restrictions` — `restrictions` CLI is read-only.
- `approve_alert` / `deny_alert` — no CLI surface; would require GUI scripting (rejected in stories).

### Prompts (reusable LLM workflows)

Prompts bundle a recipe of tool calls so the user can invoke a workflow by name from an MCP client.

| Prompt | What it does |
|---|---|
| `triage_unknown_connections` | Args: process or window. Pulls `tail_traffic`, summarizes destinations, classifies by domain reputation hint, and proposes a deny rule (Track A draft, not applied). |
| `block_telemetry_for_app` | Args: app name. Looks up known telemetry hosts (from a curated list shipped with the MCP) and produces an `.lsrules` file via `create_lsrules_file`. |
| `audit_rules_for_process` | Args: executable path. Calls `get_rules_for_process` and renders a human-readable report. |
| `prepare_incident_block` | Args: remote host or IP. Produces a high-priority deny rule, drafts it as Track A *and* prepares a Track B confirmation token. |
| `weekly_review` | Pulls `tail_traffic` for last 7 days, surfaces new top destinations, suggests rule changes. |

## Story-to-tool traceability matrix

| Story | Tools | Resource(s) |
|---|---|---|
| A1 inspect app traffic | `tail_traffic` | `littlesnitch://model` for context |
| A2 explain a rule | `explain_rule_match` | `littlesnitch://model` |
| A3 audit rules for process | `get_rules_for_process` | `littlesnitch://model` |
| A4 tail logs/traffic | `tail_log`, `tail_traffic` | — |
| B1 generate blocklist | `validate_lsrules`, `create_lsrules_file` | `littlesnitch://schema/lsrules` |
| B2 edit a rule in file | `add_rule_to_lsrules_file`, `update_rule_in_lsrules_file`, `remove_rule_from_lsrules_file` | `littlesnitch://lsrules-files/{name}` |
| B3 validate file | `validate_lsrules` | `littlesnitch://schema/lsrules` |
| C1 apply file to live | `prepare_live_model_change`, `apply_lsrules_file_to_live_model` | `littlesnitch://model` |
| C2 enable/disable group | `enable_rule_group` / `disable_rule_group` (Track B-direct) | `littlesnitch://model/rule-groups` |
| C3 hard-deny endpoint | `prepare_incident_block` prompt → both Track A draft and Track B-surgery apply | — |
| D1 read/write prefs | `list_preferences`, `read_preference`, `write_preference` (allowlisted) | `littlesnitch://preferences` |
| D2 capture traffic | `capture_process_traffic` | — |
| (admin) refresh factory groups | `update_factory_rule_groups` | — |
| (new) profile switching | `activate_profile`, `deactivate_all_profiles` | derived from model |
| (new) restrictions read | `show_restrictions` | — |
| (new) blocklist overlay CRUD | `list_blocklist_overlays`, `disable_blocklist_entry`, `enable_blocklist_entry` | derived from model |

Every story has at least one tool. Every Track B tool requires confirmation per ADR-0004.

## Consequences

**Positive:**
- Surface is small enough for an LLM to navigate without long tool-selection prompts.
- Naming makes the safety boundary visible at the call site.
- Resources let the LLM read structure once and reason locally without re-fetching.

**Negative / accepted tradeoffs:**
- The two-step confirmation (`prepare_live_model_change` → tool call with token) is more friction than a single tool call. We accept this for the safety it buys.
- We do not expose every CLI option — e.g., `tail_log -p` predicate is fully passed through, but `debug-categories` is intentionally absent (support-only). If a user needs that, they call the CLI directly.

## References

- ADR-0002 (CRUD strategy) defines tracks A / B / C.
- ADR-0004 (safety) defines the confirmation-token protocol and allowlist details.
- LS6 CLI overview: https://help.obdev.at/littlesnitch6/cmd-overview
- LS6 `update-rule-groups`: https://help.obdev.at/littlesnitch6/cmd-update-rule-groups
- LS5 per-command flag detail (still applies to shared LS6 commands): https://help.obdev.at/littlesnitch5/adv-commandline
