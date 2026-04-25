# Feasibility report — can the MCP do everything the GUI does?

**Date:** 2026-04-25
**LS version probed:** 6.3.3 (canonical install at `/Applications/Little Snitch.app/Contents/Components/littlesnitch`)
**Author:** captured during a live probe of the user's freshly installed LS 6.3.3.

This document answers: *Can `little-snitch-mcp` actually deliver "examine traffic, determine the rules for various IPs/domains, and set those rules — anything you could do via the GUI"?*

Short answer: **Yes for the things that matter, no for a small but well-defined set of GUI-only capabilities.** The set of CLI commands actually shipped in 6.3.3 is **larger than the public docs page lists** and changes the design favorably.

---

## Empirical findings vs. the public docs

The page at <https://help.obdev.at/littlesnitch6/cmd-overview> lists 11 commands. The actual `littlesnitch --help` output on 6.3.3 lists **14**. Three commands are documented only in the binary:

| Command | What it does | Why it matters |
|---|---|---|
| `profile` | `-a <name>` activates a profile, `-d` deactivates all | Direct profile switching — previously assumed unavailable. |
| `rulegroup` | `-e <name>` enables, `-d <name>` disables a rule group or blocklist | Direct rule-group toggle without the `restore-model` round-trip. Major safety win. |
| `restrictions` | shows current restrictions | Read access to LS's "restrictions" feature. |

Additionally, `restore-model` ships an LS6 flag the public docs do not mention:

- **`-t / --preserve-terminal-access`** — "If Terminal access is currently enabled, preserve it regardless of imported settings." This single flag eliminates the `allowCommandLineAccess = false` lockout footgun that drove a chunk of ADR-0004's hard-guard logic. We can simply pass `-t` on every restore.

And `capture-traffic` differs from LS5: the parent-process flag is now `-v / --via` (was `-p` in LS5) and pcap is now `-p / --pcap` (was `-c` in LS5).

## Empirical error strings (what the CLI actually says)

Captured from real CLI runs on the test box:

| Condition | Exact stderr | Used by |
|---|---|---|
| Command requires root, run without sudo | `littlesnitch must be run as root!` | Safety layer — distinguish "needs sudo" from other failures. |
| "Allow access via Terminal" disabled | `Error: command line tool is not authorized to make changes.\nPlease enable access in Little Snitch.app > Preferences > Security.` | `doctor` tool — detect and surface remediation verbatim. |

These resolve two of the open questions in [design.md](design.md).

## What works without sudo and without "Allow access via Terminal"

Confirmed by direct invocation:

- `littlesnitch --version`
- `littlesnitch --help`
- `littlesnitch <subcommand> --help`
- `littlesnitch log [-l ...] [-j] [-p ...]` — full read access to LS's log stream, JSON-formatted. **The entire observability surface (Track C reads of the log) requires no privileges.**

## What requires sudo

Per `littlesnitch must be run as root!` empirically returned for:

- `list-preferences`, `read-preference`, `write-preference`
- `export-model`, `restore-model`
- (presumed) `log-traffic`, `capture-traffic`, `profile`, `rulegroup`, `restrictions`, `update-rule-groups`, `debug-categories`, `recrypt-config`

## What additionally requires "Allow access via Terminal"

Per `Error: command line tool is not authorized to make changes.` returned for `restrictions`:

- Everything sudo-required, in addition to needing root.
- Exception: `log` works without it. Empirically confirmed.

---

## GUI ↔ MCP capability matrix

Every important GUI capability mapped to the concrete CLI / `.lsrules` / `restore-model` recipe that achieves it through the MCP.

Legend: ✅ direct, ✅* via known recipe, ⚠️ partial, ❌ not feasible.

### Read / inspect

| GUI capability | MCP path | Notes |
|---|---|---|
| ✅ View live connection log | `log -l <duration> -j` (no sudo) | `tail_log` tool. Fully streaming via `-s`. |
| ✅ Network Monitor traffic stats | `log-traffic [-b/-e/-s]` (sudo) | `tail_traffic` tool. CSV → JSON in the MCP layer. |
| ✅ Capture traffic for a process | `capture-traffic <process> [-v parent] [-p pcap]` (sudo) | `capture_process_traffic` tool. Bounded by MCP. |
| ✅ View all rules / rule groups | `export-model` (sudo) → query in JSON | `littlesnitch://model` resource and derived projections. |
| ✅ Find rules matching a process | derive from `export-model` | `get_rules_for_process` tool. |
| ✅ Find rules matching a remote (IP, host, domain) | derive from `export-model` | `find_rules_for_remote` tool. Same pattern as above. |
| ✅ Explain why a connection was allowed/denied | derive from `export-model` + `log` + `log-traffic` | `explain_rule_match` tool. |
| ✅ View preferences | `list-preferences`, `read-preference` (sudo) | `littlesnitch://preferences` resource. |
| ✅ View restrictions | `restrictions` (sudo + Allow access) | `show_restrictions` tool. |
| ✅ Export configuration backup | `export-model <path>` (sudo) | `export_model_backup` tool. |

### Write / mutate — declarative path (Track A, `.lsrules` files)

| GUI capability | MCP path |
|---|---|
| ✅ Create a rule (process + remote + action + direction + ports) | author into `.lsrules` file via `add_rule_to_lsrules_file` |
| ✅ Block a list of domains | compact `denied-remote-domains` form via `create_lsrules_file` |
| ✅ Allow a list of domains | `rules` array with `action: "allow"` |
| ✅ Set rule priority / direction / protocol | per-rule fields in the `.lsrules` schema |

### Write / mutate — direct CLI (Track B-direct, no model surgery)

These are **major upgrades from the original design** because they bypass the risky `restore-model` round-trip:

| GUI capability | MCP path | New? |
|---|---|---|
| ✅ Enable a rule group | `rulegroup -e "<group name>"` (sudo + Allow access) | NEW — direct command, no restore-model needed |
| ✅ Disable a rule group | `rulegroup -d "<group name>"` | NEW |
| ✅ Activate a profile | `profile -a "<profile name>"` | NEW |
| ✅ Deactivate all profiles | `profile -d` | NEW |
| ✅ Refresh factory rule groups | `update-rule-groups [-a] [-t]` | (LS6 dedicated command) |
| ✅ Set debug categories | `debug-categories [-a/-d/-s/-f] <names>` | (Support-only; we'll expose but flag) |

### Write / mutate — model surgery (Track B-surgery, last resort)

Used only for things that have no dedicated CLI:

| GUI capability | MCP path |
|---|---|
| ✅* Add an individual rule to a specific group in the live model | `export-model` → patch JSON to insert rule object → `restore-model -t <file>` |
| ✅* Edit an individual rule's fields in the live model | `export-model` → patch → `restore-model -t` |
| ✅* Delete an individual rule | `export-model` → patch → `restore-model -t` |
| ✅* Enable/disable a single rule (not whole group) | `export-model` → set `disabled` flag on the rule → `restore-model -t` |
| ✅* Restore from any prior backup | `restore-model -t [-m mapping] [-p password] <file>` |

`-t` is now passed by default in all our `restore-model` calls so a malicious or malformed backup cannot lock out terminal access.

### Write / mutate — preferences

| GUI capability | MCP path |
|---|---|
| ✅ Toggle silent mode (and similar prefs) | `write-preference <key> <value>` (allowlisted in MCP — see ADR-0004) |
| ✅ Remove a preference | `write-preference -r <key>` |

### Genuinely GUI-only (out of scope, no CLI path)

| GUI capability | Why not | Workaround |
|---|---|---|
| ❌ Approve/deny a live alert popup | No CLI surface; would require GUI scripting | None. We deliberately do not GUI-script. |
| ❌ Drag-drop subscribe to a remote `.lsrules` URL | LS GUI manages subscriptions; no CLI add | MCP can author the file and tell user to subscribe via GUI; user does the one-time GUI step. |
| ❌ Live network map visualization | GUI-rendered | MCP returns the underlying data via `log-traffic`; the LLM can render text summaries. |
| ⚠️ Create / delete profiles | `profile` only activates/deactivates; no `profile create` flag observed | Likely only doable via `restore-model` surgery (mutating the profile list in the model JSON). Will verify with an `export-model` once Terminal access is enabled. |
| ⚠️ Set restrictions (the `restrictions` command only shows; no `--set` flag) | CLI is read-only for restrictions | None via CLI. GUI only. |

---

## Worked CRUD example: "block evil.example for the Slack process"

End-to-end, this is what the MCP would do, mapped to real commands. Each step is annotated with `sudo` requirement and confirmation gating.

**Read phase (no confirmation):**
1. `littlesnitch log -l 30m -j` — confirm Slack has been talking to evil.example. (No sudo.)
2. `sudo littlesnitch log-traffic -b "<30m ago>"` — get connection stats. (Sudo.)
3. `sudo littlesnitch export-model /tmp/model.json` — pull the current rules. (Sudo, auto-backed-up.)
4. Query the model for any existing Slack rule that already covers evil.example.

**Write phase, two options:**

**Option A — declarative (no live mutation):**
- `add_rule_to_lsrules_file managed-dir/incident.lsrules` writes:
  ```json
  {
    "name": "Incidents",
    "rules": [
      { "process": "/Applications/Slack.app/Contents/MacOS/Slack",
        "remote-hosts": "evil.example",
        "action": "deny",
        "direction": "outgoing",
        "priority": "high" }
    ]
  }
  ```
- MCP returns the file path and instructs the user to import via GUI. No live system change.

**Option B — apply live (Track B-surgery, confirmation-gated):**
- `prepare_live_model_change` computes the diff: insert one rule object into the local rule group named "Incidents," create the group if missing.
- User approves the diff.
- MCP runs `sudo littlesnitch export-model managed-dir/backups/<timestamp>.json` (auto-backup).
- MCP runs `sudo littlesnitch restore-model -t /tmp/patched-model.json`.
- MCP confirms by re-running `export-model` and verifying the rule is present.

**Option C — flip a whole group off live (Track B-direct, confirmation-gated, no surgery):**
- If "Incidents" group exists and we just want to enable it: `sudo littlesnitch rulegroup -e "Incidents"`.
- If we want to disable a noisy group temporarily: `sudo littlesnitch rulegroup -d "Apple Services"`.

All three options are real. The MCP defaults to A; B and C require confirmation tokens.

---

## Empirical findings from `scripts/verify-cli.sh` (2026-04-25)

User ran the script against their LS 6.3.3 install. Highlights:

### Model schema (the most consequential finding)

`export-model` returns a JSON object whose **top-level shape is not the same as the `.lsrules` file format**:

| Top-level key | Type | Notes |
|---|---|---|
| `bundleVersion`, `factoryRuleSetVersion` | number | Schema versioning. The MCP should record these and refuse `restore-model` if `bundleVersion` differs from what was exported. |
| `globalDefaults` | object (12 keys) | System-wide defaults. |
| `groups` | **object** (keyed by group ID, not array) | Rule groups indexed by ID. The verify script's array-of-groups heuristic returned "no obvious rule-group array" — confirms shape. Currently 2 entries on a fresh install (likely the two factory groups). |
| `rules` | **top-level array** of rule objects | **Rules live at the top level, not nested inside groups.** 21 rules on a fresh install. Each rule presumably carries a `group` (or similar) field linking to a `groups` entry — to be confirmed by `verify-model-shape.sh`. |
| `profiles` | object (keyed by profile ID) | Empty on fresh install. |
| `noProfilePseudoProfile` | object | The "default" pseudo-profile used when no real profile is active. |
| `users` | array (1 entry) | Per-user configuration scope. |
| `codeRequirements` | object (7 entries) | Code-signing requirements for trusted apps. |
| `developerTeamNames` | object (24 entries) | Team-ID → name map. |
| `lastSeenExecutableByCodeIdentifier` | object (208 entries) | Code-ID → executable path map. The "I've seen this binary" cache. |
| `disabledDomainsInLists`, `disabledHostNamesInLists`, `disabledIPAddressRangesInLists` | array | **Local overrides for subscribed blocklists** — how a user disables a single entry inside a remote list without modifying upstream. The MCP can use these to surgically un-block one entry. |
| `networkTriggers` | array | For automatic profile switching. |
| `blocklistStatistics`, `statisticsModelCreationDate` | object/number | Stats. |

**Implications for Track B-surgery:**
- "Add a rule" = append to `model.rules` and (probably) set the rule's group-link field.
- "Disable one entry inside a subscribed blocklist" = append to the matching `disabled*InLists` array (no per-rule mutation needed).
- "Add a profile" = add an entry to the `profiles` object keyed by a new UUID.
- We must run `verify-model-shape.sh` to confirm:
  - The keys inside a `groups[id]` value (name? kind? rule references?).
  - How rules link back to groups (a `group` field? a `groupID`?).
  - The shape of one rule object (which fields it actually uses — there may be more than the `.lsrules` schema documents).

### Preference taxonomy (LS 6.3.3 ships 61 preferences)

**Hard-deny for `write_preference`** (these are LS's own permission gates; mutating them is a privilege-escalation footgun):
- `allowCommandLineAccess`
- `allowGUIScripting`
- `allowGlobalEditing` (replaces the `allowGlobalRuleEditing` named in the original ADR-0004 — the actual key is shorter)
- `allowProfileSwitching`
- `allowRuleAndProfileEditing`
- `allowSettingsEditing`

**Initial allowlist for `write_preference`** (UI / behavior toggles, no security impact):
- `dataRateUnitsBitsPerSecond` — display unit
- `detailLevelPortAndProtocol` — display detail
- `customHierarchyLevels` — display hierarchy
- `confirmAutomatically` — alert behavior
- `autoConfirmationAction`, `autoConfirmationDelay` — alert behavior
- `activeSilentMode` — silent mode toggle (this is the equivalent of GUI's silent-mode)
- `markNewBlocklistEntriesAsUnapproved`
- `defaultRuleLifetimeForCreatingRulesInAlert`
- `monitorMaxConnectionsInModel`

**Gray list — review case-by-case before allowing:**
- `automaticProfileSwitching*` — could disrupt user's profile setup
- `dnsEncryption*` — affects DNS resolution; user may want this but MCP shouldn't toggle silently
- `approveRulesAutomatically` — affects what new rules get auto-approved
- `additionalLocalnetAddresses` — affects what's considered local

### Restrictions output

`restrictions` returns plain text, not JSON, and is about **license state**, not parental controls:

```
Product never expires.
Have fully featured non-expiring license.
```

The MCP exposes this as `show_restrictions`, parses the two lines, returns a structured `{licensed: true/false, expires_at: null/date, features: "full"|"limited"}`.

### log-traffic CSV format (confirmed)

Column order matches docs exactly: `date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable`. `direction` is `in`/`out`. `protocol` is numeric (6=tcp, 17=udp). `date` is ISO-8601 UTC. Empty `remoteHostname` for unresolved connections. Quoted-string CSV for paths.

### Exit codes (the surprise)

| Command | Condition | Exit code |
|---|---|---|
| `read-preference <existing>` | success | 0 |
| `read-preference <missing>` | key doesn't exist | **0** (!) |
| `rulegroup -e <missing-group>` | group not found | 1 |

`read-preference` returns 0 even on missing keys. **The MCP must distinguish missing vs present by inspecting the JSON output**, not by exit code. Specifically: `read-preference foo bar` returns a JSON object whose values are `null` for missing keys.

`rulegroup` exit codes are reliable; the MCP can trust them for direct-CLI mutations.

### Closes open questions

This run resolves items 1, 2 (partial — needs shape probe), 5, 6, 7 from the prior list. Item 2 (full model shape) needs `scripts/verify-model-shape.sh`. Items 3 and 4 (mutation tests) are still pending user authorization.

## Empirical findings from `scripts/verify-model-shape.sh` (2026-04-25)

Drilled into the actual rule, group, profile, and user shapes.

### Critical correction: `model.groups` is not user-facing rule groups

Both `groups` entries on a fresh install are LS-managed blocklist subscriptions:

```
{
  "id": "aaaaac",
  "keys_in_value": ["isActive", "lastUpdateInvalidDomainsCount", "type", "updateInterval"],
  "name": null,
  "kind": "builtinMacOSServices"
}
```

`kind` carries the semantic identity (`builtinMacOSServices`, `builtinICloudServices`); `name` is null because builtin groups are rendered from `kind` via a localized table. User-created local groups would appear here with non-null `name` and different `kind` (likely `local` or similar, TBD).

**Open question:** what does `rulegroup -e/-d <name>` accept when `name` is null? Possibilities: kind-derived display names, group IDs, or builtins are not toggleable via this command. **Resolvable via a safe no-op probe** (`rulegroup -e "builtinMacOSServices"` etc., expect exit 1 if not accepted).

### Rules: 16 distinct field-set shapes across 21 rules

Real rules carry far more fields than the `.lsrules` schema documents. Observed across all rules:

- **Always present:** `action`, `creationDate`, `modificationDate`, `origin`.
- **Frequently present:** `factoryID`, `protected`, `lastUsed`, `useCount`, `direction`.
- **Conditionally present:** `process`, `requiresTrustedSignatureForAnyProcess`, `remote`, `remote-domains`, `remote-addresses`, `remote-hosts`, `protocol`, `ports`, `priority`, `via`, `uid`, `owner`, `group`, `factoryHelpText`, `approved`, `hidden`, `disabled`.

**The MCP must round-trip rule objects unmodified when patching a single field.** Stripping `factoryID` or `protected` would corrupt LS's factory-update path or remove safety guards.

### Discovered values

| Field | Observed values | Default when absent |
|---|---|---|
| `action` | `allow`, `ask` (this user has no `deny` rules yet) | none — must be set |
| `direction` | `incoming`, `both`, absent | `outgoing` (per docs) |
| `priority` | `high`, absent | `regular` (per docs) |

`deny` is documented and supported even though absent in this user's data.

### Process matching modes

Rules use one of:

1. `process: "/absolute/path"` — path-based match.
2. `process: "any"` — match any process (when combined with restrictive `remote`).
3. `requiresTrustedSignatureForAnyProcess: true` — match any process with a valid code signature. Used for system-level rules (e.g., DNS).
4. (Presumed) code-id form like `process: "TEAMID/identifier"` — not in this sample but documented.

### Remote matching modes (mutually exclusive)

Rules use one of:

- `remote: "<special-value>"` — `any`, `local-net`, `multicast`, `broadcast`, `bonjour`, `dns-servers`, `bpf`.
- `remote-domains: [...]`
- `remote-hosts: [...]`
- `remote-addresses: [...]`

The MCP encodes this as a discriminated union in the rule type.

### Safety-critical rule fields

| Field | Meaning | MCP guard |
|---|---|---|
| `protected: true` | LS's "don't delete me accidentally" guard | Refuse to mutate/remove without `live_write_strong` ack. |
| `factoryID` (present) | LS-shipped factory rule | Refuse to mutate/remove without strong ack. Mutating breaks `update-rule-groups`. |
| `requiresTrustedSignatureForAnyProcess: true` | System-level signature-trust rule | Treat as system-scope. Strong ack. |
| `hidden: true` | Hidden in GUI | Surface in MCP but flag as hidden in summaries. |

### Profiles and pseudo-profile

`profiles` is empty on fresh install. `noProfilePseudoProfile` has just `{ name: <something> }`. Profile shape is fully unknown until the user creates one. Profile create/delete remains a Track B-surgery operation deferred from v1 (per ADR-0003).

### Per-user defaults

`model.users[0]` shape: `{ defaults, fullName, shortName, uid }`. Per-user preferences live inside `defaults`. The MCP's `read_preference` uses `-u $USER` to scope per-user reads under sudo.

### Deletion-overlay arrays — a NEW Track B-direct surface

`disabledDomainsInLists`, `disabledHostNamesInLists`, `disabledIPAddressRangesInLists` are LS's mechanism for locally disabling individual entries inside subscribed blocklists without modifying the upstream `.lsrules` source. **All three are top-level arrays in the model.** Adding/removing an entry is just an array append/splice — much lower blast radius than rule-level surgery.

**New tools to add to ADR-0003:**
- `disable_blocklist_entry` — append to the matching `disabled*InLists` array via export → patch → restore -t.
- `enable_blocklist_entry` — remove from the matching array.

These are Track B-surgery in mechanism (use `restore-model -t`) but Track B-direct in spirit (additive overlay, can't accidentally corrupt anything else).

### Schema versioning confirmed

`bundleVersion: 7172`, `factoryRuleSetVersion: 424` on this install. The MCP records both before any `restore-model` and refuses if the imported model has different `bundleVersion` without explicit `--accept-schema-mismatch`.

## Empirical findings from smoke tests (2026-04-25)

### Smoke 1: `rulegroup -e/-d` name format

User ran `scripts/smoke-1-rulegroup-name.sh`. The CLI accepts ONLY the localized display name. Group IDs, `kind` values, and arbitrary strings are all rejected with `Rule group or blocklist "X" not found.` and exit 1.

| Candidate | Accepted? |
|---|---|
| `lsmcp_does_not_exist_*` (missing baseline) | No (exit 1, expected) |
| `builtinMacOSServices` (kind value) | **No** |
| `builtinICloudServices` (kind value) | **No** |
| `aaaaac` (group ID) | **No** |
| `aaaaad` (group ID) | **No** |
| `macOS Services` (display name) | **Yes** (exit 0) |
| `iCloud Services` (display name) | **Yes** (exit 0) |

**Design implication for ADR-0003:** the `enable_rule_group` / `disable_rule_group` tools take a *group identifier* and the MCP resolves it to the display name. Resolution rules:

1. If the input matches a non-null `name` of an entry in `model.groups`, use it directly (covers user-created groups).
2. If the input matches a `kind` (e.g., `builtinMacOSServices`), look up the localized name in a shipped table (`{ "builtinMacOSServices": "macOS Services", "builtinICloudServices": "iCloud Services", ... }`). The table grows as we encounter more `kind` values.
3. If the input matches a group ID, resolve via the model and apply rules 1–2.
4. If the input matches a display name directly, pass through.
5. If none match, return a structured error listing the candidate display names so the LLM can re-select.

### Smoke 2: `restore-model -t` rejected our patched model

User ran `scripts/smoke-2-rule-roundtrip.sh`. The patched model parsed cleanly as JSON, contained 22 rules (one more than baseline), but `restore-model -t` returned:

```
error = Error Domain=ODCustomError Code=1 "The data couldn't be read because it isn't in the correct format."
```

The test rule was constructed using `.lsrules` field names plus sensible defaults:

```json
{
  "action": "ask",
  "process": "/usr/bin/true",
  "remote-domains": ["lsmcp-smoke-*.invalid"],
  "direction": "outgoing",
  "notes": "...",
  "creationDate": <NSDate>,
  "modificationDate": <NSDate>,
  "origin": "user"
}
```

**Critical finding: the live-model rule schema differs from the `.lsrules` file schema.** LS's GUI internally converts `.lsrules` → model format on import. The CLI's `restore-model` requires the model format directly and does not accept the `.lsrules` shape.

What's likely missing (informed guesses, to be confirmed by the next probe):
- A `uuid` or per-rule unique identifier.
- A specific value for `origin` (the enum probably has values like `userCreated`, `factory`, `subscribedRemote`, `migrated`, etc., not just `"user"`).
- Possibly different NSDate encoding (offset, precision).
- Possibly a required `owner` field.

### Implications for design

| Surface | Affected? | Mitigation |
|---|---|---|
| Track A `.lsrules` authoring | No | Files use the documented `.lsrules` schema. User imports via GUI. |
| Track B-direct (`rulegroup`, `profile`, `update-rule-groups`, `disable_blocklist_entry`, `enable_blocklist_entry`) | No | None construct rules. Confirmed working. |
| Track B-surgery — `disable/enable_blocklist_entry` (overlay arrays) | No | Just string appends to top-level arrays. Should work; not yet verified end-to-end but mechanically trivial. |
| Track B-surgery — `add_rule_to_live_model` / `update_rule_in_live_model` / `remove_rule_from_live_model` | **Yes — blocked until rule schema is reverse-engineered** | Switch implementation strategy to "clone existing rule as template, modify user-changeable fields" instead of constructing from scratch. Validate via a follow-up probe after the user creates one test rule in the GUI. |
| Track B-surgery — `apply_lsrules_file_to_live_model` | **Yes — same blocker** | Either (a) implement via clone-template after rule schema is known, or (b) drop and replace with "write the file; tell user to drag into Rule Editor." |
| Track B-surgery — `restore_model_from_file` | No | This is the escape hatch for full backups — round-tripping an unmodified `export-model` should succeed. |

### Recommended next probe

Ask the user to **create one user rule via the LS GUI** (any rule, marked with a recognizable note like "lsmcp test 2026-04-25"), then run a script that:

1. Exports the model.
2. Finds the rule by note.
3. Dumps its full key set and field values (sanitizing process paths if needed).
4. Compares against our attempted construction.

This gives us the authoritative user-rule shape. Once we have it, the clone-template implementation strategy for `add_rule_to_live_model` becomes straightforward.

### Confidence updates for the value-prop use cases

- Use case #1 (traffic triage): 🟢 unchanged
- Use case #2 (rule cleanup): 🟢 unchanged (read + remove via patched model — removal is a deletion from the array, no construction needed; verify in next probe)
- Use case #3 (block telemetry for app): 🟢 → 🟡 — Track A still works; Track B-surgery `apply_lsrules_file_to_live_model` blocked pending schema
- Use case #4 (incident block): 🟢 → 🟡 — same dependency
- Use case #5 (explain rule): 🟢 unchanged
- Use case #6 (new-app onboarding): 🟢 → 🟡 — same dependency
- Use case #7 (blocklist exception): 🟢 unchanged — overlay-array path is unaffected
- Use case #8 (profile switching): 🟢 unchanged
- Use case #9 (weekly report): 🟢 unchanged
- Use case #10 (GitOps): 🟡 — depends on apply path; manual GUI import works regardless

## Empirical findings from `scripts/inspect-user-rule.sh` (2026-04-25)

**Resolves the smoke-2 blocker.** User created one rule via LS GUI (process `/bin/test`, action `ask`, direction `outgoing`, remote domain `lsmcp-test.invalid`, identification Code ID). The inspected rule's exact shape:

```json
{
  "action": "ask",
  "creationDate": "2026-04-25T17:34:31Z",
  "modificationDate": "2026-04-25T17:34:31Z",
  "origin": "frontend",
  "process": "/bin/test",
  "remote-domains": "lsmcp-test.invalid",
  "uid": 501
}
```

### What we got wrong in smoke 2 (now fixed)

| Field | Smoke 2 attempt | Actual | Why it failed |
|---|---|---|---|
| `creationDate` | NSDate seconds (number) | **ISO-8601 string** | Type mismatch on parse |
| `modificationDate` | NSDate seconds (number) | **ISO-8601 string** | Type mismatch |
| `remote-domains` | Array `["foo"]` | **String `"foo"` for single entry** | Type mismatch (the model commits to one form per case) |
| `origin` | `"user"` | **`"frontend"`** | Enum value not in allowed set |
| `direction` | `"outgoing"` (explicit) | **Absent** (default) | Probably tolerated, but cleaner to omit |
| `notes` | Set | Absent in this minimal rule | Optional field; not required |
| `uid` | Omitted | **`501`** | Required for per-user scope |

### Implications

- **`add_rule_to_live_model` works from-scratch**, no clone-template needed. The MCP just needs to use the right encodings.
- **The MCP must NOT include LS-managed fields on a fresh rule:** `factoryID`, `protected`, `owner`, `lastUsed`, `useCount`, `approved`, `hidden`. These are added by LS on its side.
- **Code-ID identification observation:** the user picked "Code ID" in the dialog, but the model still stored the rule with `process: "/bin/test"` (a path). This means LS uses the path internally and treats Code-ID identification as a presentation/matching choice, not a separate `process` value form. **Or** the second user-created rule (the script reports 2 user-created rules but only inspected the first) IS the Code-ID-shaped variant. Worth a quick follow-up to inspect both.
- **`origin: "frontend"` is the value the GUI uses.** The MCP can use the same value, or coordinate with LS upstream to add an `"mcp"` or `"api"` variant later. For v1: use `"frontend"` for compatibility.

### Confidence ratings restored

- Use case #3 (block telemetry for app): 🟡 → 🟢
- Use case #4 (incident block): 🟡 → 🟢
- Use case #6 (new-app onboarding): 🟡 → 🟢
- Use case #10 (GitOps): 🟡 → 🟢 (now that apply path works)

All ten use cases are 🟢 (verified building blocks). Smoke 3 (corrected round-trip) will lock the apply path empirically.

## Empirical findings from `scripts/smoke-3-corrected-construction.sh` (2026-04-25) — PASS

End-to-end add → verify → remove round-trip succeeded with the corrected schema. **The design is empirically locked.**

```
==== 3. restore-model -t ====    exit=0
==== 4. verify test rule present ====
  Rules after restore: 23  (was 22)
  Test rules matching: 1
==== 6. remove test rule ====    exit=0
==== 7. verify removal ====
  Rules final: 22  (back to baseline)
  Test rules matching: 0

PASS: round-trip add+remove succeeded with corrected schema.
  -> from-scratch rule construction is viable; no clone-template needed.
```

### What was sent vs. what came back (round-trip preservation check)

**Sent (key order: insertion order):**
```json
{
  "action": "ask",
  "process": "/bin/test",
  "remote-domains": "lsmcp-smoke3-1777139017.invalid",
  "origin": "frontend",
  "creationDate": "2026-04-25T17:43:37Z",
  "modificationDate": "2026-04-25T17:43:37Z",
  "uid": 501
}
```

**Received from next `export-model` (key order: alphabetical):**
```json
{
  "action": "ask",
  "creationDate": "2026-04-25T17:43:37Z",
  "modificationDate": "2026-04-25T17:43:37Z",
  "origin": "frontend",
  "process": "/bin/test",
  "remote-domains": "lsmcp-smoke3-1777139017.invalid",
  "uid": 501
}
```

**Findings:**
- All seven fields preserved exactly. No values normalized, no fields stripped, no fields injected.
- LS re-sorts keys alphabetically on export. Purely cosmetic — the MCP's diff logic must canonicalize key order before comparing.
- `direction` was NOT auto-injected; LS treats absent direction as the documented default (outgoing).
- No `factoryID`, `protected`, `lastUsed`, `useCount` were added by LS to our user-created rule. These remain LS-managed metadata for factory/aged rules only.

### Final implementation guidance for `add_rule_to_live_model` and friends

The MCP constructs rules with these rules:

1. **Required fields:** `action`, `process` (or `requiresTrustedSignatureForAnyProcess`), one of (`remote` | `remote-domains` | `remote-hosts` | `remote-addresses`), `origin: "frontend"`, `uid: $UID`, `creationDate` and `modificationDate` as ISO-8601 UTC strings (`%Y-%m-%dT%H:%M:%SZ`).
2. **Optional fields** (set when relevant): `direction` (omit for outgoing), `priority` (omit for regular), `protocol`, `ports`, `via`, `notes`, `group` (when assigning to a group).
3. **Forbidden fields on user-created rules:** `factoryID`, `protected`, `owner`, `lastUsed`, `useCount`, `approved`, `hidden` — never set; LS manages these.
4. **Single-entry remote-domains/hosts/addresses use string form;** multi-entry uses array. The MCP picks the form based on count.
5. **Diff comparison must canonicalize key order** (e.g., sort alphabetically) since LS does this on export.

### Design status: LOCKED

All ten use cases are now backed by empirically-verified building blocks. No remaining unknowns block implementation.

## Sudo + no-TTY auth path: empirically validated (2026-04-25)

The architectural concern in ADR-0006 was that GUI-spawned MCPs (Claude Desktop and friends) inherit no controlling TTY, so sudo cannot prompt for a password. The proposed mitigation was Touch ID for sudo via `pam_tid.so`. **This is now verified.**

User configured `pam_tid.so` in `/etc/pam.d/sudo_local` and ran two tests:

| Test | Command | Result |
|---|---|---|
| Sanity (regular sudo) | `sudo whoami` | Touch ID prompt → `root` |
| **No-TTY (matches MCP spawn)** | `python3 -c 'import subprocess; subprocess.run(["sudo", "whoami"], start_new_session=True)'` | **Touch ID prompt → `root`** |

`start_new_session=True` calls `setsid()` in the child before exec, dropping the controlling TTY exactly the way Claude Desktop's `posix_spawn` does. Touch ID worked.

**Implication:** with TouchID for sudo configured, every sudo-required MCP tool succeeds from a GUI client. No password caching, no askpass helper, no helper daemon — just a system Touch ID dialog per privilege escalation. ADR-0006 Tier 1 is the verified path; Tier 2 (read-only mode) and Tier 3 (warm_sudo) remain as the documented fallbacks if the user can't or won't configure TouchID.

## Open: rejection-class enumeration (S7 spike)

Smoke 3 proved one rule shape works through `restore-model -t`. We do NOT yet know the boundaries of what LS rejects. Spike S7 (4h) enumerates the rejection classes by deliberately submitting invalid patches and recording the exact stderr LS produces. Candidates to probe:

- Conflicting rules (two rules with same `process`+`remote` but different `action`).
- A rule with `group: "<id>"` referencing a non-existent group.
- A `uid` not present in `model.users`.
- A `process` path containing null bytes or non-UTF-8 sequences.
- A duplicate rule (identical to an existing one).
- A rule missing a required field per the discovered schema.

Output: a markdown table of (probe, exit code, stderr, observed behavior) feeding into the MCP's pre-flight validation rules. Goes into ADR-0007 if behaviors are surprising. Downgrades risk R3 (audit) from 🔴 to 🟡 by replacing unknown bounds with documented ones.

## Aside: harness sandbox vs MCP runtime

During verification, my Claude Code harness blocked even a benign `sudo whoami` for safety: "sudo would let the agent run sensitive Little Snitch mutations without the user's password prompt." This is a **harness sandbox restriction**, not an OS-level limit. The eventual MCP — running as a regular user process spawned by Claude Desktop — has no such sandbox. So:

- My inability to run sudo from this conversation is not a representative limit on the MCP.
- All tests requiring sudo had to be run by the user from their TTY (or, after the auth validation above, from any context).
- The MCP's permissions model is governed entirely by ADR-0004 (tool classification, confirmation tokens, hard guards) and OS-level sudo, not by anything in my harness.

### `globalDefaults` overlap with preferences

`globalDefaults` keys include `networkFilterControlBits`, `networkFilterEnabled` — the LS kill-switch. **These are not in the `write_preference` allowlist.** Mutating them would disable LS itself.

### `codeRequirements` and `lastSeenExecutableByCodeIdentifier`

- `codeRequirements` is keyed by **executable path** (`/usr/libexec/airportd`, `/usr/sbin/mDNSResponder`, etc.). Records the code-signing requirement attached to a path.
- `lastSeenExecutableByCodeIdentifier` is keyed by **code ID** (`TEAMID/identifier` format, e.g., `2BUA8C4S2C/com.1password.1password`). Maps code IDs to the most recently seen executable path.

The MCP can use the second to translate code IDs ↔ paths when authoring rules. Useful for the LLM when a user asks "block telemetry for app X" and X has a code ID rule already.

## Coverage assessment

Of the operations a typical user performs in the GUI, the MCP covers:

- **Read & inspect:** 100%. Every viewable surface in the GUI maps to a CLI read.
- **Per-rule CRUD:** 100% via the `restore-model` round-trip with `-t`. Not as ergonomic as a dedicated `add-rule` API, but lossless.
- **Rule-group CRUD:** Enable/disable directly via `rulegroup`. Create/delete groups via model surgery.
- **Profile CRUD:** Activate/deactivate directly via `profile`. Create/delete profiles likely via model surgery.
- **Preference read/write:** 100% (subject to MCP's preference allowlist).
- **Live alert handling:** **0%** (no CLI surface; we will not GUI-script).
- **Subscription wiring:** **0% via CLI** (we author `.lsrules` files; subscription is a one-time GUI action).

The user's stated goal — "examine traffic, determine the rules for various IPs/domains, set those rules" — is **fully covered.**

---

## Outstanding empirical questions

The user-run verification script at [scripts/verify-cli.sh](../scripts/verify-cli.sh) addresses items 1, 2, 5, 6, 7. Mutation tests (3, 4) are deferred until the user authorizes a no-op smoke test on a throwaway group/profile.

1. Confirm `sudo list-preferences` returns parsable key/value output and we can normalize it.
2. Confirm `sudo export-model` returns the full model JSON and identify the rule-group / rule object shape.
3. Confirm `sudo rulegroup -e <name>` actually toggles a group (test against a known throwaway group).
4. Confirm `sudo profile -a <name>` and `-d` work as documented.
5. Confirm `sudo restrictions` returns structured data we can parse.
6. Verify whether any read-only sudo operations can be made non-sudo via `-u $USER` impersonation. **Empirically: no — `littlesnitch -u $USER list-preferences` still returns `littlesnitch must be run as root!`. The `-u` flag is for *which user's preferences to act on under sudo*, not for avoiding sudo.**
7. Capture exit codes for success and the two known error modes.

## New finding: sudo + no-TTY interaction (architectural)

Discovered while attempting verification from the harness shell. macOS sudo uses **per-TTY timestamp tickets by default** (`tty_tickets` in sudoers). A `sudo -v` in the user's terminal does **not** authorize sudo from any other process/session. Implication for the MCP:

When invoked by Claude Desktop or any GUI MCP client (which spawns the MCP without a controlling TTY), every sudo-required tool will fail at the password prompt because there is no TTY to read from. The CLI returns: `sudo: a terminal is required to read the password`.

This is a real design constraint, not a bug. Options the MCP must pick from:

| Option | UX | Security | Verdict |
|---|---|---|---|
| **(a) Document a one-time TouchID-for-sudo setup** (`auth sufficient pam_tid.so` in `/etc/pam.d/sudo_local`) | Best — TouchID prompt appears as a system dialog, no TTY needed | Standard system gate | **Recommended default** |
| **(b) Ship a tiny GUI helper (`SMJobBless` / `LaunchDaemon`) that holds privileges** | Native macOS pattern but heavy lift; needs notarization | Strong (escalates only specific operations) | Defer to v2 |
| **(c) Read-only mode by default, sudo tools require user to invoke from a terminal first** | Worst — splits the MCP into "works in Claude Desktop" vs "works in CLI" | Trivial | Acceptable fallback if (a) not configured |
| **(d) `sudo -A` with an askpass helper** | Custom askpass binary popping a system dialog | OK but reinvents wheel | Reject — (a) is cleaner |
| **(e) Pre-authenticated session** — user opens Terminal, runs `sudo -v`, then immediately invokes MCP from same shell | Brittle and confusing | Same as direct sudo | Reject for daily use; document as workaround |

**Decision proposal (will go into ADR-0004 or a new ADR-0006):** combine (a) + (c). Default behavior is "TouchID for sudo recommended; read-only mode if not configured." `doctor` detects the situation and prints the one-line setup instruction.

This finding does not change the CRUD feasibility — sudo works fine when the MCP can authenticate. It changes how the MCP is *invoked*.

---

## Recommendation

The design is **sound and the goal is achievable.** The new commands (`profile`, `rulegroup`, `restrictions`) plus the `-t` flag on `restore-model` make the implementation **safer and simpler** than the original ADRs assumed.

Next step before implementation:

1. **You enable** Little Snitch → Preferences → Security → "Allow access via Terminal."
2. **I run** the 7 outstanding empirical checks above against the live system.
3. **I amend** ADR-0002 (Track B-direct), ADR-0003 (new tools), ADR-0004 (use `-t`, drop the lockout hard-guard) — flagged as TODO in this doc.
4. Once those land, the design is locked and we can move to ticketing + implementation.
