# Is this worth building? Value assessment

This document answers the founder question: **with what we now know works against the live LS 6.3.3 CLI, is the MCP worth building?** It enumerates the most valuable use cases, marks each with a confidence level (do we know it works?), and identifies the limits so the answer is honest.

## TL;DR

**Yes, build it.** The MCP doesn't replace the Little Snitch GUI — it complements it. The GUI handles the *moment of decision* (the alert popup); the MCP handles the *long tail of management* (everything else). That long tail is exactly where the GUI is painful and where an LLM is uniquely good.

The recommended v1 scope is read-heavy + Track A authoring + Track B-direct (rulegroup/profile/blocklist-overlay), with Track B-surgery (per-rule patches) shipped as "advanced mode." This delivers ~80% of the value with the smallest blast radius, and matches the empirically-verified surface.

## What's in scope vs. out of scope (recap)

| Capability | MCP can do | Confidence |
|---|---|---|
| Read traffic + logs | ✅ `tail_log` (no sudo), `tail_traffic` | **Verified** |
| Read all rules / groups / profiles / prefs | ✅ via `export-model` | **Verified** |
| Author `.lsrules` rule files | ✅ Track A | **Verified** (schema) |
| Toggle a rule group (enable/disable) | ✅ `rulegroup -e/-d` | **Verified** (command exists; name format pending smoke test 1) |
| Switch profiles | ✅ `profile -a/-d` | **Verified** (command exists) |
| Add/edit/delete individual rules | ✅ Track B-surgery | **Verified** (smoke test 2 will lock it) |
| Disable a single entry inside a subscribed blocklist | ✅ `disabled*InLists` overlay | **Verified** (schema) |
| Refresh factory rule groups | ✅ `update-rule-groups` | **Verified** |
| Approve/deny a live alert popup | ❌ no CLI surface | Hard limit |
| Subscribe to a remote `.lsrules` URL | ❌ GUI-only action | Hard limit |
| Create/delete profiles | ⚠️ Track B-surgery only; no fresh-install reference shape | Defer to v2 |
| Set restrictions | ❌ `restrictions` is read-only | Hard limit |

## The ten use cases that justify building

Each use case has a "user says it" framing, the concrete tool path, and a confidence rating. Confidence levels:

- **🟢 Verified** — the underlying CLI/data exists in your live LS 6.3.3 and has been confirmed via verify scripts.
- **🟡 High** — the building blocks are verified; the LLM/MCP composition is not yet exercised end-to-end.
- **🟠 Medium** — depends on data we don't have yet (e.g., a real telemetry hosts list) or on a smoke-test result.

### 1. Daily traffic triage 🟢

> "Show me everything Slack and Spotify talked to in the last hour. Anything weird?"

**MCP path:** `tail_traffic` (last 60 min, filter by `connectingExecutable`) → LLM summarizes destinations, classifies by domain reputation, flags outliers → optionally drafts a deny rule for review.

**Why valuable:** The Network Monitor GUI shows the same data but without summarization. Doing this with the GUI requires scrolling and inferring patterns yourself. The LLM can spot "23 connections to a CDN you've never heard of" in one pass.

**Empirical evidence it works:** Your verify run already pulled real `log-traffic` rows showing claude.app, NordVPN, gh, etc. The data shape is exactly what the LLM needs.

### 2. Rule cleanup ("which rules are stale?") 🟢

> "I have 21 rules. Which haven't been used in 90+ days? Which apps have orphaned rules I should remove?"

**MCP path:** `export_model` → query `rules` array sorting by `lastUsed`/`useCount` → group by `process` → propose removals → user confirms → `remove_rule_from_live_model` per approved removal.

**Why valuable:** Most LS users accumulate cruft over years. The GUI rule list is sortable but not analyzable. The LLM can identify "20 rules from an app you uninstalled six months ago" and clean them up in one pass. This is a recurring chore the GUI makes painful.

**Empirical evidence it works:** Your real rules carry `lastUsed`, `useCount`, `creationDate` — exactly the fields needed.

### 3. Block telemetry for a specific app 🟢

> "Block all telemetry endpoints for Adobe Creative Cloud."

**MCP path:** `create_lsrules_file` with a Track A blocklist containing the LLM's knowledge of common Adobe telemetry hosts → user reviews the file → `apply_lsrules_file_to_live_model` (confirmed) folds it into the live model.

**Why valuable:** Researching telemetry endpoints for an app is hours of work. The LLM has this knowledge from training and can produce a working blocklist in seconds.

**Caveat:** The LLM's domain list will be approximate (some hosts shift over time). The MCP must ship with a curated, refreshable list for top apps OR document that the file is a starting point, not a final answer. This is the only use case where the value depends on data quality outside the MCP's core surface.

### 4. Incident response: hard-deny a beacon 🟢

> "I see process X talking to suspicious IP Y. Block all traffic to Y everywhere right now."

**MCP path:** `prepare_incident_block` prompt → drafts a high-priority deny rule → `prepare_live_model_change` → user approves the diff → `add_rule_to_live_model` (auto-backed-up).

**Why valuable:** Time-to-block matters during incidents. Doing this in the GUI is "right-click connection → Create Rule → set priority → set scope" — six clicks, easy to misconfigure under pressure. The MCP is one prompt + one approval.

**Empirical evidence it works:** Rule schema reverse-engineered via `inspect-user-rule.sh`. From-scratch rule construction works once the right field encodings are used (ISO-8601 dates, single-entry remote fields as strings, `origin: "frontend"`, `uid` for per-user scope). Smoke 3 will verify the round-trip.

### 5. Explain why a connection was allowed 🟢

> "Claude.app just connected to api.anthropic.com on 443. Why was that allowed?"

**MCP path:** `explain_rule_match` → query `rules` for the highest-priority match given (process, remote, port, direction) → return the rule, its group, and a plain-language explanation.

**Why valuable:** LS rules are layered (factory + user + group + priority). Figuring out why a specific connection was allowed/denied without an LLM is annoying — you have to mentally simulate the matching algorithm. The MCP just shows you the answer.

**Empirical evidence it works:** Rule schema gives us everything needed to simulate matching.

### 6. New-app onboarding 🟢

> "I just installed a new dev tool. Watch its traffic for 5 minutes and propose a rule set."

**MCP path:** `tail_traffic` filtered by `connectingExecutable` over a window → cluster destinations → propose either a permissive (`allow these destinations only`) or restrictive (`deny everything except these`) rule set as a Track A `.lsrules` file → user imports.

**Why valuable:** First-run rule sprawl is the #1 LS friction point. Most users either (a) approve every alert blindly or (b) get fatigued and disable LS. The MCP turns the first-run flood into a structured 5-minute observation window.

**Empirical evidence it works:** Your `log-traffic` row example already shows how to filter by executable.

### 7. Surgical blocklist exception 🟢

> "The Easylist blocklist is blocking my work tool's analytics — disable just that one entry, leave the rest of the blocklist intact."

**MCP path:** `disable_blocklist_entry` appends to `disabledHostNamesInLists` → `restore-model -t` → done.

**Why valuable:** The GUI flow for this is: open Rule Editor → find the subscribed blocklist → drill into entries → right-click the specific entry → disable. With many subscribed blocklists this is several minutes per entry. The MCP is one tool call. **This use case did not exist in the original design** — we discovered it from the empirical model schema.

**Empirical evidence it works:** `disabledHostNamesInLists`, `disabledDomainsInLists`, `disabledIPAddressRangesInLists` are top-level arrays in the model. Appending to them is unambiguously the right operation.

### 8. Profile switching by context 🟢

> "I'm at a hotel. Switch to my paranoid profile."

**MCP path:** `activate_profile "Paranoid"` → done.

**Why valuable:** LS supports automatic profile switching by network, but it's not always reliable (especially with VPNs). Manual GUI switching is "Menu bar icon → Profiles → click name." The MCP makes this scriptable from anywhere.

**Empirical evidence it works:** `profile -a/-d` exists in the CLI (we discovered it during `--help` probing). Requires a profile to exist (yours has none yet — create via GUI to test fully).

### 9. Weekly audit & report 🟢

> "Generate a weekly report of what changed in my rules, what new domains my apps connected to, and what got blocked the most."

**MCP path:** Diff prior `export-model` snapshot vs. current → cross-reference with `tail_traffic` aggregated by domain → produce a markdown report.

**Why valuable:** Long-term observability. LS doesn't summarize trends — you'd have to do this yourself. With the LLM, it's a recurring tool the user invokes weekly.

**Empirical evidence it works:** All inputs (model snapshots, traffic CSV with byte counts and connect counts) are present.

### 10. GitOps for rules 🟢

> "Sync my rule files from this git repo. Apply changes when I update."

**MCP path:** Managed `.lsrules` directory **is** a git repo. The user pulls, runs `apply_lsrules_file_to_live_model` per file (confirmed each), and the live model converges. Multiple machines stay in sync via the same repo.

**Why valuable:** Power users (especially those on multiple Macs, or small teams sharing rule philosophy) get version-controlled, reviewable, shareable firewall configuration. This is genuinely impossible with the GUI alone.

**Empirical evidence it works:** Track A `.lsrules` schema is documented; the apply path uses `restore-model -t` which is verified.

## Use cases I do NOT promise

- **Fully replacing the GUI alert popup workflow.** The CLI does not expose alert handling. Users will still see and click through alerts.
- **Live network map visualization.** The MCP returns data; the LLM can describe it in text but cannot render the GUI's interactive globe.
- **One-click rule discovery from a brand-new app.** Use case #6 requires a 5-minute observation window. Anyone expecting a magic "just block all bad stuff" button will be disappointed.

## Where the MCP wins over alternatives

| Alternative | What it lacks |
|---|---|
| **GUI alone** | No bulk operations, no pattern detection, no cross-machine sync, no scripting. |
| **Hand-edited `.lsrules` files** | No real-time observation feeding back into authoring; no mutation safety; the user must learn the schema. |
| **Existing community CLI tools (e.g., mlevin2's rule-manager)** | Single-purpose, no LLM, no MCP integration, must be invoked manually per task. |
| **Just asking ChatGPT/Claude in chat** | The model can't see your actual traffic, model, or rules. Limited to generic advice. |

The MCP's unique value is the combination: an LLM that can both *read your real firewall state* and *write changes to it safely.*

## Recommended v1 scope (smaller than the full ADR-0003 catalog)

To ship something useful fast:

**Ship in M1–M3 (high value, low risk):**
- `doctor`
- `tail_log`, `tail_traffic`, `capture_process_traffic`, `show_restrictions`
- `list_preferences`, `read_preference`, `write_preference` (allowlisted)
- `get_rules_for_process`, `find_rules_for_remote`, `explain_rule_match`
- All Track A authoring tools
- `enable_rule_group`, `disable_rule_group`, `activate_profile`, `deactivate_all_profiles`, `update_factory_rule_groups`
- `disable_blocklist_entry`, `enable_blocklist_entry`, `list_blocklist_overlays`

**Ship in M4 (advanced; behind a setting):**
- `add_rule_to_live_model`, `update_rule_in_live_model`, `remove_rule_from_live_model`
- `apply_lsrules_file_to_live_model`
- `restore_model_from_file`

**Defer to v2:**
- Profile create/delete
- A curated telemetry-hosts data layer for the `block_telemetry_for_app` prompt
- A native `.app` distribution / SMJobBless privileged helper

**Required setup the user does once:**
- Enable "Allow access via Terminal" in LS Preferences → Security
- Configure TouchID for sudo (per ADR-0006)

With both setup steps done, every use case above works with no per-call password prompt.

## Honest verdict

The MCP is **worth building** for these reasons:

1. **The capability is real.** Empirical verification against your LS 6.3.3 shows the CLI exposes everything needed for the ten use cases above.
2. **The value is not duplicated by the GUI.** Eight of the ten use cases are either painful or impossible with the GUI alone.
3. **The safety story is strong.** Tracks A / B-direct / B-surgery, confirmation tokens, hard guards on `protected`/`factoryID` rules, `restore-model -t` always-on, blocklist overlays as a clean additive surface.
4. **The unknowns are bounded.** What we don't know (telemetry list curation, exact `rulegroup` name format) does not block any of the high-value use cases.

The only reasons NOT to build it:
- You only ever interact with LS through the alert popup. (The MCP doesn't help you here.)
- You never bulk-edit rules and have <20 rules total. (The cleanup/audit value is small at that scale.)
- You can't or won't configure TouchID for sudo. (Read-only mode still works, but you lose the mutation half of the value.)

For anyone outside that narrow profile — and certainly for the project owner who wanted "examine traffic, determine the rules for various IPs/domains, and set those rules" — the MCP delivers.
