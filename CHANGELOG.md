# Changelog

All notable changes to `little-snitch-mcp` are documented in this file.

---

## v1.0.0 — 2026-04-26

### First stable release

`little-snitch-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that lets an LLM (Claude Desktop, Claude Code, or any MCP client) read and safely mutate [Little Snitch 6](https://obdev.at/littlesnitch) firewall state on macOS. Every live mutation requires an explicit confirmation token; an automatic backup is taken before anything is applied to the live model.

Minimum supported version: **Little Snitch 6.3.3** (floor tested empirically).

---

### Installation

#### Homebrew (recommended)

```bash
# Tap not yet published — use the binary download below for v1.0.0.
```

#### Binary download

1. Download the notarized binary from the [v1.0.0 release assets](https://github.com/torsday/little-snitch-mcp/releases/tag/v1.0.0) for your architecture:
   - `little-snitch-mcp-aarch64-apple-darwin` — Apple Silicon (M1/M2/M3/M4)
   - `little-snitch-mcp-x86_64-apple-darwin` — Intel

2. Mark executable and move to your PATH:

```bash
chmod +x little-snitch-mcp-*-apple-darwin
sudo mv little-snitch-mcp-*-apple-darwin /usr/local/bin/little-snitch-mcp
```

#### Build from source

```bash
git clone https://github.com/torsday/little-snitch-mcp.git
cd little-snitch-mcp
cargo build --release
# Binary: target/release/little-snitch-mcp
```

Requires Rust 1.85+ (edition 2024).

---

### MCP client configuration

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "little-snitch": {
      "command": "/usr/local/bin/little-snitch-mcp"
    }
  }
}
```

Restart Claude Desktop after saving. The server registers automatically — no additional setup.

#### Claude Code

```bash
claude mcp add little-snitch /usr/local/bin/little-snitch-mcp
```

#### Other MCP clients

The server speaks MCP over stdio (no sockets, no network). Point your client at the binary with no arguments.

---

### Prerequisites

1. **Little Snitch 6.3.3 or newer** installed at the canonical path (`/Applications/Little Snitch.app`).
2. **CLI access enabled**: open Little Snitch Preferences → Security → check "Allow access via Terminal".
3. **sudo access**: most write operations require root. Configure [TouchID for sudo](https://support.apple.com/en-us/102280) to avoid password prompts (`warm_sudo` tool will guide you).

Run the `doctor` tool from any MCP client to verify all prerequisites.

---

### Ten use cases shipped in v1.0

See [docs/value-prop.md](docs/value-prop.md) for the full description, evidence ratings, and motivation for each.

| # | Use case | Key tools / prompts |
|---|---|---|
| 1 | **Daily traffic triage** — *"Show me everything Slack talked to in the last hour"* | `tail_traffic`, `get_rules_for_process`, `find_rules_for_remote`, `triage_unknown_connections` prompt |
| 2 | **Rule cleanup** — *"Which rules haven't been used in 90+ days?"* | `get_rules_for_process`, `audit_rules_for_process` prompt, `remove_rule_from_live_model` |
| 3 | **Block telemetry for a specific app** | `block_telemetry_for_app` prompt, `create_lsrules_file`, `apply_lsrules_file_to_live_model` |
| 4 | **Incident response: hard-deny a beacon** | `prepare_incident_block` prompt, `prepare_live_model_change`, `add_rule_to_live_model` |
| 5 | **Explain why a connection was allowed** | `find_rules_for_remote`, `get_rules_for_process` (simulate matching manually) |
| 6 | **New-app onboarding: observe + draft rules** | `capture_process_traffic`, `tail_traffic`, `create_lsrules_file` |
| 7 | **Surgical blocklist exception** | `disable_blocklist_entry`, `enable_blocklist_entry`, `list_blocklist_overlays` |
| 8 | **Profile switching by context** | `prepare_activate_profile`, `activate_profile`, `deactivate_all_profiles` |
| 9 | **Weekly audit and report** | `weekly_review` prompt, `tail_traffic`, resource `littlesnitch://model` |
| 10 | **GitOps for rules** | `create_lsrules_file`, `add_rule_to_lsrules_file`, `apply_lsrules_file_to_live_model`, managed `~/Library/Application Support/little-snitch-mcp/rules/` directory |

---

### Tools shipped

#### Read (no sudo required)

| Tool | What it does |
|---|---|
| `doctor` | Five-check environment report: binary found, CLI authorized, TouchID sudo, managed dir, restore-model flag |
| `tail_log` | Streams Little Snitch JSON log events |
| `tail_traffic` | Parses `log-traffic` CSV → typed JSON rows, filterable by process/remote/direction |
| `capture_process_traffic` | Bounded observation window: watch one process's connections for N seconds |
| `show_restrictions` | Reports which operations are restricted by the active profile |
| `read_preference` | Read a single LS global preference by key |
| `list_preferences` | List all global preferences with redaction of sensitive values |
| `export_model_backup` | Export the full live model to a timestamped JSON file in the managed directory |
| `validate_lsrules` | Validate a `.lsrules` file or inline JSON against the schema |
| `diff_lsrules_files` | Unified diff between two managed `.lsrules` files |
| `get_rules_for_process` | Return all rules matching a given process path, grouped by rule group |
| `find_rules_for_remote` | Return all rules whose remote matcher covers an IP, CIDR, hostname, or domain |

#### Managed file authoring (no sudo required)

| Tool | What it does |
|---|---|
| `create_lsrules_file` | Create a new `.lsrules` file in the managed directory |
| `add_rule_to_lsrules_file` | Append a rule to an existing managed `.lsrules` file |
| `update_rule_in_lsrules_file` | Patch a rule in a managed file by index or match tuple |
| `remove_rule_from_lsrules_file` | Remove a rule from a managed file |
| `set_lsrules_metadata` | Update the `name` or `description` field of a managed file |

#### Live model write (sudo required, confirmation token)

| Tool | What it does |
|---|---|
| `prepare_live_model_change` | Dry-run: simulate a patch, compute diff hash, issue a confirmation token |
| `add_rule_to_live_model` | Apply a new rule from a confirmed prepare |
| `update_rule_in_live_model` | Patch an existing rule in the live model |
| `remove_rule_from_live_model` | Remove a rule from the live model |
| `apply_lsrules_file_to_live_model` | Fold all rules from a managed `.lsrules` file into the live model |
| `restore_model_from_file` | Restore a previously-exported model backup (escape hatch) |
| `write_preference` / `remove_preference` | Write or remove a LS global preference (allowlisted keys only) |
| `prepare_activate_profile` / `activate_profile` | Switch to a named profile |
| `deactivate_all_profiles` | Deactivate all profiles (revert to system defaults) |
| `prepare_enable_rule_group` / `enable_rule_group` | Enable a disabled rule group |
| `prepare_disable_rule_group` / `disable_rule_group` | Disable an active rule group |
| `prepare_update_factory_rule_groups` / `update_factory_rule_groups` | Refresh factory rule groups from Objective Development |
| `disable_blocklist_entry` / `enable_blocklist_entry` | Surgically disable/enable a single entry in a subscribed blocklist |
| `warm_sudo` | Prime sudo credentials with TouchID guidance |

### Prompts shipped

| Prompt | What it does |
|---|---|
| `block_telemetry_for_app` | Drafts a `.lsrules` blocklist for a named app's telemetry endpoints (use case #3) |
| `prepare_incident_block` | Two-track incident response: quick deny rule or full model change with review (use case #4) |
| `triage_unknown_connections` | Guided traffic-triage workflow for unfamiliar processes or connections (use case #1) |
| `audit_rules_for_process` | Human-readable audit report: rules by group, disabled groups flagged, redundant and conflicting rules called out |
| `weekly_review` | Weekly firewall audit and report template (use case #9) |

### MCP Resources

| Resource URI | What it exposes |
|---|---|
| `littlesnitch://model` | Full live model JSON (5-second TTL cache) |
| `littlesnitch://model/rule-groups` | Derived summary of all rule groups with rule counts |
| `littlesnitch://model/rule-groups/{id}` | Detail for a single rule group including its rules |
| `littlesnitch://lsrules-files` | List of managed `.lsrules` files |
| `littlesnitch://lsrules-files/{name}` | Content of a specific managed `.lsrules` file |
| `littlesnitch://schema/lsrules` | JSON Schema for the `.lsrules` format |

---

### Architecture decisions (ADRs)

Six architecture decisions govern the v1.0 design; see [`docs/adr/`](docs/adr/):

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-language-runtime-and-target-version.md) | Rust + `rmcp`, targeting Little Snitch 6.3.3+ |
| [0002](docs/adr/0002-crud-strategy.md) | Track A (managed `.lsrules` files) + Track B (live model round-trip) |
| [0003](docs/adr/0003-mcp-tool-surface.md) | Tool surface taxonomy: SafeRead / SudoRead / ManagedWrite / LiveWrite / LiveWriteStrong |
| [0004](docs/adr/0004-safety-permissions-and-confirmation.md) | Confirmation-token protocol (HMAC-SHA256 signed, 5-minute TTL, diff-hash binding) |
| [0005](docs/adr/0005-deployment-and-configuration.md) | Stdio MCP transport, `LSMCP_*` env-var overrides, managed dir under `~/Library/Application Support/` |
| [0006](docs/adr/0006-sudo-strategy-and-no-tty-handling.md) | sudo gating via `LSMCP_DISABLE_LIVE_WRITE`, TouchID detection, `warm_sudo` UX |

---

### Safety model

Every live-model mutation follows a three-step protocol:

1. **Prepare** (`prepare_*` tool): reads the current model, computes a diff hash, issues an HMAC-signed confirmation token (5-minute TTL). Returns a human-readable summary for review.
2. **User reviews and approves** the summary out-of-band.
3. **Apply** (`*_apply` or non-`prepare_` tool): re-computes the diff hash, verifies the token, takes an automatic backup to the managed directory, then calls the LS CLI.

A token issued for one operation is cryptographically bound to that operation's diff hash and tool name — it cannot be replayed for a different operation or a model that has changed in the interim.

The `LSMCP_DISABLE_LIVE_WRITE=1` environment variable disables all live-write operations (useful for read-only deployments or CI).
