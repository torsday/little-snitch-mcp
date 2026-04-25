# Design overview — `little-snitch-mcp`

This document is the entry point to the design. It states what we're building and why, summarizes the architectural decisions made in the ADRs, and shows how the user stories flow through the system. Implementation tickets do not exist yet — this design must be reviewed and approved first.

---

## What this is

`little-snitch-mcp` is a Model Context Protocol server that lets an LLM (via any MCP client — Claude Desktop, Claude Code, IDE plugins) interact with the [Little Snitch](https://obdev.at/littlesnitch) macOS firewall. It exposes:

- **Read access** to logs, traffic statistics, preferences, and the rule model.
- **Declarative authoring** of `.lsrules` rule-group files in a managed directory.
- **Gated, confirmed mutations** of the live Little Snitch model for advanced workflows.

It is single-host, single-user, macOS-only, and targets **Little Snitch 6 (floor 6.3.3)**. LS5 is out of scope; users on LS5 should upgrade.

---

## Why this is non-trivial (and what's honest about scope)

A naive reading of the project is "Little Snitch must have a CRUD CLI; wrap it in MCP." It does not. Confirmed against the official LS6 CLI overview ([help.obdev.at/littlesnitch6/cmd-overview](https://help.obdev.at/littlesnitch6/cmd-overview)):

- The CLI exposes whole-model export/restore (`export-model` / `restore-model`), preference read/write, log readers, traffic capture, and (LS6-only) `update-rule-groups` to refresh factory groups.
- It does **not** expose per-rule add/edit/delete, profile switching, or live-alert handling.
- Per-rule mutation is achievable only via (a) authoring `.lsrules` files that LS imports/subscribes to, or (b) round-tripping the entire model JSON.

Both paths are valid; each has different ergonomics and risk. The MCP must offer both, default to the safer one, and gate the riskier one behind explicit confirmation. That tension is the central design problem and is what the ADRs resolve.

---

## Architectural shape

```
┌──────────────────────────────────────────────────────────────────────┐
│ MCP client (Claude Desktop / Claude Code / IDE plugin)               │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ stdio (MCP)
┌───────────────────────────────▼──────────────────────────────────────┐
│ little-snitch-mcp (single Rust binary, rmcp SDK)                     │
│                                                                      │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────────┐  │
│  │  Resources   │  │     Tools      │  │   Prompts (workflows)    │  │
│  │  (read-only) │  │ (Track A/B/C)  │  │                          │  │
│  └──────┬───────┘  └────────┬───────┘  └────────┬─────────────────┘  │
│         │                   │                   │                    │
│  ┌──────▼───────────────────▼───────────────────▼────────────────┐   │
│  │                  Safety layer (ADR-0004)                      │   │
│  │   classification • confirmation tokens • hard guards          │   │
│  └──────┬───────────────────────────────────────────────────────┘    │
│         │                                                            │
│  ┌──────▼─────────────┐  ┌────────────────────┐                      │
│  │   CLI adapter      │  │  Managed dir       │                      │
│  │  (littlesnitch)    │  │  (.lsrules files)  │                      │
│  └──────┬─────────────┘  └────────┬───────────┘                      │
└─────────┼──────────────────────────┼─────────────────────────────────┘
          │                          │
┌─────────▼─────────┐      ┌─────────▼─────────────────────────────┐
│  Little Snitch    │      │  ~/Library/Application Support/       │
│  daemon + GUI     │      │  little-snitch-mcp/                   │
│  (LS6 ≥ 6.3.3)    │      │    rules/        (Track A files)      │
└───────────────────┘      │    backups/      (auto pre-restore)   │
                           └───────────────────────────────────────┘
```

---

## ADR map

| ADR | Topic | Outcome |
|---|---|---|
| [0001](adr/0001-language-runtime-and-target-version.md) | Language, runtime, target LS version | Rust + `rmcp` (official MCP SDK), single static binary via Homebrew, target LS6 (floor 6.3.3). |
| [0002](adr/0002-crud-strategy.md) | CRUD strategy | Three-track model: declarative `.lsrules` authoring (default), Track B-direct via dedicated CLI commands (`rulegroup`, `profile`, `update-rule-groups`), Track B-surgery via `export-model`+`restore-model -t` for the rest. |
| [0003](adr/0003-mcp-tool-surface.md) | Tool/resource/prompt catalog | Concrete naming and inputs for every tool; story-to-tool traceability. |
| [0004](adr/0004-safety-permissions-and-confirmation.md) | Safety model | Tool classification, confirmation-token protocol, hard guards, sudo policy. The CLI lockout footgun is defused by hard-coding `restore-model -t`. |
| [0005](adr/0005-deployment-and-configuration.md) | Distribution and config | Homebrew tap distribution (signed/notarized binaries), env-var config, version detection, no telemetry. |
| [0006](adr/0006-sudo-strategy-and-no-tty-handling.md) | Sudo + no-TTY handling | TouchID for sudo (recommended), automatic read-only mode (fallback), `warm_sudo` recovery tool. Solves the GUI-spawned MCP can't authenticate problem. |

**Companion document:** [feasibility-report.md](feasibility-report.md) — empirical probe of LS 6.3.3, GUI-to-MCP capability matrix, model schema deep-dive, and outstanding verification items. Read this first if you want to confirm the design actually works against the live CLI.

---

## How a user story flows through the system

Worked example: **Story C3 — "block all traffic to evil.example everywhere right now."**

1. User says it in their MCP client.
2. LLM invokes the **`prepare_incident_block`** prompt with `remote = "evil.example"`.
3. Prompt logic:
   - Calls `validate_lsrules` on a drafted rule (`process: any, remote-hosts: evil.example, action: deny, priority: high`).
   - Calls `create_lsrules_file` writing `incident-evil-example-2026-04-25.lsrules` into the managed dir. (Track A — managed-write, no confirmation.)
   - Calls `prepare_live_model_change` describing "fold this file into the live model as a new local rule group." (Track B — produces a diff and a single-use confirmation token.)
4. The MCP client surfaces the diff to the user. User approves.
5. LLM calls `apply_lsrules_file_to_live_model` with the file path and the confirmation token.
6. Safety layer:
   - Re-computes the diff; verifies token hash matches.
   - Runs `export-model` to `backups/2026-04-25T20-31-12Z.json` and includes that path in the tool response.
   - Runs `restore-model` with the patched payload.
7. Tool returns `{ ok: true, backup: ".../2026-04-25T20-31-12Z.json", applied_group: "incident-evil-example-2026-04-25" }`.
8. LLM tells the user: rule applied, file lives at X, backup at Y.

If the user instead wanted only the safe path, they can ask for "the file but don't apply" and steps 3a–3b are the entire flow.

---

## Open questions (must be resolved before implementation)

These are flagged in the ADRs but listed here for visibility:

1. **CLI lockout error string.** What exact stderr does `littlesnitch` produce when "Allow access via Terminal" is off? The docs do not specify; we'll discover empirically and add a regex match in the safety layer.
2. **Exit codes.** Not documented; we'll catalog them during implementation and add to `cli/contract.ts`.
3. **`restore-model` partial-failure semantics.** If the JSON is structurally valid but semantically invalid (e.g., references a deleted user UID), what does the CLI do? Determines our backup-restore strategy.
4. **`.lsrules` file size limits.** Practical, not documented. We'll set a soft cap of 5 MB per file and document.
5. **Whether to ship a curated "known telemetry hosts" list** (used by the `block_telemetry_for_app` prompt). Source, license, refresh cadence — all TBD.

---

## Non-goals (explicit)

Repeated from the user-stories doc and ADR-0003 because they are the design's most likely scope-creep vectors:

- Real-time alert handling.
- Profile switching.
- Multi-host / fleet management.
- HTTPS hosting of subscriptions (we author files; we do not host).
- Little Snitch for Linux.
- GUI scripting.

---

## What happens after this is approved

1. Resolve the open questions above (small spikes; can be done in the implementation phase if cheap).
2. Decompose ADR-0003's tool catalog into per-tool implementation tickets, with safety classification per tool from ADR-0004.
3. File tickets in the GitHub project (intentionally not yet — per the user's instruction we design first).
4. Implementation in milestones:
   - **M0 — skeleton:** stdio MCP server, version detection, `doctor` tool.
   - **M1 — read surface:** all Track C tools and their resources.
   - **M2 — Track A authoring:** managed dir, lsrules CRUD on files, schema validation.
   - **M3 — Safety + Track B:** confirmation protocol, hard guards, `apply_lsrules_file_to_live_model`, `export_model_backup`, `set_rule_group_disabled_in_live_model`.
   - **M4 — Prompts and polish:** the named workflows from ADR-0003.
   - **M5 — Distribution:** npm publication, README config snippets per client.

---

## Threat model

The trust story summarized in the README's "Security & trust" section, formalized.

### Assets

| Asset | Why it matters |
|---|---|
| The live Little Snitch model | A tampered model can silently allow exfiltration or block legitimate traffic. |
| Sudo credentials (cached state) | LiveWrite tools depend on `sudo`; a forged invocation could mutate the live model. |
| The managed directory (`~/Library/Application Support/little-snitch-mcp/`) | Holds authored `.lsrules` files and pre-mutation backups. Tampering corrupts what the user can review or restore. |
| The release binary | Runs as root by design. A swapped binary owns the host's network policy. |
| Confirmation tokens | The HMAC secret and token-state machine are the gate between an LLM prompt and a model mutation. |

### Adversaries

| Adversary | Realistic capability | Defense posture |
|---|---|---|
| **Compromised LLM client** (or a prompt-injection attack against a cooperative one) | Issues arbitrary tool calls, including LiveWrite. | The two-step prepare/apply protocol forces a human-readable diff into the loop and binds the apply call to a model-state hash. A single bad call cannot mutate the live model. |
| **Malicious / compromised dependency** | New version of a transitive crate adds a network capability or a backdoor. | `cargo audit` (RUSTSEC) + `cargo deny [bans]` (HTTP/TLS/socket crates) + Dependabot review. |
| **Network attacker** | Anywhere outside the host. | Out of reach: the binary opens no sockets. Defense is structural, not configurable. |
| **Local non-root attacker on the user's host** | Reads / writes user-owned files; cannot escalate without sudo. | Managed dir is mode 0700; tokens are HMAC-SHA256 with TTL; backups are owner-readable only. The live model itself is sudo-gated by Little Snitch, not by us. |
| **Local root attacker** | Can replace the binary, the `littlesnitch` CLI, the user's shell, sudoers, anything. | Out of scope. Codesign + notarization + build-provenance attestation make a *swap-and-go* attack against the **distributed** binary detectable; nothing this server does can defend a host whose root is already compromised. |
| **Apple / Objective Development supply chain** | Compromise of codesign infrastructure, notarization service, or the `littlesnitch` CLI itself. | Out of scope; we trust the platform vendor at this layer. |

### Attack surfaces and mitigations

| Surface | Risk | Mitigation | Verifies |
|---|---|---|---|
| MCP transport | A non-stdio transport (HTTP, SSE, WS) would expose the tool surface to remote callers. | `rmcp` built with `transport-io` only; ban list (`deny.toml`) on `tokio-tungstenite`, `tonic`, etc. | `rg 'transport-' Cargo.toml` |
| Network sockets | Any HTTP / TCP / UDP / TLS code path. | No HTTP-client crate in `Cargo.toml`; `tokio` features omit `net`; `cargo-deny [bans]` rejects HTTP/TLS crates as a CI gate. | `git grep TcpStream\|TcpListener\|UdpSocket -- 'src/**/*.rs'` |
| Confirmation-token forgery | Predictable / replayable / TTL-bypassable tokens let a single LLM call mutate the live model. | HMAC-SHA256 over (tool, args-canonicalized, model-state-hash, expiry); `subtle::ConstantTimeEq` for verification; 5-minute TTL; bound to a model-state hash that's recomputed at apply time. | ADR-0004 § 9 (eight verifier checks) and `src/safety/token.rs` tests. |
| Path traversal | A tool that takes a path argument writes outside the managed dir. | All managed-dir writes flow through `src/managed_dir.rs::resolve()`, which canonicalizes paths and rejects traversal. The mode-0700 dir is created at boot. | Per-tool tests in `tests/`. |
| Privilege escalation via `sudo` | A LiveWrite tool calls `sudo` with attacker-influenced arguments. | `sudo` is invoked only with a fixed argv prefix and the `littlesnitch` binary path; user-supplied data lands in argv positions that `littlesnitch` parses, never as flags. | Code review + integration tests. |
| Logging leakage | Tracing emits secrets, full pref values, or token bytes. | `tracing` logs to stderr only (never stdout, which is reserved for MCP framing); tokens are never `Display`/`Debug`-printed; pref keys are allowlisted. | Manual audit; future: `Redacted<T>` newtype. |
| Stdout corruption | Anything writing to stdout outside the MCP framing path corrupts JSON-RPC. | `tracing-subscriber` configured for stderr; `println!` is forbidden (clippy). | `git grep 'println!\|print!' -- 'src/**/*.rs'` |
| Release-artifact tampering | A modified binary published as an official release. | Codesign (Developer ID), Apple notarization, Sigstore-signed GitHub Actions build-provenance attestation, SHA256SUMS, `gh attestation verify`. | Section: "Verify it yourself" in README. |
| Dependency confusion | A typo'd / squatted crate name. | `[sources]` in `deny.toml` allows only `crates.io`; no git deps. | CI: `cargo deny check sources`. |

### Accepted risks

- An attacker who already controls the user's `sudo` configuration or root account can do anything; this server does not pretend to defend against that.
- A user who *consciously* approves a malicious diff in the prepare/apply handshake will see the diff applied. The protocol exists to require informed consent, not to override it.
- Transitive Cargo CVEs not yet in RUSTSEC will not be caught by `cargo audit`. The Dependabot weekly cadence and `[bans]` denylist narrow but do not eliminate this window.

### Out of scope

Same as `SECURITY.md § Out of scope`: vulnerabilities in Little Snitch itself, the `littlesnitch` CLI, macOS, the sandbox, codesign, notarization, Apple developer infrastructure, and root-equivalent local attackers.
