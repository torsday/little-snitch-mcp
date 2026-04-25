# little-snitch-mcp

A Model Context Protocol (MCP) server for the [Little Snitch](https://obdev.at/littlesnitch) macOS firewall.

Lets an LLM (via Claude Desktop, Claude Code, or any MCP client) read and safely mutate [Little Snitch 6](https://obdev.at/littlesnitch) firewall state on macOS. Every live mutation requires an explicit confirmation token; an automatic backup is taken before anything is applied to the live model.

> **Requires:** Little Snitch 6.3.3+, macOS. LS5 is out of scope.

---

## Installation

### Binary download (recommended)

1. Download the notarized binary from the [latest release](https://github.com/torsday/little-snitch-mcp/releases/latest) for your architecture:
   - `little-snitch-mcp-aarch64-apple-darwin` — Apple Silicon (M1/M2/M3/M4)
   - `little-snitch-mcp-x86_64-apple-darwin` — Intel

2. Mark executable and move to your PATH:

```bash
chmod +x little-snitch-mcp-*-apple-darwin
sudo mv little-snitch-mcp-*-apple-darwin /usr/local/bin/little-snitch-mcp
```

The binary is signed and notarized by Apple (Developer ID); Gatekeeper validates it on first run.

### Build from source

```bash
git clone https://github.com/torsday/little-snitch-mcp.git
cd little-snitch-mcp
cargo build --release
# Binary: target/release/little-snitch-mcp
```

Requires Rust 1.85+ (edition 2024).

---

## Security & trust

`little-snitch-mcp` is a **local-only** Rust binary that drives the **local** Little Snitch app via Apple's `littlesnitch` CLI. Installing it does not introduce cloud connectivity, telemetry, or network egress that wasn't already on your machine — and the binary you're trusting with sudo is small enough to audit in an afternoon.

### Data flow

```
Little Snitch model (local) ─→ littlesnitch CLI (local) ─→ MCP server (local stdio)
                                                                 │
                                                                 ↓
                                                    MCP client (local)
                                                                 │
                                                                 ↓
                                              LLM provider (only if your client uses one)
```

The LLM hop at the bottom is **your client's** choice, not this server's. If you run a local-only client (or a client configured to use a local model), nothing in this stack reaches the network.

### Hard guarantees

Each guarantee is enforced by code, not by promise. Click through to verify.

- **No network sockets** — the binary opens zero outbound connections. The dependency graph is the proof: [`Cargo.toml`](./Cargo.toml) contains no HTTP client (no `reqwest`, `hyper`, `ureq`, `isahc`, `surf`, `curl`), no async-net runtime is enabled (`tokio` features are pinned to `macros, rt-multi-thread, io-std, signal, process, time` — `net` is **not** in the list), and the only use of `std::net` is `IpAddr` parsing for CIDR matching against in-memory rule strings ([`src/tools/find_rules_for_remote.rs`](./src/tools/find_rules_for_remote.rs)). There is no socket-opening code path for an attacker to reach.
- **Stdio-only MCP transport** — the `rmcp` server is built with `features = ["server", "macros", "transport-io", "schemars"]` only. No HTTP, no SSE, no WebSocket transports compiled in. Communication is JSON-RPC over the stdin/stdout pair the MCP client launched the process with.
- **Tool-level safety classification, enforced at the call site** — every tool is registered with one of five tiers in [`src/safety/classification.rs`](./src/safety/classification.rs); the dispatcher checks the tier before invoking the tool, not the tool implementation:

  | Tier | What it can do | Examples |
  |---|---|---|
  | **SafeRead** | Read-only. No side effects. No sudo. | `tail_traffic`, `get_rules_for_process`, `find_rules_for_remote`, `doctor` |
  | **SudoRead** | Read-only but the CLI requires sudo. No mutations. | a small set of `littlesnitch` queries that require root |
  | **ManagedWrite** | Writes only inside the managed rules directory. Never touches the live model. No sudo. | `create_lsrules_file`, `add_rule_to_lsrules_file`, `update_rule_in_lsrules_file` |
  | **LiveWrite** | Mutates the live Little Snitch model. Requires sudo **and** a fresh confirmation token. | `add_rule_to_live_model`, `manage_rule_groups`, `update_factory_rule_groups` |
  | **LiveWriteStrong** | Full-model mutations (e.g. `restore-model`). Same gate as LiveWrite, plus mandatory pre-backup. | `restore_model_from_file` |
- **Two-step confirmation protocol for every live mutation** — no single LLM prompt can change the live model. The `prepare_*` tool reads the current model, computes a diff hash, and issues an HMAC-SHA256 token (5-minute TTL); the corresponding apply tool re-reads the model, recomputes the hash, and refuses if anything drifted. Implementation in [`src/safety/token.rs`](./src/safety/token.rs); the eight verifier checks are pinned by ADR-0004 §9 and the protocol's tests.
- **Automatic backup before every live mutation** — every LiveWrite path runs through [`src/tools/backup_harness.rs`](./src/tools/backup_harness.rs), which calls `littlesnitch export-model` into the managed `backups/` directory before any mutation. A timestamped JSON snapshot exists on disk before `restore-model` ever runs.
- **Allowlisted preferences keys** — [`src/safety/prefs.rs`](./src/safety/prefs.rs) and [`src/safety/secret_prefs.rs`](./src/safety/secret_prefs.rs) gate which `littlesnitch prefs` keys can be read or written; arbitrary preference manipulation is rejected by the dispatcher, not the tool.
- **Managed directory is mode-0700 and bounded** — [`src/managed_dir.rs`](./src/managed_dir.rs) creates `~/Library/Application Support/little-snitch-mcp/` at boot with mode 0700 (owner-only). All file-writing tools resolve paths relative to that root; the env override `LSMCP_MANAGED_DIR` lets you relocate it for testing but cannot escape into other writable surfaces at tool-call time.
- **No telemetry, no analytics, no phone-home** — production dependencies are the eighteen crates listed in [`Cargo.toml`](./Cargo.toml) (rmcp, tokio, serde, serde_json, schemars, anyhow, thiserror, clap, tracing, tracing-subscriber, hmac, sha2, subtle, rand, hex, regex, jsonschema, similar, ipnet). None of them open network sockets in the configured feature set.
- **`cargo audit` runs on every CI build** — [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, and `cargo audit` on every push and PR. A new RUSTSEC advisory against any dependency fails the build.
- **`cargo deny` enforces the no-network invariant in CI** — [`deny.toml`](./deny.toml) bans `reqwest`, `hyper`, `ureq`, `isahc`, `surf`, `curl`, `tokio-tungstenite`, `tonic`, `rustls`, `native-tls`, `openssl`, `mio`, and `async-net`. A future contributor pulling in any of them — directly or transitively — fails CI before merge. The README's "no network sockets" claim is enforced, not asserted.
- **GitHub Actions pinned to commit SHAs** — every workflow step uses `<owner>/<action>@<sha>`, with the human-readable tag in a comment. Mutable-tag attacks (e.g. the March 2025 `tj-actions/changed-files` incident) become a non-event. Dependabot rolls the SHAs forward weekly via [`.github/dependabot.yml`](./.github/dependabot.yml).
- **Release binaries carry a Sigstore-signed build-provenance attestation** — [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) produces a transparency-log-published attestation tying each binary to the exact workflow run, repository, and commit. Verify with `gh attestation verify <binary> --repo torsday/little-snitch-mcp`. This is the Rust/binary analog of npm provenance.

### Opt-in escape hatches

Two facilities deliberately broaden the surface and are gated explicitly:

- **`sudo` for LiveWrite tools** — the live model can only be mutated as root, by design. The `warm_sudo` tool exists to refresh the credential cache so non-interactive sessions don't fail mid-mutation; it never stores a password and never bypasses the system sudo policy. Configure TouchID-for-sudo (detected by [`src/safety/touchid.rs`](./src/safety/touchid.rs)) for non-interactive convenience.
- **The `littlesnitch` CLI itself** — every privileged operation goes through Objective Development's signed CLI. Anything that CLI cannot do, this server cannot do. We do not GUI-script and we do not invoke private SPIs.

There is **no** raw-script escape hatch in this server: the agent cannot ship arbitrary shell, AppleScript, or JXA through the MCP surface.

### Verify it yourself

You don't have to take this README's word for any of the above.

1. **Audit the source.** The repo at [github.com/torsday/little-snitch-mcp](https://github.com/torsday/little-snitch-mcp) is the canonical source. Each release is built from its own `v<version>` tag.
2. **Confirm there's no networking code.**
   ```bash
   git clone https://github.com/torsday/little-snitch-mcp && cd little-snitch-mcp
   git grep -nE 'reqwest|hyper|ureq|isahc|TcpStream|TcpListener|UdpSocket' -- 'src/**/*.rs' Cargo.toml
   # Expected: no matches.
   git grep -n 'std::net' -- 'src/**/*.rs'
   # Expected: only IpAddr/IpNet usage in find_rules_for_remote.rs.
   ```
3. **Verify the binary's signature and notarization.** Release binaries are built by GitHub Actions on a clean macOS runner, signed with a **Developer ID Application** certificate, and submitted to Apple's notarization service. The stapled ticket means Gatekeeper validates offline — no network call at launch:
   ```bash
   codesign -dv --verbose=4 /usr/local/bin/little-snitch-mcp
   spctl --assess --verbose /usr/local/bin/little-snitch-mcp
   ```
4. **Verify build provenance.** Each release artifact is published with a Sigstore-signed attestation tying it to the GitHub Actions run that built it:
   ```bash
   gh attestation verify ./little-snitch-mcp-aarch64-apple-darwin.tar.gz \
     --repo torsday/little-snitch-mcp
   # Expected: "✓ Verification succeeded!" with a workflow URL and commit SHA.
   ```
5. **Verify the download checksum.** Every release ships a `SHA256SUMS` file:
   ```bash
   shasum -a 256 -c SHA256SUMS
   # Expected: "little-snitch-mcp-...tar.gz: OK" for each artifact.
   ```
6. **Confirm the dependency tree is clean.**
   ```bash
   cargo tree --edges no-dev | grep -E 'reqwest|hyper|ureq|tokio-tungstenite'
   # Expected: no matches.
   cargo audit
   cargo deny check bans advisories sources licenses
   # Expected: no advisories, no banned crates, no unknown sources.
   ```

### Out of scope

The threat model deliberately excludes anything outside this codebase: vulnerabilities in Little Snitch itself, the `littlesnitch` CLI, the macOS sandbox, Apple's notarization and codesign infrastructure, transitive Cargo CVEs (tracked via `cargo audit`, but not part of this project's guarantees), and any attacker with root-equivalent local access (who could replace the binary, the CLI, or your shell). A compromised LLM client that drops malicious tool calls is in-scope: the confirmation-token protocol exists precisely to make a single bad call non-fatal.

### Reference docs

- [`SECURITY.md`](./SECURITY.md) — vulnerability reporting, scope, hardening commitments
- [`docs/design.md` § Threat model](./docs/design.md#threat-model) — assets, adversaries, attack surfaces, accepted risks
- [`docs/adr/0004-safety-permissions-and-confirmation.md`](./docs/adr/0004-safety-permissions-and-confirmation.md) — full safety model: tier taxonomy, token protocol, eight verifier checks
- [`docs/adr/0006-sudo-strategy-and-no-tty-handling.md`](./docs/adr/0006-sudo-strategy-and-no-tty-handling.md) — sudo posture, TouchID detection, no-TTY handling
- [`deny.toml`](./deny.toml) — the cargo-deny configuration that pins the no-network invariant
- [`src/safety/`](./src/safety/) — classification registry, token logic, prefs allowlist, sudo and TouchID detection

---

## Quick start

### Prerequisites

1. **Little Snitch 6.3.3 or newer** installed at the canonical path (`/Applications/Little Snitch.app`).
2. **CLI access enabled**: open Little Snitch Preferences → Security → check "Allow access via Terminal".
3. **sudo access**: most write operations require root. Configure [TouchID for sudo](https://support.apple.com/en-us/102280) to avoid password prompts (the `warm_sudo` tool guides you through this).

Run the `doctor` tool from any MCP client to verify all prerequisites in one shot.

### Claude Desktop

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

Restart Claude Desktop after saving.

### Claude Code

```bash
claude mcp add little-snitch /usr/local/bin/little-snitch-mcp
```

### Other MCP clients

The server speaks MCP over stdio — no sockets, no network. Point your client at the binary with no arguments.

---

## What it does

- **Read firewall state** — live log stream, historical traffic stats, the full rule model, preferences.
- **Author `.lsrules` rule-group files** in a managed directory you can `git`-track.
- **Toggle rule groups** (`rulegroup -e/-d`), switch profiles (`profile -a/-d`), and refresh factory groups via dedicated CLI commands.
- **Add/edit/delete individual rules** via a confirmed `export-model` → patch → `restore-model -t` round-trip (with auto-backup).
- **Surgically disable blocklist entries** via the deletion-overlay arrays — without modifying the upstream blocklist.
- **Apply changes to the live model** only with explicit per-call confirmation and an automatic backup before every mutation.

### Example prompts

**Observability**
- *"What did Slack talk to in the last hour? Anything I shouldn't expect?"* — pulls live traffic, summarizes destinations, flags outliers.
- *"Why was this connection allowed?"* — walks the rule model and explains the matching rule in plain English.
- *"Tail traffic from this PID for 30 seconds and tell me what it's doing."* — bounded packet capture + interpretation.

**Cleanup**
- *"I have 21 rules. Which haven't been used in 90 days? Which apps have orphaned rules?"* — sort by `lastUsed`/`useCount`, propose removals, you approve, MCP applies.
- *"Generate my weekly firewall report."* — diff prior model snapshot, aggregate new domains by app, summarize.

**Authoring**
- *"Block all telemetry endpoints for Adobe Creative Cloud."* — drafts a `.lsrules` blocklist, you review, apply with confirmation.
- *"I just installed Linear. Watch its traffic for 5 minutes and propose a sane rule set."* — observation window → clustered destinations → drafted rules.

**Incident response**
- *"Block evil.example everywhere right now."* — high-priority deny rule, two-step confirmation, auto-backed-up before applying.

**Surgical exceptions**
- *"The EasyList blocklist is blocking my work analytics. Disable just that one entry."* — uses LS's deletion-overlay arrays so the upstream blocklist stays intact.

**Lifecycle**
- *"Switch to my paranoid profile."* — direct CLI, no model surgery.
- *"Sync my firewall rules from this git repo across both my Macs."* — managed `.lsrules` directory is the repo.

The full set of ten use cases with confidence ratings is in [docs/value-prop.md](docs/value-prop.md). Each is grounded in capabilities verified against a live LS 6.3.3 install — not "the docs say this should work."

---

## What it explicitly does not do

The Little Snitch CLI does not expose **alert popup handling** (approve/deny live alerts) or **subscribing to a remote `.lsrules` URL** (a one-time GUI action). We do not pretend it does. We do not GUI-script. See [docs/design.md](docs/design.md) for the full non-goals list.

---

## Release and distribution

Releases are built by the [GitHub Actions release workflow](.github/workflows/release.yml), which produces notarized, stapled binaries for both `aarch64-apple-darwin` (Apple Silicon) and `x86_64-apple-darwin` (Intel).

### Setting up Apple Developer secrets

The notarization step requires five repository secrets. Set them in **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Value |
|---|---|
| `APPLE_ID` | Your Apple ID email address (e.g. `you@example.com`) |
| `APPLE_TEAM_ID` | Your 10-character Apple Developer Team ID (found in [developer.apple.com/account](https://developer.apple.com/account) under Membership) |
| `APPLE_APP_SPECIFIC_PASSWORD` | An app-specific password generated at [appleid.apple.com](https://appleid.apple.com) → Security → App-Specific Passwords |
| `MACOS_CERTIFICATE` | Base64-encoded Developer ID Application certificate (`.p12`). Export from Keychain Access, then: `base64 -i Certificate.p12 \| pbcopy` |
| `MACOS_CERTIFICATE_PWD` | The passphrase you set when exporting the `.p12` |

The certificate must be a **Developer ID Application** certificate (not Mac App Store). If you don't have one, request it at [developer.apple.com/account/resources/certificates](https://developer.apple.com/account/resources/certificates).

### Release process

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds both architectures, signs each binary, submits to Apple's notarization service, staples the ticket, and publishes the release assets.

---

## Design and background

Read in this order:

1. [docs/value-prop.md](docs/value-prop.md) — **start here**: ten concrete use cases with confidence ratings, recommended v1 scope, honest verdict.
2. [docs/feasibility-report.md](docs/feasibility-report.md) — empirical probe of LS 6.3.3, GUI-to-MCP capability matrix, model schema deep-dive.
3. [docs/design.md](docs/design.md) — overview, architecture diagram, worked example.
4. [docs/user-stories.md](docs/user-stories.md) — personas and acceptance criteria.
5. ADRs (in order):
   - [0001 — language, runtime, target LS version](docs/adr/0001-language-runtime-and-target-version.md)
   - [0002 — CRUD strategy](docs/adr/0002-crud-strategy.md)
   - [0003 — MCP tool surface](docs/adr/0003-mcp-tool-surface.md)
   - [0004 — safety, permissions, confirmation protocol](docs/adr/0004-safety-permissions-and-confirmation.md)
   - [0005 — deployment and configuration](docs/adr/0005-deployment-and-configuration.md)
   - [0006 — sudo strategy and no-TTY handling](docs/adr/0006-sudo-strategy-and-no-tty-handling.md)

---

## Reference material

The CLI we're targeting: [Little Snitch 6 command line overview](https://help.obdev.at/littlesnitch6/cmd-overview) (with [LS5's per-command flag reference](https://help.obdev.at/littlesnitch5/adv-commandline) still applicable for the commands shared between versions).
The file format we author: [`.lsrules` schema](https://developer.obdev.at/littlesnitch6/adv-lsrules-file-format).
