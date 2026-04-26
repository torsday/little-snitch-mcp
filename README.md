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
