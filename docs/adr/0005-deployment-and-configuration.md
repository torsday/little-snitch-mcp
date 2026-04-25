# ADR-0005 — Deployment, configuration, and the user installation path

- **Status:** Proposed
- **Date:** 2026-04-25
- **Deciders:** Project owner
- **Depends on:** ADR-0001

## Context

The MCP server has to land on a user's macOS box, register with an MCP client (Claude Desktop today; Claude Code, IDE plugins, others tomorrow), and run reliably as a long-lived stdio process. The installation must be friction-light because users will try this on a whim and the moment they hit a 6-step setup they leave.

This ADR locks the distribution channel, the configuration shape, the install ergonomics, and the version-detection layer for LS5 vs LS6.

## Decision

### Distribution

- **Primary: Homebrew tap.** `brew tap torsday/little-snitch-mcp && brew install little-snitch-mcp`. The formula points at signed/notarized binaries from a tagged GitHub release.
- **Alternative: `cargo install little-snitch-mcp`** for users who prefer building from crates.io.
- **Manual: download the notarized binary from a GitHub release** and drop it into `/usr/local/bin/` or `/opt/homebrew/bin/`.
- **Future: `.pkg` installer.** Defer to v2; Homebrew covers the audience for v1.

The MCP binary is a single static stdio MCP server. No HTTP, no daemon, no background launch agent in v1.

### MCP client wiring

The README ships exactly one canonical config snippet per supported client. Initial coverage:

- Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`).
- Claude Code CLI (the `mcp` block in user/project config).

The snippet pins the command to `/opt/homebrew/bin/little-snitch-mcp` (or `/usr/local/bin/little-snitch-mcp` for Intel Macs / non-Homebrew installs) and passes config via env vars (see below). We do not ship a one-click installer in v1; documenting the snippet keeps maintenance cheap.

### Configuration

Configuration is read at startup from environment variables, with a hard preference for "fewer knobs is better." Initial knobs:

| Env var | Purpose | Default |
|---|---|---|
| `LSMCP_MANAGED_DIR` | Where Track A `.lsrules` files and backups live. | `~/Library/Application Support/little-snitch-mcp/` |
| `LSMCP_LS_BIN` | Path to `littlesnitch` CLI. | Auto-detected (see below). |
| `LSMCP_LOG_LEVEL` | `error` / `warn` / `info` / `debug`. | `info` |
| `LSMCP_DISABLE_LIVE_WRITE` | If `true`, disable all Track B tools (read-only mode). | unset |
| `LSMCP_PREFERENCE_ALLOWLIST_FILE` | Optional path to a user-supplied JSON allowlist that overrides the built-in for `write_preference`. | unset |

No config file in v1. Env vars are MCP-client-friendly (every client supports passing env to the spawned MCP).

### Locating `littlesnitch`

Auto-detect order:

1. `LSMCP_LS_BIN` if set and executable.
2. `/Applications/Little Snitch.app/Contents/Components/littlesnitch` (canonical LS install path; preserved in LS6).
3. `/Applications/Little Snitch.app/Contents/MacOS/littlesnitch` (alternate location; checked defensively).
4. `which littlesnitch` (rare; only if the user added a symlink).

If none resolve, the MCP starts in degraded mode where `doctor` returns a helpful error and all CLI-backed tools refuse with a remediation message.

### Version detection

At startup the MCP runs `littlesnitch --version` and parses the version string.

- ≥ 6.3.3 → all tools enabled.
- 6.x but < 6.3.3 → `doctor` reports an "upgrade required" status; tools that depend on commands new in 6.3.3 are disabled.
- LS5.x → `doctor` reports "unsupported version, upgrade to LS6 required"; all CLI-backed tools refuse.
- Unknown / unparsable → log a warning, treat as < 6.3.3, surface in `doctor`.

The version-detection result is exposed via `littlesnitch://doctor`.

### Logging

- Logs go to stderr (stdout is reserved for the MCP transport).
- Default level `info`: tool calls (without sensitive args), CLI invocations (with redacted preferences), backup paths.
- `debug` level: full CLI args (still redacted for known-secret keys), full responses.
- Never log: preference values for keys in `SECRET_PREFERENCE_KEYS` (below), contents of capture-traffic files, `.lsrules` file contents from third-party sources, full model dumps.

### `SECRET_PREFERENCE_KEYS` (audit-grounded)

The redaction list is enumerated explicitly so logging code references a constant rather than relying on developer judgment per call. Initial entries (LS 6.3.3):

- `dnsEncryptionConfigurations` — may contain DNS-over-HTTPS server URLs with embedded API keys / tokens.
- `dnsEncryptionEnabledConfigurations` — same.
- Any preference key whose name matches the case-insensitive regex `(password|secret|token|credential|key)` — catch-all for future LS additions.

When logging a preference value, check the key against this list first. If matched, emit `<redacted: KEY>` in place of the value.

Updates to this list happen in code (`src/safety/secret_prefs.rs` constant + regex) and require an ADR amendment.

### Update channel

Homebrew (`brew upgrade little-snitch-mcp`) is the primary update channel. `doctor` includes the installed version and a "newer available" check against the GitHub releases API (only if the user is online; offline-tolerant; disable with `LSMCP_DISABLE_VERSION_CHECK=true`).

### Uninstallation

- `brew uninstall little-snitch-mcp` removes the binary.
- The managed directory is **not** auto-removed (it contains user-authored rule files and backups). README documents the manual `rm -rf` step for users who want a clean uninstall.

### Telemetry

None. The MCP makes no network calls of its own except the optional npm version check, which can be disabled by setting `LSMCP_DISABLE_VERSION_CHECK=true`.

## Options considered

- **Ship as a Swift `.app` from day one.** More native, but the MCP SDK story for Swift is immature in 2026. Defer.
- **Run as a launch agent / persistent daemon.** Unnecessary complexity; MCP clients already manage process lifetime via stdio.
- **Config file (`~/.config/little-snitch-mcp/config.json`).** Adds another surface to keep in sync with env vars. Skip until we have ≥6 knobs (we have 5).
- **Auto-update via the MCP itself.** Out of scope; users update via `brew upgrade`.
- **npm distribution.** Rejected with the language switch — would require Node runtime. Homebrew covers the macOS power-user audience cleanly.

## Consequences

**Positive:**
- Single static binary; no Node/Python/etc. runtime dependency for the user.
- `brew install little-snitch-mcp` is one command and matches power-user expectations.
- ~5MB resident memory; small enough to ignore in Activity Monitor.
- No persistent state outside the managed dir.
- Read-only mode (`LSMCP_DISABLE_LIVE_WRITE=true`) gives nervous users a safe default they can opt into without changing tool surface.

**Negative / accepted tradeoffs:**
- Notarization required for the released binary so it runs without Gatekeeper friction. One-time setup; standard for any signed macOS tool.
- Sudo prompts (when not using TouchID per ADR-0006) surface in the terminal that launched the MCP, which may be hidden behind the MCP client. README documents this.
- No GUI for configuration. Acceptable; this is a developer/power-user tool.

## References

- ADR-0001 for runtime/SDK choice.
- LS6 CLI overview: https://help.obdev.at/littlesnitch6/cmd-overview
- MCP TypeScript SDK transport docs: https://github.com/modelcontextprotocol/typescript-sdk
