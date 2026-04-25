# ADR-0006 — Sudo strategy and no-TTY handling

- **Status:** Proposed
- **Date:** 2026-04-25
- **Deciders:** Project owner
- **Depends on:** ADR-0004, ADR-0005

## Context

Discovered during empirical verification (see [feasibility-report.md](../feasibility-report.md)): all `littlesnitch` commands except `log` require sudo. macOS sudo by default uses **per-TTY timestamp tickets** (`tty_tickets` in sudoers) — meaning a `sudo -v` in the user's terminal does NOT carry over to a different process or session.

This breaks the most important MCP runtime: **GUI-spawned MCP clients (Claude Desktop, IDE plugins, web clients) launch the MCP without a controlling TTY.** Every sudo-required tool returns:

```
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
```

The MCP cannot prompt for a password through the MCP transport (stdio is owned by the protocol). It cannot pipe one in (no secure source). It cannot rely on a pre-cached sudo session (different TTY).

This is not a bug — it's an architectural constraint imposed by macOS's security model. Any solution must work *with* macOS's authentication primitives, not around them.

## Decision

Three-tier strategy, applied in order:

1. **Recommended setup: TouchID for sudo.** Document the one-time configuration so sudo can authenticate via the macOS system Touch ID dialog (which doesn't require a TTY).
2. **Fallback: read-only mode by default.** When the MCP detects it cannot escalate, it disables every sudo-required tool and operates as a `log`-and-`.lsrules`-authoring-only service. The user gets observability + Track A authoring with zero auth friction.
3. **Recovery: warm-sudo workflow.** Provide a `warm_sudo` tool whose only job is to print clear, copy-pasteable instructions for the user to authenticate from a terminal, plus a polling mechanism the MCP uses to detect when sudo becomes available again.

`doctor` reports which tier is active.

## Empirical validation (2026-04-25)

User configured `pam_tid.so` in `/etc/pam.d/sudo_local` and ran two tests:

```
# Test 1: regular sudo from a TTY (sanity check)
$ sudo -K && sudo whoami
[Touch ID prompt → user touches sensor]
root

# Test 2: sudo with no controlling TTY — exactly how Claude Desktop spawns the MCP
$ sudo -K && python3 -c 'import subprocess; subprocess.run(["sudo", "whoami"], start_new_session=True)'
[Touch ID prompt → user touches sensor]
root
```

`start_new_session=True` calls `setsid()` in the Python subprocess before exec, stripping the controlling TTY in the same way `posix_spawn` does for MCP server children. Touch ID dialog appears as a system-level UI overlay, sensor touch is sufficient to authenticate, sudo succeeds, output flows to the parent's stdout.

**This validates that with `pam_tid.so` configured, the MCP can perform every sudo-required tool from any GUI client (Claude Desktop, IDE plugins, web clients) without TTY, password caching, or askpass helpers.** The auth strategy below is no longer a proposal — it's a confirmed working path.

## Tier 1: TouchID for sudo (recommended setup)

Apple supports TouchID as a sudo authentication factor via PAM. As of macOS Sonoma (14) and later, the supported customization point is `/etc/pam.d/sudo_local` (a file Apple guarantees won't be overwritten on system updates, unlike `/etc/pam.d/sudo`).

**One-time setup, documented in README and surfaced by `doctor`:**

```
sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local
sudo sh -c 'printf "auth       sufficient     pam_tid.so\n" >> /etc/pam.d/sudo_local'
```

(Or, equivalent, via `Edit` of an existing file.)

Once this is set, `sudo` invoked from any process — including the MCP, with no TTY — triggers the macOS system Touch ID dialog. The user touches the sensor; sudo proceeds. No timestamp ticket is needed.

**Why this is the recommended default:**
- No custom binary to ship and notarize.
- No password caching or storage on our end.
- The auth UI is standard macOS — users recognize it.
- Works whether the MCP is invoked from Claude Desktop, an IDE, or a terminal.
- Falls back gracefully: if Touch ID hardware is missing or fails, sudo prompts on a TTY (which still works for terminal-launched MCPs).

`doctor` checks for the presence of `auth.*pam_tid.so` in `/etc/pam.d/sudo_local` and reports a green/yellow/red status.

## Tier 2: Read-only mode (automatic fallback)

If the MCP starts in a context where sudo cannot succeed (no TTY, no Touch ID configured), it enters **read-only mode** automatically:

- All `safe_read` tools enabled (e.g., `tail_log`, `read_lsrules_file`, `doctor`, schema resources).
- All `managed_write` tools enabled (Track A `.lsrules` authoring — these write to the managed dir, no sudo needed).
- All `sudo_read` and every `live_write` / `live_write_strong` tool disabled. They appear in the tool list with a description prefix like "(unavailable: sudo not configured)" and refuse with a structured error pointing at the `warm_sudo` tool.

This mode is also explicitly opt-in via `LSMCP_DISABLE_LIVE_WRITE=true` (already in ADR-0005). The two paths converge on the same disabled set.

**Why this is a safe fallback:**
- The user gets a working MCP immediately, with the most-used capability (observability) and the safest mutation surface (Track A).
- The user is never confused by tools that fail at runtime — disabled tools say so up front.
- The remediation path (configure TouchID) is one command.

## Tier 3: `warm_sudo` recovery tool

When a sudo-required tool is invoked in read-only mode, the MCP returns:

```
This tool requires elevated privileges and the MCP cannot authenticate. To enable
sudo for this MCP session, either:

  (a) Configure TouchID for sudo (recommended, one-time):
      sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local
      echo 'auth sufficient pam_tid.so' | sudo tee -a /etc/pam.d/sudo_local

  (b) Run this MCP from a terminal where you can authenticate sudo, then keep the
      session warm with:
      sudo -v && (while true; do sudo -n true; sleep 60; done) &

After (a), every tool will Just Work.
After (b), tools will work only as long as the keepalive runs and the MCP shares
that TTY's sudo timestamp — fragile; (a) is strongly recommended.
```

The `warm_sudo` tool also polls (every few seconds, with a max wait) to detect when sudo becomes available, then re-enables the disabled tools for the current session.

## Options considered

| Option | Verdict |
|---|---|
| Custom askpass helper that pops a Cocoa password dialog | Rejected. Reinvents PAM/TouchID with a custom UI; harder to audit; we'd have to handle the password securely. TouchID delegates to macOS. |
| `SMJobBless` privileged helper (notarized LaunchDaemon holding privileges, MCP communicates via XPC) | Rejected for v1. Heavy lift, requires notarization and a signed binary, and the security model is harder to reason about than "TouchID gates each sudo call." Worth revisiting in v2 if MCP usage warrants it. |
| Store an encrypted password in macOS Keychain and feed via `sudo -S` | Rejected. Bad security pattern. Keychain access has its own auth dance and we'd be moving the auth problem, not solving it. |
| Require the user to launch the MCP from a terminal with an active sudo session | Rejected as the *primary* mode. Documented as Tier 3 fallback only because it ties the MCP to a specific TTY and disqualifies GUI clients. |
| Disable sudo-required tools entirely (read-only product) | Rejected. We lose CRUD, which is the user's headline ask. |
| Add `tty_tickets` removal from sudoers (`Defaults !tty_tickets`) | Rejected. Mutating system sudoers is a real security change and out of scope for an MCP installer. |

## Consequences

**Positive:**
- The MCP works in every MCP client (Claude Desktop, IDEs, CLI), with appropriate UX in each.
- TouchID is a familiar, system-blessed auth UI.
- Fallback mode is genuinely useful, not a degraded experience.
- The MCP never holds, transmits, or caches the user's password.

**Negative / accepted tradeoffs:**
- Users on Macs without Touch ID hardware (older Intel Minis, some external-display-only setups) get either Tier 3 or read-only. Document this.
- Touch ID setup, while one-line, is still a setup step. Some users will not do it. Read-only mode is the answer for them.
- Each sudo call triggers a Touch ID prompt. For interactive MCP usage this is acceptable (a few prompts per session). For batch operations, batching multiple LS calls into one wrapper that single-prompts is a future optimization.

## References

- ADR-0004 (safety) — tool classification interacts with this strategy: `safe_read` tools always work; `live_write` tools depend on sudo availability.
- ADR-0005 (deployment) — `LSMCP_DISABLE_LIVE_WRITE` env var triggers the same disabled set as automatic read-only mode.
- Apple's `pam_tid.so` documentation (man pages on macOS).
- `/etc/pam.d/sudo_local.template` ships with macOS Sonoma+.
