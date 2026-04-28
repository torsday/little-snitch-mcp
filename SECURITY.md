# Security Policy

`little-snitch-mcp` is an MCP server that, by design, holds the keys to mutate a macOS firewall as root. Security-relevant defects are taken seriously.

## Supported versions

Until v1.0.0 ships, only the latest commit on `main` is supported. After v1.0.0, the latest minor release on the current major line will receive security fixes.

| Version | Supported |
|---------|-----------|
| `main`  | ✅ |
| `< 1.0` | ⚠️ pre-release; upgrade to latest `main` |

## Reporting a vulnerability

**Please do not file a public GitHub issue for security defects.**

Use **GitHub Private Vulnerability Reporting**: open the [Security tab](https://github.com/torsday/little-snitch-mcp/security) → "Report a vulnerability". This routes the report through GitHub's encrypted advisory workflow, with private back-and-forth between you and the maintainer until a fix and coordinated-disclosure timeline are agreed.

Please include:

- A description of the issue and its impact.
- A minimal reproduction (commit SHA, configuration, MCP transcript if relevant).
- Whether the issue is already public, and any disclosure constraints on your end.

## What to expect

| Step | Target |
|------|--------|
| Acknowledgement | Within 72 hours |
| Initial assessment + severity | Within 7 days |
| Fix + advisory drafted | Within 30 days for High/Critical; best-effort otherwise |
| Coordinated disclosure | After fix is released; credit given unless you ask otherwise |

If you do not receive an acknowledgement within 72 hours, please re-send — the inbox occasionally drops mail.

## Scope

### In scope

- Confirmation-token forgery, replay, or TTL-bypass against the LiveWrite gate.
- Privilege escalation beyond what `sudo littlesnitch` already grants on the host.
- Path traversal out of the managed rules / backups directory.
- Any code path in this repository that opens a network socket, writes to stdout outside the MCP framing path, or invokes a binary other than `littlesnitch` / `sudo` / `security` / standard POSIX utilities.
- Logging or error paths that leak secrets, full preference values, or token bytes.
- Supply-chain regressions: a dependency or feature flag that re-introduces network capability or a TLS / HTTP client.
- Tampering with the release artifact such that the GitHub Actions build provenance attestation, codesign signature, or notarization ticket fail to verify.

### Out of scope

The threat model deliberately excludes:

- Vulnerabilities in **Little Snitch** itself or the `littlesnitch` CLI (report to [Objective Development](https://obdev.at/support/contact)).
- Vulnerabilities in macOS, the sandbox, codesign, notarization, or Apple's developer infrastructure.
- Transitive Cargo CVEs in third-party crates — these are tracked via `cargo audit` in CI and patched on the normal dependency cadence; only report if the CVE has a working exploit path through `little-snitch-mcp` specifically.
- Attackers with **root-equivalent local access** — anyone who can replace the binary, the `littlesnitch` CLI, your shell, or your `sudo` configuration is already past every defense this server can offer.
- Social-engineering of the human operator (e.g. an LLM convincing the user to approve a malicious diff). The two-step confirmation protocol exists to make this hard, not impossible; the human is the final authority.

## Hardening commitments

These properties are pinned by code and CI; a regression that breaks any of them is a security defect:

- Zero outbound network sockets in the binary (enforced by `cargo-deny [bans]` against HTTP-client crates and the absence of `tokio`'s `net` feature).
- MCP transport is stdio-only.
- Live-model mutations require `sudo` **and** a fresh HMAC-SHA256 token bound to a model-state hash.
- Every live mutation is preceded by an automatic backup written to the managed `backups/` directory.
- Release binaries carry a Sigstore-signed GitHub Actions build-provenance attestation, an Apple Developer ID code signature, and Apple notarization (verified by Gatekeeper via online lookup; standalone Mach-O binaries can't embed a stapled ticket).

See the [README "Security & trust" section](./README.md#security--trust) and [`docs/design.md` § Threat model](./docs/design.md#threat-model) for the full posture.
