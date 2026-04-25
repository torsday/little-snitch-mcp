# ADR-0001 — Language, runtime, MCP SDK, and target Little Snitch version

- **Status:** Proposed
- **Date:** 2026-04-25
- **Deciders:** Project owner
- **Supersedes:** —

## Context

The MCP server must run on a user's macOS machine, expose tools to an MCP-speaking client (Claude Desktop, IDE plugins, etc.) over stdio, and shell out to the `littlesnitch` CLI. Three axes need decisions before any code is written:

1. Which **target Little Snitch version** are we coding against? LS6 is current (point release 6.3.3 as of 2026-04). LS5 is legacy. The user has chosen "use the most recent software."
2. Which **MCP SDK** — TypeScript (Node), Python (FastMCP), or something else? Both are first-party; the question is fit and shippability.
3. Which **runtime** — Node.js, Bun, Deno, Python, native Swift?

These choices are upstream of the entire codebase and cheap to revisit only if made before implementation starts.

## Decision

- **Target Little Snitch version: LS6, floor 6.3.3.** No LS5 fallback. The authoritative CLI reference is https://help.obdev.at/littlesnitch6/cmd-overview.
- **Language + SDK: Rust + `rmcp`** (the official Rust MCP SDK at github.com/modelcontextprotocol/rust-sdk, with `#[tool]` macros and tokio-based async).
- **Distribution:** single static binary via Homebrew tap (`brew install little-snitch-mcp`) plus tagged GitHub release binaries.

## Why Rust over TypeScript/Node (the original recommendation, reversed)

The original ADR chose TS/Node by reflex — most mature MCP SDK, easiest `npx` trial. Reconsidered after the empirical work in [feasibility-report.md](../feasibility-report.md) and [value-prop.md](../value-prop.md) sharpened what this project actually is:

- **macOS-only system tool.** Not cross-platform. Not a web service. Distribution should match the audience's expectations — power users on Macs all have Homebrew; most do not have Node.
- **Safety-critical mutation logic.** Track B-surgery patches LS's full data model. A malformed `restore-model` payload corrupts user rules. Rust's type system (especially `serde` + tagged enums) gives compile-time guarantees that the rule JSON is well-formed before it touches the CLI — exactly the property we want for the discriminated unions in the rule schema (`remote` is one-of-N; `process` is one-of-N; `action` is one-of-N).
- **Long-lived stdio process.** Startup time and memory matter modestly; a static Rust binary uses ~5MB RAM resting vs. 80MB+ for a Node process. This shows up in the user's Activity Monitor.
- **Distribution velocity.** `brew install` is one command, no runtime dependency. `npx little-snitch-mcp` would force every user to install Node first.
- **The Rust MCP SDK is production-ready in 2026.** `rmcp` has 4.7M crates.io downloads, supports stdio transport, has macros that eliminate the boilerplate that made Rust-for-MCP awkward in 2024.

## Options considered

### Target version
- **LS5 only.** Rejected: legacy.
- **LS6 only, floor 6.3.3 (chosen).** Most recent surface, includes `update-rule-groups`, uses `debug-categories`. Cleaner code: no version-shim layer. `doctor` returns a clear "LS 6.3.3 or later required" error if the installed version is lower.
- **LS5 + LS6 with detection.** Rejected per user direction to target the most recent software.

### Language + SDK

| Language | SDK | Verdict |
|---|---|---|
| **Rust + `rmcp` (chosen)** | Official, production-ready (4.7M downloads), `#[tool]` macros, tokio async | Best fit. Single-binary distribution, strict types for the rule JSON, native macOS feel. |
| TypeScript + `@modelcontextprotocol/sdk` | Official, most mature | Strong second. Easier dev iteration, but Node runtime requirement is a meaningful tax for a power-user macOS tool. |
| Python + FastMCP | Official, decorator ergonomics | Distribution to non-Python users requires `uv`/pipx/pyz; lacks Rust's type guarantees. |
| Swift | Apple-native; could use system frameworks directly | MCP SDK story in Swift is immature in 2026. Worth revisiting in v2 if a Swift SDK matures. |
| Go | Single binary; community MCP SDKs | Fine option, but Rust's enums match the discriminated unions in the rule schema better. |

### Distribution
- **Homebrew tap `torsday/little-snitch-mcp` + GitHub release binaries (chosen).** `brew install little-snitch-mcp` is one command. Notarization needed for the binary to run without Gatekeeper friction.
- **Cargo `cargo install little-snitch-mcp`.** Available too, but only useful for Rust developers; not the primary path.
- **`.pkg` installer.** Defer to v2; Homebrew covers the audience for v1.

## Consequences

**Positive:**
- Single-binary distribution. `brew install little-snitch-mcp` and the user is done.
- Strict typing for the LS model JSON via `serde` — discriminated unions for `remote`/`process`/`action` catch malformed payloads at compile time, before any `restore-model` call.
- ~5MB resident memory vs. ~80MB for a Node process. Fits the "background system tool" expectation.
- Faster cold start; the MCP feels snappy when the client spawns it.
- No runtime dependency for the user (no Node, no Python).

**Negative / accepted tradeoffs:**
- Slower dev iteration than TS — accepted in exchange for the safety and distribution wins.
- Smaller pool of MCP-in-Rust examples (vs. the dozens of TS reference servers). `rmcp`'s docs are sufficient but less battle-tested.
- Notarization needed for the released binary. Real but one-time setup.
- Contributors comfortable in Rust are a smaller group than TS contributors. Document the project's contribution path clearly.
- LS5 users are excluded. They can upgrade.

**Follow-ups:**
- Pin the LS6 CLI surface in a `cli/contract.rs` typed module so changes are explicit.
- Add a `doctor` tool that checks LS version (≥ 6.3.3), "Allow access via Terminal," macOS version, the `littlesnitch` binary path, TouchID-for-sudo configuration. Reports actionable errors (referenced from ADR-0004 and ADR-0006).
- Set up a Homebrew tap (`torsday/little-snitch-mcp`) that points at signed/notarized GitHub release binaries.
- Lock in the model schema version (`bundleVersion`) the binary was built against; refuse `restore-model` on mismatch.

## References

- Little Snitch 6 CLI overview: https://help.obdev.at/littlesnitch6/cmd-overview
- Little Snitch 5 CLI reference (per-command detail; flag/option set is unchanged for the commands shared with LS6): https://help.obdev.at/littlesnitch5/adv-commandline
- LS6 `update-rule-groups`: https://help.obdev.at/littlesnitch6/cmd-update-rule-groups
- MCP Rust SDK (`rmcp`): https://github.com/modelcontextprotocol/rust-sdk and https://docs.rs/rmcp
- MCP TypeScript SDK (alternative considered): https://github.com/modelcontextprotocol/typescript-sdk
- MCP Python SDK (alternative considered): https://github.com/modelcontextprotocol/python-sdk
