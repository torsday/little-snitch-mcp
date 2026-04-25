# Spike — rmcp + `#[tool]` macro ergonomics (2026-04)

Tracks [#1](https://github.com/torsday/little-snitch-mcp/issues/1). Outcome: **proceed with rmcp 1.5.x as committed in [ADR-0001](../adr/0001-language-runtime-and-target-version.md).**

## What was built

Minimal stdio MCP server (`src/main.rs`, ~70 lines) exposing one `echo(message: String) -> String` tool. Bootstrapped against published `rmcp = "1.5"` from crates.io.

## Verified acceptance criteria

| AC | Result |
|----|--------|
| Boots as MCP stdio server | ✓ — `initialize` returns `protocolVersion: 2025-03-26` and advertises `tools` capability |
| Trivial tool callable | ✓ — `tools/list` lists `echo` with the schemars-derived input schema; `tools/call` echoes the message back |
| Logs to stderr only; stdout pristine for JSON-RPC | ✓ — `tracing_subscriber::fmt().with_writer(std::io::stderr).with_ansi(false)`; smoke harness pipes stderr to a separate file and stdout parses cleanly as one JSON object per line |
| Ergonomics note | This document |

## Ergonomics findings

1. **Macro shape is exactly what we want for ~30 tools.** The `#[tool_router]` + `#[tool(description = "…")]` + `#[tool_handler]` triplet collapses the boilerplate to the function body itself; tool params arrive as `Parameters<T>` where `T: Deserialize + JsonSchema`. Schema is auto-derived. This is the API surface ADR-0001 was hoping for.

2. **`ServerInfo` is `#[non_exhaustive]`.** Cannot be built with a struct literal (even with `..Default::default()`). Use `let mut info = ServerInfo::default(); info.foo = ...;` instead. Trivial but worth a one-line helper if it shows up in more than one place.

3. **`Implementation::from_build_env()` resolves to `rmcp` / `1.5.0`, not the consuming crate.** The macro/function appears to bake in rmcp's own `CARGO_PKG_*` at compile time of the rmcp crate. Override locally with `env!("CARGO_PKG_NAME")` / `env!("CARGO_PKG_VERSION")`. Consider a thin wrapper (e.g. `our_implementation()` in a util module) once we have a real server crate so every entrypoint reports correctly.

4. **`tool_router` field triggers `dead_code` under `-D warnings`.** Field is read by macro-generated code that the lint pass doesn't see. `#[allow(dead_code)]` on the field is the cleanest fix; documented inline.

5. **Edition 2024 + Rust 1.95 builds clean.** No nightly features needed.

6. **No surprises in JSON-RPC framing.** Newline-delimited JSON, one object per line. The smoke test piped `initialize` → `notifications/initialized` → `tools/call` and got three clean responses on stdout.

## What this unblocks

Every M0 issue can now land into a real Cargo project: model serde (#2, #24), tool classification (#42), confirmation-token protocol (#3, #43), rule constructor (#58), and the rest of the safety-chain work all share this skeleton.

## Out of scope (deliberately)

No real tool surface, no model serde, no safety chain, no CLI invocation, no integration tests. Spike was strictly the "does the framework work the way we need it to" question.
