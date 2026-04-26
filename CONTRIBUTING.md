# Contributing to little-snitch-mcp

## Prerequisites

- **Rust 1.85+** (edition 2024). Install via [rustup](https://rustup.rs/). `rustup update stable` to get the latest.
- **macOS** — the server uses Little Snitch's macOS-only CLI.
- **Little Snitch 6.3.3+** for live integration testing. Not required for unit tests or most of the test suite (see Mock binary below).

Check your version:

```bash
rustc --version       # must be 1.85.0+
cargo --version
```

## Building

```bash
cargo build           # debug
cargo build --release # release
```

## Running tests

```bash
cargo test            # all unit + integration tests
cargo test --test e2e_smoke        # E2E smoke tests
cargo test --test integration_track_b
```

Most tests use pure inner functions or mock binaries and do not require a live Little Snitch install.

## Mock binary pattern

The `LSMCP_LS_BIN` env var overrides the path to the `littlesnitch` CLI binary. This is the standard way to test without a live LS install:

```bash
# Point at a mock script that returns canned JSON
LSMCP_LS_BIN=/path/to/mock-littlesnitch cargo test
```

The resolver tries `LSMCP_LS_BIN` before falling back to the system path (see `src/cli/binary.rs`). A mock binary is any executable that accepts the same subcommand + flag arguments as the real `littlesnitch` and writes the expected JSON to stdout.

## Managed directory override

The `LSMCP_MANAGED_DIR` env var overrides the managed rules directory (normally `~/Library/Application Support/little-snitch-mcp/rules/`). Use a temp directory in tests to avoid touching your real rules directory:

```bash
LSMCP_MANAGED_DIR=/tmp/test-rules cargo test
```

**Important — `ENV_LOCK`:** Tests that set `LSMCP_MANAGED_DIR` must acquire the `ENV_LOCK` mutex in `src/managed_dir.rs` to prevent concurrent env-var mutations from racing across threads. The `unsafe { std::env::set_var(...) }` call is inherently racy without this serialization. See `managed_dir.rs` for the usage pattern.

## CI

CI runs on macOS-15-arm64 using a recent stable Rust (1.95+, which may be newer than your local toolchain). To catch issues before pushing:

```bash
cargo fmt --check
RUSTFLAGS="-D warnings" cargo clippy
cargo test
cargo audit
```

`cargo clippy --fix --allow-dirty` can auto-fix most lint warnings, but verify it did not remove test-only imports — those are silently removed because clippy doesn't see the `#[cfg(test)]` usage path.

## Branch workflow

This repo uses **git worktrees** for branch isolation. Each feature branch lives in a sibling directory so the main checkout stays on `main`:

```bash
BRANCH=feat/my-feature
git worktree add ../worktrees/$BRANCH -b $BRANCH
cd ../worktrees/$BRANCH
# ... work here ...
git push -u origin $BRANCH
# When done:
git worktree remove ../worktrees/$BRANCH
```

PRs are merged with squash. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) — `type(scope): subject` in lowercase, imperative mood, no trailing period.

## Architecture overview

Before adding or modifying a tool, read:

1. **Safety classification** — every tool must be classified before it is registered. The five tiers (in ascending danger) are `SafeRead`, `SudoRead`, `ManagedWrite`, `LiveWrite`, `LiveWriteStrong`. See [`src/safety/classification.rs`](src/safety/classification.rs) and [`src/safety/registry.rs`](src/safety/registry.rs). Getting the classification wrong is a security issue.

2. **Confirmation-token protocol** — any `LiveWrite`/`LiveWriteStrong` tool that mutates the live model must follow the two-step prepare/apply pattern: `prepare_*` issues an HMAC-signed token; the apply step verifies it and re-checks the diff hash. See [`src/safety/token.rs`](src/safety/token.rs).

3. **`#[tool]` attribute required** — `#[tool_router]` only registers a method as an MCP tool if it has a `#[tool(description = "...")]` attribute. A `///` doc comment is not sufficient. Missing this makes the tool invisible to MCP clients without any compile error.

For broader context, read the ADRs and design docs listed in [README.md](README.md#design-and-background).

## Test structure

| File | What it covers |
|---|---|
| `tests/e2e_smoke.rs` | Happy-path E2E for the top ten use cases using pure inner functions + temp dirs |
| `tests/integration_track_b.rs` | Live-model round-trip (Track B) — prepare → apply → verify |
| `tests/lsrules_crud_cycle.rs` | Managed `.lsrules` file CRUD cycle (Track A) |
| `tests/no_unsafe_restore_model.rs` | Invariant: `restore_model` is guarded against overwriting the live model without a backup |
| `src/**/*.rs` (inline `#[cfg(test)]`) | Unit tests co-located with the module they test |
