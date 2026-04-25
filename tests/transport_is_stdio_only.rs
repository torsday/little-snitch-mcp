//! Pins the README's "Stdio-only MCP transport" guarantee at build time.
//!
//! The MCP server's transport is the most security-relevant feature flag in
//! the binary: enabling `transport-sse`, `transport-streamable-http`, or any
//! future network-capable rmcp transport would expose the entire tool surface
//! to remote callers. The "Hard guarantees" bullet in README.md and the
//! threat model in docs/design.md both depend on it remaining stdio-only.
//!
//! This test parses `Cargo.toml` and asserts that the `rmcp` dependency:
//!   1. Lists `transport-io` as the only `transport-*` feature.
//!   2. Does not list any of the network-capable transports.
//!
//! The check is deliberately string-based against `Cargo.toml` rather than
//! reflective against `rmcp` itself: we want a contributor who edits
//! `features = [...]` to fail the build at PR time, not at runtime.

use std::fs;

const FORBIDDEN_TRANSPORTS: &[&str] = &[
    "transport-sse",
    "transport-sse-server",
    "transport-streamable-http",
    "transport-streamable-http-server",
    "transport-worker",
    "transport-async-rw",
    "transport-child-process",
];

#[test]
fn rmcp_uses_only_stdio_transport() {
    let manifest = fs::read_to_string("Cargo.toml").expect("read Cargo.toml");

    // Find the rmcp dependency line. Tolerate either:
    //   rmcp = { version = "...", features = [...] }
    // or a multi-line block; we slice from "rmcp" to the next blank line.
    let rmcp_idx = manifest
        .find("rmcp")
        .expect("Cargo.toml does not mention rmcp — has the dependency been removed?");
    let rest = &manifest[rmcp_idx..];
    let block_end = rest.find("\n\n").unwrap_or(rest.len());
    let rmcp_block = &rest[..block_end];

    assert!(
        rmcp_block.contains("\"transport-io\""),
        "rmcp dependency must enable `transport-io` (stdio MCP transport).\n\
         Found block:\n{rmcp_block}"
    );

    for forbidden in FORBIDDEN_TRANSPORTS {
        let needle = format!("\"{forbidden}\"");
        assert!(
            !rmcp_block.contains(&needle),
            "rmcp must not enable `{forbidden}`. The README's \"no network sockets\" \
             and \"stdio-only MCP transport\" guarantees depend on this. If a \
             non-stdio transport is genuinely required, update README.md, \
             docs/design.md threat model, deny.toml, and SECURITY.md before \
             relaxing this test.\n\
             Found block:\n{rmcp_block}"
        );
    }
}

#[test]
fn tokio_does_not_enable_net_feature() {
    let manifest = fs::read_to_string("Cargo.toml").expect("read Cargo.toml");

    let tokio_idx = manifest
        .find("\ntokio")
        .or_else(|| manifest.find("tokio ="))
        .expect("Cargo.toml does not mention tokio");
    let rest = &manifest[tokio_idx..];
    let block_end = rest.find("\n\n").unwrap_or(rest.len());
    let tokio_block = &rest[..block_end];

    // We accept these; everything else under tokio's feature flag set is
    // either irrelevant or actively dangerous for the no-network invariant.
    // `net` is the one we specifically care about — it's what would re-enable
    // TCP/UDP socket APIs.
    assert!(
        !tokio_block.contains("\"net\""),
        "tokio must not enable the `net` feature. The README's \"no network \
         sockets\" guarantee depends on the absence of TCP/UDP socket APIs.\n\
         Found block:\n{tokio_block}"
    );
}
