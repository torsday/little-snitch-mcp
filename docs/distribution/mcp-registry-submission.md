# MCP Registry submission (draft)

This file holds the submission entry for the [official MCP Registry](https://github.com/modelcontextprotocol/registry). It's a draft so the content is reviewable here in-repo; the actual submission is a PR against `modelcontextprotocol/registry` once `v1.0.0` ships.

## When to submit

After `v1.0.0` is tagged, released, and the Homebrew formula has been bumped (i.e. the install command in this submission actually works). Submitting before the install command resolves wastes registry maintainer time and looks unprofessional.

## Submission shape

The registry's `server.json` schema (subject to change before the upstream registry stabilizes — re-check the [`README`](https://github.com/modelcontextprotocol/registry/blob/main/README.md) and [`docs/server-json/`](https://github.com/modelcontextprotocol/registry/tree/main/docs/server-json) at submission time):

```json
{
  "name": "io.github.torsday/little-snitch-mcp",
  "description": "MCP server for the Little Snitch macOS firewall — read live traffic, author .lsrules files, and safely mutate the live model with two-step confirmation.",
  "repository": {
    "url": "https://github.com/torsday/little-snitch-mcp",
    "source": "github"
  },
  "version_detail": {
    "version": "1.0.0",
    "release_date": "TBD",
    "is_latest": true
  },
  "packages": [
    {
      "registry_name": "homebrew",
      "name": "torsday/tap/little-snitch-mcp",
      "version": "1.0.0",
      "runtime_arguments": []
    },
    {
      "registry_name": "github-releases",
      "name": "torsday/little-snitch-mcp",
      "version": "1.0.0",
      "package_arguments": [
        {
          "type": "named",
          "name": "asset",
          "value": "little-snitch-mcp-v1.0.0-{arch}-apple-darwin.tar.gz"
        }
      ]
    }
  ]
}
```

## Submission PR description (draft)

> Adds `little-snitch-mcp` — a Rust MCP server that lets an LLM read and safely mutate Little Snitch firewall state on macOS. Local stdio only; no network sockets in the binary (enforced by `cargo-deny`). Every live-model mutation requires a two-step HMAC-SHA256 confirmation token and is preceded by an automatic backup. Release binaries are notarized and carry a Sigstore-signed GitHub Actions build-provenance attestation.
>
> - Repo: https://github.com/torsday/little-snitch-mcp
> - Install: `brew install torsday/tap/little-snitch-mcp`
> - Security posture: see [README "Security & trust"](https://github.com/torsday/little-snitch-mcp#security--trust)
> - Threat model: [`docs/design.md` § Threat model](https://github.com/torsday/little-snitch-mcp/blob/main/docs/design.md#threat-model)
> - Vulnerability reporting: [`SECURITY.md`](https://github.com/torsday/little-snitch-mcp/blob/main/SECURITY.md)

## Other directories

Lower-priority listings to add after the official registry lands. None of them require code changes — just web-form submissions.

| Directory | URL | Submission method | Notes |
|---|---|---|---|
| **mcp.so** | https://mcp.so | Web form / GitHub PR | High-traffic MCP catalog. |
| **pulse-mcp.com** | https://pulsemcp.com | Web form | Curated MCP directory. |
| **glama.ai/mcp** | https://glama.ai/mcp/servers | Auto-indexed from GitHub topics | Add `mcp`, `mcp-server`, `model-context-protocol` topics to the repo. |
| **smithery.ai** | https://smithery.ai | GitHub auth + claim | Local-stdio mode only — do *not* enable hosted mode (incompatible with sudo). |
| **Anthropic Claude Desktop directory** | TBD — check status at submission time | Anthropic-curated | Only submit after meaningful adoption. |

## What we explicitly skip

- **npm** — wrong audience for a macOS sudo-required system tool. Adds a packaging layer for no UX gain.
- **crates.io as the primary install path** — `cargo install` builds from source and produces an unnotarized binary. Acceptable as a tertiary fallback; not promoted.
- **Hosted MCP services** (Smithery hosted mode, mcp-server.com hosted, etc.) — structurally incompatible with a server that must call `sudo` on the user's local Mac.
- **Mac App Store** — sandbox blocks `sudo`, blocks invoking `littlesnitch`, blocks writing outside container dirs.
