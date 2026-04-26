//! Server-side MCP prompts.
//!
//! Each prompt is a templated workflow the LLM can fetch via MCP's
//! `prompts/get` to seed its conversation. Prompts here are
//! **instructional** — they return text describing what tools to call
//! and what shape the result should have. They never call tools
//! themselves; the LLM does, after reading the prompt.
//!
//! See [ADR-0003](../../docs/adr/0003-mcp-tool-surface.md) for the
//! prompt-vs-tool separation rationale.

pub mod block_telemetry_for_app;
