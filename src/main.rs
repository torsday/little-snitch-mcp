use anyhow::Result;
use clap::Parser;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use tracing_subscriber::EnvFilter;

pub mod cli;
pub mod managed_dir;
pub mod safety;
pub mod tools;

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about = env!("CARGO_PKG_DESCRIPTION"))]
struct Cli {}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EchoArgs {
    pub message: String,
}

#[derive(Clone)]
pub struct EchoServer {
    #[allow(dead_code)] // read by the #[tool_handler] macro expansion
    tool_router: ToolRouter<EchoServer>,
}

impl Default for EchoServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl EchoServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    // Classification: SafeRead. Registered in `safety::registry::TOOLS`.
    // Every new `#[tool]` method MUST have a matching entry there — the
    // unit tests in `safety::registry` enforce uniqueness and shape.
    #[tool(description = "Echo a message back to the caller. Smoke-test tool for the M0 spike.")]
    async fn echo(
        &self,
        Parameters(args): Parameters<EchoArgs>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(args.message)]))
    }

    // Classification: SafeRead. No filesystem writes; reads are path-scoped.
    #[tool(
        description = "Validate a .lsrules JSON file (or inline JSON) against the Little Snitch \
                       rule-group schema. Returns `valid: true` with an empty `errors` array on \
                       success, or `valid: false` with field-level errors on failure. Provide \
                       exactly one of `path` (absolute path to a .lsrules file) or `inline_json` \
                       (in-memory JSON object)."
    )]
    async fn validate_lsrules(
        &self,
        Parameters(args): Parameters<tools::ValidateLsrulesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::validate_lsrules::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: ManagedWrite. Writes to managed dir only; no sudo; no live-model effect.
    #[tool(
        description = "Create a new .lsrules file in the managed directory. \
                       Provide `name` (used as the filename), optional `description`, \
                       optional `denied_remote_domains` list, and optional `rules` array. \
                       The content is validated against the lsrules schema before writing. \
                       Refuses to overwrite an existing file unless `replace: true` is passed."
    )]
    async fn create_lsrules_file(
        &self,
        Parameters(args): Parameters<tools::CreateLsrulesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::create_lsrules_file::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }
}

#[tool_handler]
impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_03_26;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::from_build_env();
        impl_info.name = env!("CARGO_PKG_NAME").into();
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        info.server_info = impl_info;
        info.instructions = Some(
            "little-snitch-mcp spike server. Exposes one `echo` tool to validate \
             rmcp + #[tool] macro ergonomics over stdio."
                .into(),
        );
        info
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("little-snitch-mcp spike: starting stdio server");

    let managed = managed_dir::ManagedDir::bootstrap()?;
    tracing::info!(root = %managed.root.display(), "managed directory ready");

    let service = EchoServer::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
