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

pub mod safety;

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

    let service = EchoServer::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
