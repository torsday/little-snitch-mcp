use anyhow::Result;
use clap::Parser;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        Annotated, CallToolResult, Content, Implementation, ListResourceTemplatesResult,
        ListResourcesResult, PaginatedRequestParams, ProtocolVersion, RawResource,
        RawResourceTemplate, ReadResourceRequestParams, ReadResourceResult, ResourceContents,
        ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use tracing_subscriber::EnvFilter;

use little_snitch_mcp::{managed_dir, resources, tools};

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
    #[tool(description = "Create a new .lsrules file in the managed directory. \
                       Provide `name` (used as the filename), optional `description`, \
                       optional `denied_remote_domains` list, and optional `rules` array. \
                       The content is validated against the lsrules schema before writing. \
                       Refuses to overwrite an existing file unless `replace: true` is passed.")]
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

    // Classification: ManagedWrite. Writes to managed dir only; no sudo; no live-model effect.
    #[tool(
        description = "Remove a rule from a managed .lsrules file by zero-based index or by a \
                       partial match tuple. Provide `file_name` plus exactly one of `index` \
                       (zero-based position in the `rules` array) or `match_tuple` (a JSON \
                       object whose key/value pairs must all match exactly one rule). Returns \
                       the removed rule, remaining rule count, and a unified diff of the change."
    )]
    async fn remove_rule_from_lsrules_file(
        &self,
        Parameters(args): Parameters<tools::RemoveRuleArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::remove_rule_from_lsrules_file::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: ManagedWrite. Writes to managed dir only; no sudo; no live-model effect.
    #[tool(
        description = "Update a rule in a managed .lsrules file by zero-based index or by a \
                       partial match tuple. Provide `file_name`, exactly one of `index` or \
                       `match_tuple` (to identify the rule), and `updates` (a JSON object \
                       whose fields are merged into the matched rule — unmentioned fields are \
                       preserved). Re-validates the file and returns the before/after rule \
                       and a unified diff."
    )]
    async fn update_rule_in_lsrules_file(
        &self,
        Parameters(args): Parameters<tools::UpdateRuleArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::update_rule_in_lsrules_file::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: ManagedWrite. Writes to managed dir only; no sudo; no live-model effect.
    #[tool(
        description = "Add a rule to a managed .lsrules file. Provide `file_name` and `rule` \
                       (a valid lsrules rule object). Deduplicates on the \
                       (process, remote, direction, ports, action) tuple — if an equivalent rule \
                       already exists, returns `already_present: true` with no change. Otherwise \
                       appends the rule, re-validates, and returns the new rule count and a \
                       unified diff."
    )]
    async fn add_rule_to_lsrules_file(
        &self,
        Parameters(args): Parameters<tools::AddRuleArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::add_rule_to_lsrules_file::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SudoRead. Calls `littlesnitch export-model`; requires sudo; no live-model mutation.
    #[tool(
        description = "Export the current Little Snitch model to a timestamped backup file in \
                       the managed backups directory. Wraps `littlesnitch export-model`. \
                       Returns the absolute path of the written backup file. \
                       Requires that the CLI is authorized and running as root (sudo). \
                       Can be called standalone or used as a pre-mutation safety step."
    )]
    async fn export_model_backup(
        &self,
        Parameters(args): Parameters<tools::ExportModelBackupArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::export_model_backup::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SudoRead. Reads preferences via CLI; requires sudo; no mutation.
    #[tool(
        description = "Read one or more Little Snitch preferences by key. Provide a list of \
                       key names (dot-separated paths into globalDefaults, e.g. \
                       `\"allowCitrixMode\"`). Returns a map of key → value; a null value \
                       indicates the key is not present. Note: the CLI returns exit 0 even \
                       for missing keys — the JSON output is inspected, not the exit code. \
                       Requires that the CLI is authorized and running as root (sudo)."
    )]
    async fn read_preference(
        &self,
        Parameters(args): Parameters<tools::ReadPreferenceArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::read_preference::run(args) {
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
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();
        let mut impl_info = Implementation::from_build_env();
        impl_info.name = env!("CARGO_PKG_NAME").into();
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        info.server_info = impl_info;
        info.instructions =
            Some("MCP server for safely managing Little Snitch rules from an LLM.".into());
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let resource = Annotated {
            raw: RawResource {
                uri: resources::lsrules_files::URI.to_string(),
                name: "lsrules-files".to_string(),
                title: Some("Managed .lsrules files".to_string()),
                description: Some(
                    "Lists all .lsrules rule-group files in the managed rules directory."
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
                size: None,
                icons: None,
                meta: None,
            },
            annotations: None,
        };
        Ok(ListResourcesResult::with_all_items(vec![resource]))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        let tmpl = Annotated {
            raw: RawResourceTemplate {
                uri_template: resources::lsrules_files::URI_TEMPLATE.to_string(),
                name: "lsrules-file".to_string(),
                title: Some("Single .lsrules file".to_string()),
                description: Some(
                    "Content and validation status of one named .lsrules rule-group file."
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
                icons: None,
            },
            annotations: None,
        };
        Ok(ListResourceTemplatesResult::with_all_items(vec![tmpl]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let managed = managed_dir::ManagedDir::bootstrap()
            .map_err(|e| McpError::internal_error(format!("managed directory error: {e}"), None))?;

        // Listing resource
        if request.uri == resources::lsrules_files::URI {
            let entries = resources::lsrules_files::list(&managed.rules)
                .map_err(|e| McpError::internal_error(e, None))?;
            let json = serde_json::to_string_pretty(&entries)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                json,
                resources::lsrules_files::URI,
            )]));
        }

        // Per-file resource
        if let Some(name) = resources::lsrules_files::match_file_uri(&request.uri) {
            match resources::lsrules_files::read_file(&managed.rules, name) {
                Ok(contents) => {
                    let json = serde_json::to_string_pretty(&contents)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                    return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                        json,
                        request.uri,
                    )]));
                }
                Err(msg) if msg.contains("not found") => {
                    return Err(McpError::invalid_params(msg, None));
                }
                Err(msg) => {
                    return Err(McpError::internal_error(msg, None));
                }
            }
        }

        Err(McpError::invalid_params(
            format!("unknown resource URI: {}", request.uri),
            None,
        ))
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
