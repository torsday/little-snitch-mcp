use anyhow::Result;
use clap::Parser;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    handler::server::{
        router::{prompt::PromptRouter, tool::ToolRouter},
        wrapper::Parameters,
    },
    model::{
        Annotated, CallToolResult, Content, GetPromptRequestParams, GetPromptResult,
        Implementation, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
        PaginatedRequestParams, PromptMessage, ProtocolVersion, RawResource, RawResourceTemplate,
        ReadResourceRequestParams, ReadResourceResult, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    prompt, prompt_handler, prompt_router, schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::stdio,
};
use tracing_subscriber::EnvFilter;

use little_snitch_mcp::{cli, managed_dir, prompts, resources, safety, tools};
use std::sync::Arc;

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
    #[allow(dead_code)] // read by the #[prompt_handler] macro expansion
    prompt_router: PromptRouter<EchoServer>,
    session: Arc<safety::Session>,
}

impl Default for EchoServer {
    fn default() -> Self {
        Self::new(Arc::new(
            safety::Session::new().expect("OS RNG unavailable"),
        ))
    }
}

#[prompt_router]
impl EchoServer {
    /// Drafts a `.lsrules` blocking the named application's telemetry
    /// hosts. The LLM, having read this prompt, calls
    /// `create_lsrules_file` and instructs the operator to review
    /// before applying via `apply_lsrules_file_to_live_model`. No
    /// live mutation occurs in this flow. See ADR-0004 §S5.
    #[prompt(name = "block_telemetry_for_app")]
    fn block_telemetry_for_app(
        &self,
        Parameters(args): Parameters<prompts::block_telemetry_for_app::Args>,
    ) -> Vec<PromptMessage> {
        prompts::block_telemetry_for_app::build_messages(&args)
    }
}

#[tool_router]
impl EchoServer {
    pub fn new(session: Arc<safety::Session>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
            session,
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

    // Classification: SudoRead. Reads all preferences via CLI; requires sudo; no mutation.
    #[tool(
        description = "List all Little Snitch preferences as a key→value map. \
                       Optional `scope` selects which store to query: \
                       `\"global\"` (system-wide defaults, `-g`), \
                       `\"user\"` (per-user overrides, `-u`), or \
                       `\"all\"` (both stores merged, the default). \
                       Secret keys (dnsEncryption*, any key matching \
                       password|secret|token|credential|key) are redacted to \
                       `\"<redacted: KEY>\"`. \
                       Requires the CLI to be authorized and running as root (sudo)."
    )]
    async fn list_preferences(
        &self,
        Parameters(args): Parameters<tools::ListPreferencesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::list_preferences::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. No sudo, no mutation; safe to call repeatedly.
    #[tool(
        description = "Run environment diagnostics for the Little Snitch MCP server. \
                       Returns a structured report with five checks: \
                       (1) littlesnitch binary found and version ≥ 6.3.3, \
                       (2) CLI authorized ('Allow access via Terminal' enabled), \
                       (3) TouchID for sudo configured (needed for GUI-client sudo), \
                       (4) managed directory accessible and writable, \
                       (5) restore-model supports --preserve-terminal-access (-t). \
                       Each check has status green|yellow|red plus an optional remediation hint. \
                       Safe to call at any time — no mutations."
    )]
    async fn doctor(
        &self,
        Parameters(args): Parameters<tools::DoctorArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::doctor::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Wraps `littlesnitch log -j -l <duration>`; no sudo required.
    #[tool(
        description = "Stream Little Snitch connection log events as JSON for a bounded duration. \
                       Wraps `littlesnitch log -j -l <duration>`. No sudo or 'Allow access via \
                       Terminal' required (empirically verified). \
                       Provide `duration_secs` (1–3600) and an optional `predicate` \
                       (NSPredicate string, e.g. `\"processName == 'curl'\"`). \
                       Returns a list of parsed JSON log events plus the total count."
    )]
    async fn tail_log(
        &self,
        Parameters(args): Parameters<tools::TailLogArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::tail_log::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Surfaces setup instructions + polls for sudo readiness.
    #[tool(
        description = "Surface TouchID-for-sudo setup instructions and poll until sudo becomes \
                       available for this MCP session. Call this when live-write tools report \
                       that sudo is unavailable. Returns: current TouchID status, copy-pasteable \
                       setup commands (Tier 1: one-time TouchID config; Tier 3: terminal keepalive), \
                       and whether sudo is available now. If sudo is not immediately available, \
                       polls `sudo -n true` every 5 s for up to 60 s and returns success when \
                       it detects sudo has been authenticated. On success, re-enables live-write \
                       tools for the current session."
    )]
    async fn warm_sudo(
        &self,
        Parameters(args): Parameters<tools::WarmSudoArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::warm_sudo::run(args).await {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SudoRead. Reads license info via CLI; requires sudo; no mutation.
    #[tool(description = "Query Little Snitch license and feature-gate status. \
                       Wraps `littlesnitch restrictions` (requires sudo). \
                       Returns `{ licensed, expires_at, features, raw }` where \
                       `licensed` is true when the copy is fully registered, \
                       `expires_at` is an ISO 8601 date string or null for perpetual licenses, \
                       `features` is `\"full\"` for a complete license or `\"limited\"` for \
                       demo/trial mode, and `raw` is the verbatim CLI output for debugging \
                       unexpected formats.")]
    async fn show_restrictions(
        &self,
        Parameters(args): Parameters<tools::ShowRestrictionsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::show_restrictions::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Issues a confirmation token; no mutation.
    #[tool(description = "Prepare a preference write for user confirmation. \
                       Validates `key` against the write allowlist (ADR-0004 §4) and returns \
                       a short-lived confirmation token and a human-readable diff summary. \
                       Present the summary to the user, then pass the token to `write_preference`. \
                       Hard-deny keys (kill-switch flags) are unconditionally refused.")]
    async fn prepare_write_preference(
        &self,
        Parameters(args): Parameters<tools::PrepareWritePreferenceArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::write_preference::prepare_write(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: LiveWrite. Requires root + valid token; mutates globalDefaults.
    #[tool(
        description = "Write an allowlisted preference key in Little Snitch's globalDefaults. \
                       Requires a confirmation token from `prepare_write_preference` \
                       (the user must have approved the proposed change). \
                       Wraps `littlesnitch write-preference <key> <value>`. \
                       Requires the MCP server to be running as root."
    )]
    async fn write_preference(
        &self,
        Parameters(args): Parameters<tools::WritePreferenceArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::write_preference::write(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Issues a confirmation token; no mutation.
    #[tool(description = "Prepare a preference removal for user confirmation. \
                       Validates `key` against the write allowlist (ADR-0004 §4) and returns \
                       a short-lived confirmation token and a diff summary. \
                       Present the summary to the user, then pass the token to `remove_preference`. \
                       Hard-deny keys are unconditionally refused.")]
    async fn prepare_remove_preference(
        &self,
        Parameters(args): Parameters<tools::PrepareRemovePreferenceArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::write_preference::prepare_remove(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: LiveWrite. Requires root + valid token; removes from globalDefaults.
    #[tool(
        description = "Remove an allowlisted preference key from Little Snitch's globalDefaults, \
                       restoring the built-in default. \
                       Requires a confirmation token from `prepare_remove_preference`. \
                       Wraps `littlesnitch write-preference -r <key>`. \
                       Requires the MCP server to be running as root."
    )]
    async fn remove_preference(
        &self,
        Parameters(args): Parameters<tools::RemovePreferenceArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::write_preference::remove(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SudoRead. Reads historical traffic stats; requires sudo; no mutation.
    #[tool(
        description = "Fetch historical traffic statistics from Little Snitch. \
                       Wraps `littlesnitch log-traffic [-b <begin>] [-e <end>]` (requires sudo). \
                       Returns a typed JSON array of connection records with fields: \
                       date (ISO-8601), direction (in/out), uid, ip_address, remote_hostname, \
                       protocol (tcp/udp/icmp/numeric), port, connect_count, deny_count, \
                       byte_count_in, byte_count_out, connecting_executable, parent_app_executable. \
                       Remote hostnames and process paths are wrapped in an `untrusted_data` \
                       envelope (may contain adversarial content). \
                       Optional filters: `process_name` (substring of connecting_executable), \
                       `remote_host` (substring of ip_address or remote_hostname), \
                       `direction` (\"in\" or \"out\"). \
                       Results capped at 10 000 rows after filtering."
    )]
    async fn tail_traffic(
        &self,
        Parameters(args): Parameters<tools::TailTrafficArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::tail_traffic::run(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: ManagedWrite. Edits metadata fields in a managed .lsrules file.
    #[tool(
        description = "Update the `name` and/or `description` metadata fields in a managed \
                       .lsrules file without touching the `rules` array. \
                       At least one of `name` or `description` must be provided. \
                       Pass an empty string for `description` to remove the field. \
                       Returns the updated values and a unified diff."
    )]
    async fn set_lsrules_metadata(
        &self,
        Parameters(args): Parameters<tools::SetMetadataArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::lsrules_metadata::set_metadata(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Computes a diff between two managed files; no mutation.
    #[tool(
        description = "Compute a unified diff between two managed .lsrules files. \
                       Returns the diff as a string and an `identical` boolean. \
                       Both files must exist in the managed rules directory. \
                       Safe to call at any time — no mutations."
    )]
    async fn diff_lsrules_files(
        &self,
        Parameters(args): Parameters<tools::DiffLsrulesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::lsrules_metadata::diff_files(args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SudoRead. Runs `littlesnitch capture-traffic` and writes output to a
    // time-stamped file in the managed captures/ directory.
    #[tool(
        description = "Capture network traffic for a specific process using Little Snitch. \
                       Runs `littlesnitch capture-traffic` and writes the output (hex or pcap) \
                       to the managed captures/ directory. \
                       Returns the path, format, file size, elapsed time, and whether the \
                       size cap was reached. Requires sudo access (SudoRead)."
    )]
    async fn capture_process_traffic(
        &self,
        Parameters(args): Parameters<tools::CaptureTrafficArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::capture_process_traffic::run(args).await {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Issues a confirmation token for activating a profile.
    #[tool(
        description = "Prepare a confirmation token for activating a named Little Snitch profile. \
                       Call this first, present the summary to the user, then pass the token to \
                       `activate_profile` after approval."
    )]
    async fn prepare_activate_profile(
        &self,
        Parameters(args): Parameters<tools::PrepareActivateProfileArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_profiles::prepare_activate(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: LiveWrite. Activates a named Little Snitch profile after token verification.
    #[tool(
        description = "Activate a named Little Snitch profile. \
                       Validates the profile exists, takes a pre-mutation backup, then runs \
                       `littlesnitch profile -a <name>`. Requires a token from \
                       `prepare_activate_profile`."
    )]
    async fn activate_profile(
        &self,
        Parameters(args): Parameters<tools::ActivateProfileArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_profiles::activate(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Issues a confirmation token for deactivating all profiles.
    #[tool(
        description = "Prepare a confirmation token for deactivating all Little Snitch profiles. \
                       Call this first, present the summary to the user, then pass the token to \
                       `deactivate_all_profiles` after approval."
    )]
    async fn prepare_deactivate_all_profiles(
        &self,
        Parameters(args): Parameters<tools::PrepareDeactivateAllProfilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_profiles::prepare_deactivate(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: LiveWrite. Deactivates all Little Snitch profiles after token verification.
    #[tool(
        description = "Deactivate all Little Snitch profiles (`profile -d`). \
                       Takes a pre-mutation backup first. Requires a token from \
                       `prepare_deactivate_all_profiles`."
    )]
    async fn deactivate_all_profiles(
        &self,
        Parameters(args): Parameters<tools::DeactivateAllProfilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_profiles::deactivate_all(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: SafeRead. Issues a confirmation token for updating factory rule groups.
    #[tool(
        description = "Prepare a confirmation token for updating Little Snitch factory rule groups. \
                       Optional `scope`: \"apple\", \"third-party\", or \"all\" (default). \
                       Call this first, then pass the token to `update_factory_rule_groups`."
    )]
    async fn prepare_update_factory_rule_groups(
        &self,
        Parameters(args): Parameters<tools::PrepareUpdateFactoryRuleGroupsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::update_factory_rule_groups::prepare_update(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    // Classification: LiveWrite. Refreshes factory rule groups from LS-managed sources.
    #[tool(
        description = "Refresh Little Snitch factory rule groups from LS-managed sources. \
                       Optional `scope`: \"apple\" (`-a`), \"third-party\" (`-t`), or \"all\" (default). \
                       Takes a pre-mutation backup first. Requires a token from \
                       `prepare_update_factory_rule_groups`."
    )]
    async fn update_factory_rule_groups(
        &self,
        Parameters(args): Parameters<tools::UpdateFactoryRuleGroupsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::update_factory_rule_groups::update(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    /// Resolve a rule-group name and issue a confirmation token.
    ///
    /// Pass the returned token and `resolved_name` to `enable_rule_group`
    /// after user approval.
    async fn prepare_enable_rule_group(
        &self,
        Parameters(args): Parameters<tools::PrepareEnableRuleGroupArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_rule_groups::prepare_enable(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    /// Enable a rule group. Requires the token from `prepare_enable_rule_group`.
    async fn enable_rule_group(
        &self,
        Parameters(args): Parameters<tools::EnableRuleGroupArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_rule_groups::enable(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    /// Resolve a rule-group name and issue a confirmation token for disabling.
    ///
    /// For builtin groups (macOS Services, iCloud Services, etc.) you must
    /// pass `acknowledge_builtin: true`. Pass the returned token and
    /// `resolved_name` to `disable_rule_group` after user approval.
    async fn prepare_disable_rule_group(
        &self,
        Parameters(args): Parameters<tools::PrepareDisableRuleGroupArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_rule_groups::prepare_disable(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }

    /// Disable a rule group. Requires the token from `prepare_disable_rule_group`.
    async fn disable_rule_group(
        &self,
        Parameters(args): Parameters<tools::DisableRuleGroupArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::manage_rule_groups::disable(&self.session, args) {
            Ok(result) => {
                let json = serde_json::to_string_pretty(&result).unwrap_or_else(|e| e.to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(msg) => Ok(CallToolResult::error(vec![Content::text(msg)])),
        }
    }
}

#[tool_handler]
#[prompt_handler(router = self.prompt_router)]
impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_03_26;
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_prompts()
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
        let schema_resource = Annotated {
            raw: RawResource {
                uri: resources::schema::URI.to_string(),
                name: "lsrules-schema".to_string(),
                title: Some(".lsrules JSON Schema".to_string()),
                description: Some(
                    "JSON Schema (draft-07) for Little Snitch .lsrules rule-group files. \
                     Consult this before authoring or validating .lsrules content."
                        .to_string(),
                ),
                mime_type: Some("application/schema+json".to_string()),
                size: Some(resources::schema::SCHEMA_STR.len() as u32),
                icons: None,
                meta: None,
            },
            annotations: None,
        };
        Ok(ListResourcesResult::with_all_items(vec![
            resource,
            schema_resource,
        ]))
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

        // Schema resource — served directly from the embedded string; no ManagedDir needed.
        if request.uri == resources::schema::URI {
            return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                resources::schema::SCHEMA_STR,
                resources::schema::URI,
            )]));
        }

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
                Err(msg) if msg.starts_with(resources::lsrules_files::NOT_FOUND_PREFIX) => {
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

    // #10: LSMCP_LOG_LEVEL controls tracing level; default info.
    // stdout is the JSON-RPC transport — all log output must go to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("LSMCP_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("little-snitch-mcp: starting stdio server");

    // #12: Refuse to start if the installed LS version is below 6.3.3.
    if let Ok(bin) = cli::resolve_binary() {
        if let Err(e) = cli::require_compatible(&bin) {
            anyhow::bail!("{e}");
        }
    }

    let managed = managed_dir::ManagedDir::bootstrap()?;
    tracing::info!(root = %managed.root.display(), "managed directory ready");

    let session =
        Arc::new(safety::Session::new().map_err(|e| anyhow::anyhow!("OS RNG failure: {e}"))?);
    let service = EchoServer::new(session).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
