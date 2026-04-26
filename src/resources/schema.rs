/// MCP resource URI for the .lsrules JSON Schema.
pub const URI: &str = "littlesnitch://schema/lsrules";

/// The .lsrules JSON Schema, embedded at compile time.
pub const SCHEMA_STR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/lsrules.schema.json"
));
