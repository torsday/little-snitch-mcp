//! `block_telemetry_for_app` — drafts a `.lsrules` blocking the
//! telemetry endpoints of a named application.
//!
//! Per [ADR-0004 §S5 decision](../../docs/adr/0004-safety-permissions-and-confirmation.md)
//! and [#5](https://github.com/torsday/little-snitch-mcp/issues/5):
//! we ship no curated telemetry-host list. The LLM drafts the host
//! list from its training (and an optional caller-provided URL),
//! writes the draft via `create_lsrules_file`, and tells the operator
//! to review before applying. No live mutation.
//!
//! The prompt is a server-side **template**: it returns instructions
//! for the LLM, not tool calls. The LLM, having read the instructions,
//! is responsible for calling `create_lsrules_file` with the drafted
//! content.

use rmcp::model::{PromptMessage, PromptMessageRole};
use serde::Deserialize;

/// Arguments to the prompt.
///
/// Wrapped in [`rmcp::handler::server::wrapper::Parameters`] when used
/// inside an `#[rmcp::prompt]` method.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct Args {
    /// Application whose telemetry should be blocked. Free-form name
    /// (e.g. "Slack", "Microsoft Office", "Adobe Photoshop"). The LLM
    /// uses this to seed its draft list.
    pub app_name: String,

    /// Optional URL the LLM should fetch and integrate as an
    /// additional source of telemetry hosts (e.g. an upstream
    /// blocklist or a vendor's transparency page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_url: Option<String>,
}

/// Build the messages returned by the prompt.
///
/// Pure function — no I/O, no state. Easy to test.
pub fn build_messages(args: &Args) -> Vec<PromptMessage> {
    let url_clause = args
        .optional_url
        .as_deref()
        .map(|u| {
            format!(
                "\n\nAlso fetch this source and integrate any telemetry hostnames it lists: {u}"
            )
        })
        .unwrap_or_default();

    let body = format!(
        "Goal: draft a Little Snitch `.lsrules` file that blocks the telemetry / analytics \
         endpoints of **{app}** without applying it to the live model.

Steps:

1. From your training, list the hostnames {app} is known to use for telemetry, crash reporting, \
   feature-flag fetches, and product analytics. Be conservative — include only hosts you are \
   confident are telemetry, not hosts the app needs for its core function.{url_clause}

2. Group the hostnames into a `denied_remote_domains` list. Use lowercased fully-qualified \
   names. Do not include leading dots; Little Snitch matches parent domains.

3. Call the `create_lsrules_file` tool with:
   - `name`: `block-{app_slug}-telemetry`
   - `description`: a one-line summary that names the app and the source(s) you used
   - `denied_remote_domains`: the list from step 2
   - `replace`: false (refuse if a file by this name already exists)

4. **Do not apply the file to the live model in this turn.** Tell the operator to:
   a. Open the produced `.lsrules` file under their managed directory and review the host list.
   b. Remove or add hostnames as needed.
   c. When satisfied, instruct you to call `apply_lsrules_file_to_live_model` (which will \
      compute the diff and request a confirmation token) — that is a separate step that \
      requires their explicit approval.

5. Return a brief summary to the operator: the file path, the number of hosts blocked, \
   the source(s) used, and the exact next-step instruction in step 4.

Notes:
- If the operator asks to apply the file directly without review, refuse and explain that \
  this prompt is the **draft** half of a two-step workflow per ADR-0004's safety model.
- If you cannot identify any reliable telemetry hosts for **{app}**, do NOT guess. Tell the \
  operator and ask them to supply a source URL via the `optional_url` argument.",
        app = args.app_name,
        url_clause = url_clause,
        app_slug = slugify(&args.app_name),
    );

    vec![PromptMessage::new_text(PromptMessageRole::User, body)]
}

/// Conservatively slugify an app name for use in a filename.
/// Lowercase, ASCII alphanumerics and `-` only; everything else
/// collapses to a single `-`. Empty input yields "app".
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dash = true; // suppress leading dash
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { "app".into() } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(name: &str, url: Option<&str>) -> Args {
        Args {
            app_name: name.into(),
            optional_url: url.map(String::from),
        }
    }

    fn body_of(args: &Args) -> String {
        let msgs = build_messages(args);
        assert_eq!(msgs.len(), 1);
        // The PromptMessage representation is opaque; serialize and read.
        serde_json::to_string(&msgs[0]).unwrap()
    }

    #[test]
    fn body_names_the_app_in_the_goal() {
        let s = body_of(&args("Slack", None));
        assert!(s.contains("Slack"), "missing app name: {s}");
    }

    #[test]
    fn body_names_the_create_tool_to_call() {
        let s = body_of(&args("Slack", None));
        assert!(s.contains("create_lsrules_file"), "missing tool name: {s}");
    }

    #[test]
    fn body_proposes_a_kebab_filename_from_the_app_name() {
        let s = body_of(&args("Microsoft Office", None));
        assert!(
            s.contains("block-microsoft-office-telemetry"),
            "expected slug `microsoft-office`: {s}"
        );
    }

    #[test]
    fn body_includes_url_when_supplied() {
        let s = body_of(&args("Slack", Some("https://example.com/list")));
        assert!(s.contains("https://example.com/list"), "missing url: {s}");
    }

    #[test]
    fn body_omits_url_clause_when_no_url_supplied() {
        let s = body_of(&args("Slack", None));
        assert!(
            !s.contains("Also fetch this source"),
            "url clause must be absent when no url given: {s}"
        );
    }

    #[test]
    fn body_explicitly_forbids_auto_apply() {
        let s = body_of(&args("Slack", None));
        assert!(
            s.contains("Do not apply"),
            "must instruct against auto-apply: {s}"
        );
    }

    #[test]
    fn body_names_the_apply_tool_as_the_separate_followup_step() {
        let s = body_of(&args("Slack", None));
        assert!(
            s.contains("apply_lsrules_file_to_live_model"),
            "must reference the apply tool as the next step: {s}"
        );
    }

    #[test]
    fn body_instructs_refusal_on_no_known_hosts() {
        let s = body_of(&args("ObscureApp", None));
        assert!(
            s.contains("do NOT guess"),
            "must tell LLM not to guess: {s}"
        );
    }

    #[test]
    fn body_uses_user_role() {
        // The prompt frames the workflow as a user instruction so the
        // LLM treats it as the conversation seed, not as its own prior
        // assistant turn.
        let msgs = build_messages(&args("Slack", None));
        let json = serde_json::to_value(&msgs[0]).unwrap();
        assert_eq!(json.get("role").and_then(|v| v.as_str()), Some("user"));
    }

    // ---------- slugify ----------

    #[test]
    fn slugify_lowercases_and_collapses_spaces() {
        assert_eq!(slugify("Microsoft Office"), "microsoft-office");
    }

    #[test]
    fn slugify_strips_leading_and_trailing_punctuation() {
        assert_eq!(slugify("--Slack!!"), "slack");
    }

    #[test]
    fn slugify_collapses_runs_of_non_alnum() {
        assert_eq!(slugify("Adobe   ::   Photoshop"), "adobe-photoshop");
    }

    #[test]
    fn slugify_handles_unicode_by_collapsing() {
        // Non-ASCII chars become a single dash; the result is still a
        // valid filename, even if not pretty.
        assert_eq!(slugify("Café 🎯 Manager"), "caf-manager");
    }

    #[test]
    fn slugify_empty_input_yields_app_placeholder() {
        assert_eq!(slugify(""), "app");
        assert_eq!(slugify("!!!"), "app");
    }
}
