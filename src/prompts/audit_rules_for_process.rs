//! `audit_rules_for_process` — instructs the LLM to fetch the rules for
//! a named process and produce a human-readable audit report.
//!
//! The prompt is a server-side **template**: it returns instructions for
//! the LLM. The LLM, having read the instructions, calls
//! `get_rules_for_process` and formats the result. No live mutation.

use rmcp::model::{PromptMessage, PromptMessageRole};
use serde::Deserialize;

/// Arguments to the prompt.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct Args {
    /// Process path or bundle identifier to audit (e.g.
    /// `/Applications/Slack.app/Contents/MacOS/Slack` or
    /// `com.tinyspeck.slackmacgap`).
    pub process: String,
}

/// Build the messages returned by the prompt.
///
/// Pure function — no I/O, no state.
pub fn build_messages(args: &Args) -> Vec<PromptMessage> {
    let body = format!(
        "Goal: produce a human-readable audit report for the Little Snitch rules that govern \
         the process **{process}**.

Steps:

1. Call `get_rules_for_process` with `process` set to `{process}`.

2. For each rule group returned, render a section:
   - Group header: `[group display name]` — mark `(DISABLED)` if `is_active` is false.
   - Within the group, list every rule as a one-line summary:
     `#<index>  <action>  <direction>  <remote>`
     where `<remote>` is the hostname, IP, or domain from the rule, and `<action>` is \
     `allow` or `deny`.

3. Flag every **disabled group** prominently — a disabled group means its rules are \
   currently not enforced, which may be a security gap or intentional maintenance state.

4. Identify **redundant rules** within a group: duplicate (action + direction + remote) \
   combinations that appear more than once. List them under a \"Redundant\" sub-header.

5. Identify **conflicting rules** across all groups: a remote that has both an `allow` \
   and a `deny` rule (in any direction). List them under a \"Conflicts\" section at the \
   end of the report.

6. End the report with a brief **Summary** block:
   - Total rule count
   - Number of disabled groups (with names)
   - Number of redundant entries
   - Number of conflicts
   - One-sentence risk assessment (none / low / medium / high) based on the above

Notes:
- If `get_rules_for_process` returns zero rules, tell the operator no rules are currently \
  set for `{process}` and that all connections may be governed by the catch-all profile.
- Do not modify or suggest modifying any rule unless the operator explicitly asks. This \
  prompt is **read-only** — it surfaces information, it does not act.",
        process = args.process,
    );

    vec![PromptMessage::new_text(PromptMessageRole::User, body)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(process: &str) -> Args {
        Args { process: process.into() }
    }

    fn body_of(a: &Args) -> String {
        let msgs = build_messages(a);
        assert_eq!(msgs.len(), 1);
        serde_json::to_string(&msgs[0]).unwrap()
    }

    #[test]
    fn body_names_the_process() {
        let s = body_of(&args("/Applications/Slack.app/Contents/MacOS/Slack"));
        assert!(s.contains("Slack"), "process name missing: {s}");
    }

    #[test]
    fn body_names_the_tool_to_call() {
        let s = body_of(&args("com.example.app"));
        assert!(s.contains("get_rules_for_process"), "tool name missing: {s}");
    }

    #[test]
    fn body_instructs_flagging_disabled_groups() {
        let s = body_of(&args("com.example.app"));
        assert!(s.contains("DISABLED"), "disabled flag instruction missing: {s}");
    }

    #[test]
    fn body_instructs_redundancy_detection() {
        let s = body_of(&args("com.example.app"));
        assert!(s.contains("edundant"), "redundancy instruction missing: {s}");
    }

    #[test]
    fn body_instructs_conflict_detection() {
        let s = body_of(&args("com.example.app"));
        assert!(s.contains("onflict"), "conflict instruction missing: {s}");
    }

    #[test]
    fn body_instructs_summary_block() {
        let s = body_of(&args("com.example.app"));
        assert!(s.contains("Summary"), "summary instruction missing: {s}");
    }

    #[test]
    fn body_forbids_modification_without_request() {
        let s = body_of(&args("com.example.app"));
        assert!(
            s.contains("read-only"),
            "must declare read-only intent: {s}"
        );
    }

    #[test]
    fn body_handles_zero_rules_case() {
        let s = body_of(&args("com.example.app"));
        assert!(s.contains("zero rules"), "zero-rules case missing: {s}");
    }

    #[test]
    fn body_uses_user_role() {
        let msgs = build_messages(&args("com.example.app"));
        let json = serde_json::to_value(&msgs[0]).unwrap();
        assert_eq!(json.get("role").and_then(|v| v.as_str()), Some("user"));
    }
}
