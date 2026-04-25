# User Stories

This document defines who we're building for, the jobs they want to get done with an LLM-driven Little Snitch assistant, and the acceptance criteria each story must satisfy. Stories are the source of truth for tool-surface scoping; if an ADR proposes a tool that no story justifies, either the story is missing or the tool is.

Format: `As a <persona>, I want <capability>, so that <outcome>.` Each story carries acceptance criteria framed as observable behavior of the MCP, not implementation notes.

---

## Personas

- **P1 — Privacy-conscious power user.** Daily-driver Mac, technically literate, wants to know what their machine is talking to and curb anything unexpected. Comfortable with the GUI, allergic to friction.
- **P2 — Security-minded developer.** Runs builds, CI agents, and dev tooling locally. Wants tight rules around dev binaries (Homebrew, npm, language runtimes) without breaking workflows.
- **P3 — Incident responder / blue-teamer.** Investigating a suspicious process or beacon. Needs fast read access to traffic and the ability to hard-deny known-bad destinations.
- **P4 — Rules-as-code operator.** Manages a fleet (personal or small team) and treats `.lsrules` files as version-controlled configuration. Wants the LLM to author and refactor rule groups without touching the live model.
- **P5 — Curious observer.** Less technical user who wants plain-English answers to "what is X.app doing on the network?" without learning Little Snitch's mental model.

Personas not in scope: enterprise MDM-driven deployments (LS supports them, but the MCP is single-host); non-macOS users (Little Snitch for Linux exists but is a separate product surface and out of scope for v1).

---

## Epic A — Read & explain

### A1. Inspect what an app is talking to (P1, P5)
**As a** privacy-conscious user, **I want** to ask "what has Slack been connecting to in the last hour?" **so that** I can spot unexpected destinations.

Acceptance:
- The MCP can return a deduplicated list of remote endpoints (host, port, count, first/last seen) for a process specified by name or path within a bounded time window.
- The result includes both allowed and denied connections so the user can see what would have escaped.
- If the user has not enabled "Allow access via Terminal," the MCP returns a structured error explaining the exact GUI step required, not a raw CLI failure.

### A2. Explain a single rule (P5)
**As a** curious user, **I want** to ask "why is this connection allowed?" **so that** I understand which rule matched.

Acceptance:
- Given a process and a remote endpoint, the MCP returns the highest-priority matching rule and the rule group it belongs to.
- The explanation names the matching keys (process path, remote-host glob, port, direction) in plain language.

### A3. Audit all rules touching a process (P2, P3)
**As a** developer, **I want** all rules that match a given executable, **so that** I can reason about what's been allowed across rule groups.

Acceptance:
- The MCP can enumerate every rule whose `process` key matches the queried executable (path-based and code-id-based), grouped by rule group.
- Disabled rules are clearly flagged.
- The output is stable enough to diff between two snapshots.

### A4. Tail logs and traffic (P3)
**As an** incident responder, **I want** to stream recent log and traffic events filtered by process or remote, **so that** I can confirm a hypothesis quickly.

Acceptance:
- Tooling exposes both a one-shot "last N minutes" read and a bounded streaming read (caller specifies a max duration; MCP enforces it).
- Filters by process name, executable path, remote host/IP, and direction are supported.
- Output is structured (one event per record) so the LLM can summarize without re-parsing.

---

## Epic B — Author rules declaratively

### B1. Generate an `.lsrules` blocklist for an app (P1, P2, P4)
**As a** privacy user, **I want** the LLM to draft a `.lsrules` file blocking a named app's telemetry endpoints, **so that** I can review and import it.

Acceptance:
- A tool produces a syntactically valid `.lsrules` JSON file in a managed directory.
- The file uses the compact `denied-remote-domains` form when the entire group is a blocklist; otherwise it uses the full `rules` array.
- The MCP validates the file against the documented schema before writing and surfaces validation errors in line.
- The MCP never auto-imports the file into Little Snitch — the user is told the next step (import via GUI, host as HTTPS subscription, or apply via model surgery if explicitly requested).

### B2. Add, modify, or remove a rule inside an existing `.lsrules` file (P4)
**As a** rules-as-code operator, **I want** the LLM to make targeted edits to a rule group file, **so that** I keep the file as the source of truth.

Acceptance:
- Add/update/remove operations target a rule by a stable selector (e.g., process + remote + direction tuple, or by index inside the file).
- Edits are idempotent: re-running the same add does not create duplicates.
- Every write produces a structured diff the LLM can present to the user.

### B3. Validate a `.lsrules` file before publication (P4)
**As an** operator, **I want** to validate any `.lsrules` file (mine or third-party) against the documented schema, **so that** I don't publish a broken subscription.

Acceptance:
- Validation is exposed as a standalone tool that takes a path or inline JSON.
- The tool returns specific field errors (path, expected type, allowed values) — not just "invalid."

---

## Epic C — Apply changes to the live system (gated)

### C1. Apply an `.lsrules` file as a local rule group (P2, P3)
**As a** developer, **I want** to ask the LLM to apply a freshly authored rule group to my live Little Snitch, **so that** I don't have to drag-and-drop in the GUI.

Acceptance:
- This is a model-surgery operation: it requires explicit user confirmation each call (no "remember my choice" mode).
- Before applying, the MCP exports the current model to a timestamped backup file and reports the path.
- On failure, the MCP surfaces the error and points the user at the backup path so they can manually restore.
- The default scope is the user's rules, not system-wide; system-wide writes additionally require sudo and an even stronger confirmation.

### C2. Disable or enable a rule group on the live system (P3)
**As an** incident responder, **I want** to flip a rule group on or off live, **so that** I can quickly toggle a blocklist.

Acceptance:
- The MCP performs this via model surgery (export → patch the `disabled` flag → restore) with the same confirmation and backup contract as C1.
- The MCP refuses to disable factory rule groups unless the user re-confirms with a stronger acknowledgement.

### C3. Hard-deny a remote endpoint right now (P3)
**As an** incident responder, **I want** to say "block all traffic to evil.example everywhere right now," **so that** I can contain a beacon while I investigate.

Acceptance:
- The MCP authors a deny rule (process: any, remote-hosts: evil.example, action: deny, priority: high) and applies it via model surgery — but only with explicit confirmation.
- If the user prefers safer mode, the MCP can instead write the rule to a managed `.lsrules` file and tell the user how to subscribe.

---

## Epic D — Configuration & ergonomics

### D1. Read and (selectively) write preferences (P1, P2)
**As a** user, **I want** the LLM to read any preference and to write a small allowlist of safe ones, **so that** I can tune behavior without diving into Preferences.

Acceptance:
- All preferences are readable via a resource.
- Only preferences on a documented allowlist (e.g., notification verbosity, alert appearance) are writable. Security-sensitive prefs (e.g., disabling LS itself, allowing global rule editing) are explicitly non-writable; the MCP returns a refusal that names the preference and explains why.

### D2. Capture traffic for a specific process for diagnostic purposes (P3)
**As an** incident responder, **I want** to capture a process's traffic to a pcap, **so that** I can analyze it offline.

Acceptance:
- The MCP wraps `littlesnitch capture-traffic` and returns the resulting file path.
- Capture is bounded (max duration, max bytes) so a runaway capture cannot fill the disk.

---

## Out-of-scope for v1 (explicit non-goals)

- **Real-time alert handling** (approve/deny pop-ups). LS does not expose this via CLI; we will not GUI-script.
- **Profile switching.** Not exposed via CLI in LS5/6.
- **Multi-host fleet management.** Single host, single user MCP.
- **Subscribing to remote `.lsrules` URLs from the MCP.** Subscriptions are added through the GUI; we author files but do not auto-subscribe.
- **Little Snitch for Linux.** Different product, different surface.

---

## Story-to-tool traceability

Tracking that every accepted story has at least one tool that delivers it lives in [adr/0003-mcp-tool-surface.md](adr/0003-mcp-tool-surface.md). If a story here is added without a corresponding entry there, that ADR is out of date.
