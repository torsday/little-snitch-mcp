# little-snitch-mcp

A Model Context Protocol (MCP) server for the [Little Snitch](https://obdev.at/littlesnitch) macOS firewall.

> **Status: design locked, ready for implementation.** All ten use cases are backed by empirically-verified building blocks (see [docs/feasibility-report.md](docs/feasibility-report.md)). No code yet.
>
> **Target:** Little Snitch 6, floor version **6.3.3**. LS5 is out of scope.

## What it will do

Let an LLM (via Claude Desktop, Claude Code, or any MCP client) help you:

- Read what your Mac is talking to — live log stream, historical traffic stats, the full rule model, preferences.
- Author `.lsrules` rule-group files in a managed directory you can `git`-track.
- Toggle rule groups (`rulegroup -e/-d`), switch profiles (`profile -a/-d`), and refresh factory groups directly via dedicated CLI commands.
- Add/edit/delete individual rules via a confirmed `export-model` → patch → `restore-model -t` round-trip (with auto-backup).
- Surgically disable single entries inside subscribed blocklists via the deletion-overlay arrays — without modifying the upstream blocklist.
- Apply changes to your live Little Snitch only with explicit per-call confirmation and an automatic backup before every mutation.

See [docs/value-prop.md](docs/value-prop.md) for ten concrete, evidence-backed use cases.

## What it explicitly will not do

The Little Snitch CLI does not expose **alert popup handling** (approve/deny live alerts) or **subscribing to a remote `.lsrules` URL** (a one-time GUI action). We will not pretend it does. We will not GUI-script. See [docs/design.md](docs/design.md) for the full non-goals list.

## What you'll be able to ask it to do

Concrete examples — all backed by the verified CLI surface, not aspirational:

**Observability**
- *"What did Slack talk to in the last hour? Anything I shouldn't expect?"* — pulls live traffic, summarizes destinations, flags outliers.
- *"Why was this connection allowed?"* — walks the rule model and explains the matching rule in plain English.
- *"Tail traffic from this PID for 30 seconds and tell me what it's doing."* — bounded packet capture + interpretation.

**Cleanup**
- *"I have 21 rules. Which haven't been used in 90 days? Which apps have orphaned rules?"* — sort by `lastUsed`/`useCount`, propose removals, you approve, MCP applies.
- *"Generate my weekly firewall report."* — diff prior model snapshot, aggregate new domains by app, summarize.

**Authoring**
- *"Block all telemetry endpoints for Adobe Creative Cloud."* — drafts a `.lsrules` blocklist, you review, apply with confirmation.
- *"I just installed Linear. Watch its traffic for 5 minutes and propose a sane rule set."* — observation window → clustered destinations → drafted rules.

**Incident response**
- *"Block evil.example everywhere right now."* — high-priority deny rule, two-step confirmation, auto-backed-up before applying.

**Surgical exceptions**
- *"The EasyList blocklist is blocking my work analytics. Disable just that one entry."* — uses LS's deletion-overlay arrays so the upstream blocklist stays intact.

**Lifecycle**
- *"Switch to my paranoid profile."* — direct CLI, no model surgery.
- *"Sync my firewall rules from this git repo across both my Macs."* — managed `.lsrules` directory is the repo.

The full set of ten use cases with confidence ratings is in [docs/value-prop.md](docs/value-prop.md). Each is grounded in capabilities verified against a live LS 6.3.3 install — not "the docs say this should work."

## Design

Read in this order:

1. [docs/value-prop.md](docs/value-prop.md) — **start here**: ten concrete use cases with confidence ratings, recommended v1 scope, honest verdict.
2. [docs/feasibility-report.md](docs/feasibility-report.md) — empirical probe of LS 6.3.3, GUI-to-MCP capability matrix, model schema deep-dive.
3. [docs/design.md](docs/design.md) — overview, architecture diagram, worked example.
4. [docs/user-stories.md](docs/user-stories.md) — personas and acceptance criteria.
5. ADRs (in order):
   - [0001 — language, runtime, target LS version](docs/adr/0001-language-runtime-and-target-version.md)
   - [0002 — CRUD strategy](docs/adr/0002-crud-strategy.md)
   - [0003 — MCP tool surface](docs/adr/0003-mcp-tool-surface.md)
   - [0004 — safety, permissions, confirmation protocol](docs/adr/0004-safety-permissions-and-confirmation.md)
   - [0005 — deployment and configuration](docs/adr/0005-deployment-and-configuration.md)
   - [0006 — sudo strategy and no-TTY handling](docs/adr/0006-sudo-strategy-and-no-tty-handling.md)

## Reference material

The CLI we're targeting: [Little Snitch 6 command line overview](https://help.obdev.at/littlesnitch6/cmd-overview) (with [LS5's per-command flag reference](https://help.obdev.at/littlesnitch5/adv-commandline) still applicable for the commands shared between versions).
The file format we'll author: [`.lsrules` schema](https://developer.obdev.at/littlesnitch6/adv-lsrules-file-format).
