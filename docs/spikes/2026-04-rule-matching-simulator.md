# Spike — LS rule-matching simulator (2026-04)

Tracks [#6](https://github.com/torsday/little-snitch-mcp/issues/6). **Outcome: ship the algorithm specification below; defer the verified implementation to [#29](https://github.com/torsday/little-snitch-mcp/issues/29) (the `explain_rule_match` tool that consumes it).** That ticket already needs live LS access for end-to-end verification, so collapsing the simulator into it avoids two trips through the same trial-and-error loop.

## Why doc-only

The AC requires "All 20 fixtures match LS's actual behavior (verified by creating each connection scenario and observing LS's decision)". Verification is the load-bearing word — an unverified simulator that ships ahead of LS observation is worse than no simulator at all because downstream tools (`explain_rule_match`) would silently lie. The spike's *design* is a separable artifact, and that's what this note captures so the implementer can move quickly.

## The matching problem

Given:

- `model: Model` — the parsed `export-model` JSON (rules + groups + globalDefaults).
- `query: ConnectionQuery { process, remote, port, direction }` — what would-be connection to evaluate.

Return: `Option<RuleMatch { rule_index, rule, why }>` — the rule LS would have matched, or `None` if no rule matches (LS falls back to its default policy).

## Algorithm — total order with documented tiebreakers

The matcher reduces to a **filter-then-rank** pipeline. Filter rules to those that *could* match the query; rank survivors by a 4-key total order; return the winner.

### Step 1 — filter to applicable rules

A rule is *applicable* iff every field LS uses for matching either:

- has the literal value `"any"` (or its array equivalent), or
- has a value that satisfies the query.

Per-field rules:

| Rule field | Matches query when |
|------------|---------------------|
| `action` | always (action is the *output*, not a filter) |
| `process` | `process == query.process`, OR `process == "any"`, OR `process` is a `requiresTrustedSignatureForAnyProcess` rule that matches the query's signature, OR `process` is a `code-id`/path that matches the query's executable identity |
| `remote-domains` / `remote-hosts` / `remote-addresses` | the query's remote (resolved name + IP) is in the listed set; LS does both forward (host→IP) and reverse matching |
| `remote` (special string: `"any"`, `"local-net"`, `"multicast"`, `"broadcast"`, `"bonjour"`, `"dns-servers"`) | semantic match against the query's remote category |
| `direction` | absent ⇒ any direction; `"incoming"` ⇒ only incoming; `"outgoing"` is the implicit default but explicit overrides only match outgoing |
| `protocol` | absent ⇒ any; otherwise byte-match against `query.protocol` |
| `ports` | absent ⇒ any; otherwise the query's port falls in the listed set/range |
| `via` | absent ⇒ any interface; otherwise the query's interface matches |
| `disabled` | `disabled: true` — rule is **not** applicable, full stop |
| `group` (with `groups[group_id].isActive == false`) | rule is **not** applicable; group disable acts as a per-rule disable |

### Step 2 — rank survivors by 4-key total order

Compare two applicable rules by these keys in order; first non-equal key decides the winner.

| # | Key | Higher wins |
|---|-----|-------------|
| 1 | **Priority tier** | `priority: "high"` > absent (regular) > `priority: "low"` |
| 2 | **Specificity score** | sum of contributions from the 11 dimensions in the table below; higher is more specific |
| 3 | **Group precedence** | rule belonging to a group with lower numeric `position` (groups are ordered) wins; rules outside any group rank with `position = 0` |
| 4 | **Declaration order within model.rules** | earlier index wins (deterministic tiebreaker; LS has no rule of "later overrides earlier") |

If all four keys are equal, the rules are observationally identical and either one is a correct return value; the matcher picks the lower index for determinism.

### Specificity score (key 2 dimensions)

| Dimension | Contribution |
|-----------|--------------|
| `process` is an exact path | +5 |
| `process` is a `code-id` | +4 |
| `process` is `requiresTrustedSignatureForAnyProcess` | +3 |
| `process` is `"any"` | 0 |
| `remote-addresses` exact-IP entry matches | +5 |
| `remote-hosts` exact-host entry matches | +4 |
| `remote-domains` exact-domain entry matches | +3 |
| `remote-domains` parent-domain entry matches (e.g. `example.com` matches `api.example.com`) | +2 |
| `remote` special string matches (`local-net`, etc.) | +1 |
| `remote: "any"` | 0 |
| `ports` constrains the match (vs absent) | +1 |
| `protocol` constrains the match (vs absent) | +1 |
| `direction` constrains the match (vs absent) | +1 |

This scheme is *empirical*: the integers are educated guesses chosen so that an exact-process + exact-IP rule beats a broad-allow rule, which beats a broad-deny rule. The implementer must verify each pair against LS and adjust. Two principles to preserve while tuning:

1. **Process specificity strictly dominates remote specificity.** A path-specific allow for `Mail.app → any` should win over an any-process deny for `evil.example`. The +5 process baseline vs +5 IP-exact remote baseline maintains this only because process is summed once and remote is also summed once; review carefully.
2. **No two distinct shapes should produce identical specificity scores by accident.** If they do, key 3/4 decide arbitrarily — operators won't know why a rule won. Tune the weights to break ties on real data.

## Fixture set (20 cases for the implementer)

Each fixture is a `(model, query, expected_match)` tuple. Group them by what they exercise:

| # | Exercises | Description |
|---|-----------|-------------|
| 1 | trivial allow | one `allow any/any` rule; any query matches it |
| 2 | trivial deny | one `deny any/any` rule; any query is denied |
| 3 | empty model | no rules; query returns `None` |
| 4 | priority tier | `high deny mail.com` + `regular allow mail.com` → deny wins |
| 5 | priority tier (low) | `regular allow mail.com` + `low deny mail.com` → allow wins |
| 6 | process specificity | `allow Mail.app/any` + `deny any/mail.com` → first wins for Mail.app, second wins for Safari |
| 7 | remote specificity (IP > host > domain) | three `allow` rules at different remote shapes; query for IP that matches all three returns the IP-exact rule |
| 8 | remote-domains parent matching | `allow example.com` matches a query for `api.example.com` (parent matching) |
| 9 | direction filter | `incoming deny any/any` + `outgoing allow any/any` → outgoing query gets allow |
| 10 | ports constrain | `allow Mail.app/mail.com:587` + `deny Mail.app/mail.com` → port-587 query gets allow, port-25 query gets deny |
| 11 | protocol constrain | `allow tcp` matches tcp query, not udp |
| 12 | via interface | `allow via en0` matches en0 query, not en1 |
| 13 | disabled rule | `disabled: true` rule never matches even when otherwise applicable |
| 14 | group `isActive: false` | rule in disabled group never matches |
| 15 | group precedence | two groups with different `position`, identical rules; lower-position group wins |
| 16 | declaration order tiebreaker | two identical rules; first wins |
| 17 | requiresTrustedSignatureForAnyProcess | rule matches a signed binary regardless of path |
| 18 | code-id match | rule matches by code-id even if path differs (move/rename) |
| 19 | local-net special | `allow local-net` matches RFC1918 query, not public IP |
| 20 | bonjour special | `allow bonjour` matches mDNS query (224.0.0.251 / 5353) |

## Quirks worth flagging during verification

These are observed in the wild but not yet locked in by smoke tests; the implementer should confirm or refute each as they verify the fixture set.

1. **Domain matching is case-insensitive but exact-host matching is not.** `example.COM` in `remote-domains` matches `example.com`. We don't yet know about `remote-hosts`.
2. **`remote-domains` parent matching is greedy.** `com` in `remote-domains` does NOT match `example.com` — LS appears to require at least one label boundary, so `*.com` is not the same as `com`. Verify.
3. **`globalDefaults.networkFilterEnabled: false` short-circuits matching.** When LS's filter is off, no rule applies. The simulator should handle this branch explicitly to avoid producing misleading matches.
4. **`profiles[].isActive`** is rumored to scope rules to active profiles only; the active-profile field appears in `globalDefaults`. Confirm the scoping rule.

## Out of scope (deliberate)

- **Network-layer DNS lookups.** The simulator should accept `(remote_name, remote_ip)` as a pair; resolving a name to an IP at simulator time would tie tests to the network and is the consumer's responsibility.
- **Live model drift.** The simulator operates on a snapshot. The consumer (`explain_rule_match`) should re-export and re-run if the answer matters between calls.
- **Performance.** Linear scan over `model.rules` is fine — typical models have hundreds of rules, not millions.

## What this unblocks

[#29 — Implement explain_rule_match tool using S6 simulator](https://github.com/torsday/little-snitch-mcp/issues/29). That ticket inherits the AC for live verification and the fixture list above; landing the simulator there avoids splitting the verification work across two PRs.
