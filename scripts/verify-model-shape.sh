#!/usr/bin/env bash
# Drill into the LS6.3.3 model shape using the keys discovered by verify-cli.sh.
# Dumps structure (keys, types, sample non-sensitive scalars) — never the full
# values, never the full process/host strings.
#
# Usage: bash scripts/verify-model-shape.sh
# Sudo will be required.

set -u

LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"

if [[ ! -x "$LS" ]]; then echo "ERR: littlesnitch not at $LS" >&2; exit 1; fi
if ! command -v jq >/dev/null 2>&1; then echo "ERR: jq missing" >&2; exit 1; fi

section() { printf '\n========== %s ==========\n' "$1"; }

# Cache the model in memory by reading once and feeding into multiple jq filters
# via a temp fifo would be ideal, but simpler: just sudo-export per call. Sudo
# will reuse its timestamp ticket within the 5-min window.

section "groups: keys (these are group IDs)"
sudo "$LS" export-model | jq '.groups | keys'

section "groups: per-group summary (id -> {name, type, key set})"
sudo "$LS" export-model | jq '
  .groups
  | to_entries
  | map({
      id: .key,
      keys_in_value: (.value | keys),
      name: (.value.name? // null),
      kind: (.value.kind? // .value.type? // null),
      enabled: (.value.enabled? // null),
      isFactory: (.value.isFactory? // .value.factory? // null)
    })
'

section "rules: count + first rule's key set (no values)"
sudo "$LS" export-model | jq '{count: (.rules|length), first_rule_keys: (.rules[0]|keys)}'

section "rules: distinct top-level key sets (which fields each rule uses)"
sudo "$LS" export-model | jq '
  .rules
  | map(keys | sort)
  | group_by(.)
  | map({key_set: .[0], count: length})
  | sort_by(-.count)
'

section "rules: distinct values for action / direction / priority"
sudo "$LS" export-model | jq '
  {
    action: (.rules | map(.action? // "<absent>") | unique),
    direction: (.rules | map(.direction? // "<absent>") | unique),
    priority: (.rules | map(.priority? // "<absent>") | unique)
  }
'

section "rules: how rules link to groups (sample non-sensitive fields per rule)"
sudo "$LS" export-model | jq '
  .rules[0:5] | map(
    [(. | keys[]) | select(test("group|owner|parent|profile|scope"; "i"))] as $link_keys
    | { link_keys_present: $link_keys,
        action: .action?,
        direction: .direction?,
        has_remoteHosts: (has("remoteHosts") or has("remote-hosts")),
        has_remoteDomains: (has("remoteDomains") or has("remote-domains")),
        has_remoteAddresses: (has("remoteAddresses") or has("remote-addresses")),
        process_field: ([keys[] | select(test("process|executable|codeId"; "i"))]),
        disabled: .disabled?
      }
  )
'

section "profiles: keys (likely group IDs / profile IDs)"
sudo "$LS" export-model | jq '.profiles | keys'

section "noProfilePseudoProfile: key set"
sudo "$LS" export-model | jq '.noProfilePseudoProfile | keys'

section "users: array length and first entry's key set"
sudo "$LS" export-model | jq '{count: (.users|length), first_user_keys: (.users[0]|keys)}'

section "globalDefaults: full keys"
sudo "$LS" export-model | jq '.globalDefaults | keys'

section "codeRequirements: keys (these are code-id strings; redact before sharing if you prefer)"
sudo "$LS" export-model | jq '.codeRequirements | keys | .[0:5]'

section "lastSeenExecutableByCodeIdentifier: 5 sample keys (code IDs only, no paths)"
sudo "$LS" export-model | jq '.lastSeenExecutableByCodeIdentifier | keys | .[0:5]'

section "bundleVersion + factoryRuleSetVersion (schema versions)"
sudo "$LS" export-model | jq '{bundleVersion, factoryRuleSetVersion}'

section "done"
echo "If any code-id strings, app paths, or rule field names look sensitive, redact before sharing."
