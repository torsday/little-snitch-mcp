#!/usr/bin/env bash
# Read-only verification of the Little Snitch CLI surface.
# Confirms shape of preferences, restrictions, model, and traffic log
# without dumping the full model to disk.
#
# Usage: bash scripts/verify-cli.sh
#
# Will prompt for sudo password (cached for ~5 min). Output is structure-only;
# review before sharing if you're worried about leaking app/process names.

set -u

LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"

if [[ ! -x "$LS" ]]; then
  echo "ERR: littlesnitch CLI not found at $LS" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERR: jq not installed (brew install jq)" >&2
  exit 1
fi

section() { printf '\n========== %s ==========\n' "$1"; }

section "version"
"$LS" --version

section "prefs: first 25 keys (no values)"
sudo "$LS" list-preferences | awk -F' = ' 'NF{print $1}' | head -25

section "prefs: total count"
sudo "$LS" list-preferences | wc -l | tr -d ' '

section "prefs: -g global-only (first 15 keys)"
sudo "$LS" list-preferences -g | awk -F' = ' 'NF{print $1}' | head -15

section "prefs: -u user-only (first 15 keys)"
sudo "$LS" list-preferences -u | awk -F' = ' 'NF{print $1}' | head -15

section "restrictions"
sudo "$LS" restrictions

section "model: top-level keys"
sudo "$LS" export-model | jq 'keys'

section "model: per-key type and size"
sudo "$LS" export-model | jq '
  to_entries
  | map({
      k: .key,
      t: (.value | type),
      len: (.value | if type == "array" then length
                     elif type == "object" then (keys | length)
                     else null end)
    })
'

section "model: rule-group sample (best-effort across common key names)"
sudo "$LS" export-model | jq '
  def first_array_of_groups:
    [ to_entries[]
      | select(.value | type == "array")
      | select(.value[0]? | type == "object")
      | select(.value[0]? | has("rules") or has("name"))
      | .key
    ] | first;
  . as $m
  | (first_array_of_groups // null) as $k
  | if $k == null then "no obvious rule-group array under top-level keys"
    else { key_used: $k,
           sample_group_keys: ($m[$k][0] | keys),
           sample_rule_keys: ($m[$k][0].rules[0]? // null | if . == null then "no rules in first group" else keys end)
         }
    end
'

section "model: profiles sample (best-effort)"
sudo "$LS" export-model | jq '
  def first_profile_array:
    [ to_entries[]
      | select(.key | test("profile"; "i"))
      | select(.value | type == "array")
      | .key
    ] | first;
  . as $m
  | (first_profile_array // null) as $k
  | if $k == null then "no obvious profile array under top-level keys"
    else { key_used: $k,
           count: ($m[$k] | length),
           sample_profile_keys: ($m[$k][0]? | if . == null then "empty" else keys end)
         }
    end
'

section "log-traffic: 5min CSV (header + up to 5 rows)"
sudo "$LS" log-traffic -b "$(date -v-5M '+%Y-%m-%d %H:%M:%S')" 2>&1 | head -6

section "exit codes"
sudo "$LS" read-preference allowCommandLineAccess >/dev/null 2>&1
echo "read-preference (existing key): $?"
sudo "$LS" read-preference no_such_key_zzz >/dev/null 2>&1
echo "read-preference (missing key): $?"
sudo "$LS" rulegroup -e "definitely-not-a-real-group-zzz" >/dev/null 2>&1
echo "rulegroup -e (missing group): $?"

section "done"
echo "If anything looks sensitive (app paths, hostnames), redact before sharing."
