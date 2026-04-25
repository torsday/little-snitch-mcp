#!/usr/bin/env bash
# Reverse-engineer the live-model rule shape by inspecting a user-created rule.
#
# Prerequisites:
#   1. In Little Snitch, open Rules (Cmd+R or Window > Rules).
#   2. Click + to add a new rule. Set:
#        Process: any executable (e.g., /usr/bin/curl)
#        Action: Ask
#        Direction: Outgoing
#        Remote:  domain  =>  lsmcp-test.invalid
#        (Optionally: add a Note containing "lsmcp")
#      Save.
#   3. Run this script.
#
# The script finds rules without a factoryID (= user-created rules), dumps the
# first one's exact key/value shape, and leaves the rule in place for later
# deletion via the GUI.
#
# Usage: bash scripts/inspect-user-rule.sh

set -u
LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"

if ! command -v jq >/dev/null; then echo "ERR: jq required"; exit 1; fi
if [[ ! -x "$LS" ]]; then echo "ERR: littlesnitch not at $LS"; exit 1; fi

echo "==== fetching model ===="
MODEL=$(sudo "$LS" export-model)
TOTAL=$(echo "$MODEL" | jq '.rules | length')
USER_COUNT=$(echo "$MODEL" | jq '[.rules[] | select(has("factoryID") | not)] | length')
echo "Total rules: $TOTAL"
echo "Rules without factoryID (= user-created): $USER_COUNT"

if [[ "$USER_COUNT" -eq 0 ]]; then
  echo
  echo "No user-created rules found. Please create one in the LS GUI first:"
  echo "  Window > Rules > + > set Action=Ask, Direction=Outgoing,"
  echo "    Process=/usr/bin/curl, Remote=domain 'lsmcp-test.invalid', Save."
  echo "Then re-run this script."
  exit 2
fi

echo
echo "==== first user rule: full key set ===="
echo "$MODEL" | jq '[.rules[] | select(has("factoryID") | not)] | .[0] | keys'

echo
echo "==== first user rule: per-field type and (sanitized) sample value ===="
echo "$MODEL" | jq '
  [.rules[] | select(has("factoryID") | not)]
  | .[0]
  | to_entries
  | map({
      k: .key,
      t: (.value | type),
      v: (.value
            | if type == "string" then
                if length > 80 then (.[0:80] + "…") else . end
              elif type == "array" then
                if length > 0 then "[\(length) items: \(.[0])]" else "[]" end
              elif type == "object" then "{\(keys | length) keys}"
              else . end)
    })
'

echo
echo "==== if you added a Note containing 'lsmcp', show its raw rule ===="
echo "$MODEL" | jq '
  [.rules[] | select(has("factoryID") | not) | select((.notes? // "") | test("lsmcp"; "i"))]
  | if length > 0 then .[0] else "no rule with note matching lsmcp" end
'

echo
echo "==== what the SAME rule's process/remote field looks like (compare to .lsrules schema) ===="
echo "$MODEL" | jq '
  [.rules[] | select(has("factoryID") | not)] | .[0]
  | {
      process_kind: (
        if has("process") then "process"
        elif has("requiresTrustedSignatureForAnyProcess") then "trusted-signature"
        else "other" end),
      process_value: (.process? // null),
      remote_kind: (
        ["remote","remote-domains","remote-hosts","remote-addresses"]
        | map(select(. as $k | ($k | IN(.)) | not))[0]? // (
            ["remote","remote-domains","remote-hosts","remote-addresses"]
            | map(select(. as $k | (input_filename // "") | length > 0))
          )
      ),
      action: .action,
      direction: (.direction // "<absent: defaults to outgoing>"),
      priority: (.priority // "<absent: defaults to regular>")
    }
'

echo
echo "==== done ===="
echo "If anything in the output looks sensitive, redact before sharing."
echo "When you're done, you can delete the test rule via LS Rules editor."
