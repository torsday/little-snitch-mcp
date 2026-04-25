#!/usr/bin/env bash
# Clean up state left behind by smoke tests:
#   1. Remove any user-created rule whose process is "/bin/test"
#      (the rule from your GUI test; may exist in 1+ variants).
#   2. Delete the ~/.little-snitch-mcp-smoke/ backup directory.
#
# Both steps require sudo. Backup is taken before the model patch.
#
# Usage: bash scripts/cleanup-smoke-state.sh

set -u
LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
SMOKE_DIR="$HOME/.little-snitch-mcp-smoke"

if ! command -v jq >/dev/null; then echo "ERR: jq required"; exit 1; fi
if [[ ! -x "$LS" ]]; then echo "ERR: littlesnitch not at $LS"; exit 1; fi

echo "==== 1. inspect current /bin/test rules ===="
MODEL=$(sudo "$LS" export-model)
TEST_RULES=$(echo "$MODEL" | jq '[.rules[] | select(.process? == "/bin/test")] | length')
TOTAL=$(echo "$MODEL" | jq '.rules | length')
echo "Total rules: $TOTAL  /  rules with process=/bin/test: $TEST_RULES"

if [[ "$TEST_RULES" -gt 0 ]]; then
  echo
  echo "Rules to be removed:"
  echo "$MODEL" | jq '[.rules[] | select(.process? == "/bin/test")]'

  echo
  echo "==== 2. one-shot backup before patch ===="
  mkdir -p "$SMOKE_DIR"
  BACKUP="$SMOKE_DIR/cleanup-backup-$(date +%Y%m%dT%H%M%S).json"
  sudo "$LS" export-model "$BACKUP"
  sudo chmod 600 "$BACKUP"
  echo "Backup: $BACKUP"

  echo
  echo "==== 3. patched model (rules where process != /bin/test) ===="
  # Write to the mode-700 smoke dir, not /tmp. Even before the chmod 600 below,
  # the parent dir's 700 mode prevents other users from traversing to read it.
  # Closes the TOCTOU finding from the security audit.
  PATCHED="$SMOKE_DIR/cleanup-patch-$(date +%Y%m%dT%H%M%S).json"
  sudo cat "$BACKUP" | jq '.rules |= map(select(.process? != "/bin/test"))' | sudo tee "$PATCHED" >/dev/null
  sudo chmod 600 "$PATCHED"

  echo
  echo "==== 4. restore-model -t ===="
  sudo "$LS" restore-model -t "$PATCHED"
  echo "  exit=$?"
  sudo rm -f "$PATCHED"

  echo
  echo "==== 5. verify removal ===="
  AFTER=$(sudo "$LS" export-model | jq '[.rules[] | select(.process? == "/bin/test")] | length')
  echo "Rules with process=/bin/test now: $AFTER  (expected 0)"
else
  echo "No /bin/test rules to remove. Skipping model patch."
fi

echo
echo "==== 6. delete smoke backup directory ===="
if [[ -d "$SMOKE_DIR" ]]; then
  echo "Removing: $SMOKE_DIR"
  sudo rm -rf "$SMOKE_DIR"
  echo "  done"
else
  echo "$SMOKE_DIR does not exist; nothing to delete."
fi

echo
echo "Cleanup complete."
