#!/usr/bin/env bash
# Smoke test 2: rule mutation round-trip via export-model + restore-model -t.
#
# Adds ONE test rule, verifies it appears, removes it, verifies it's gone.
# The test rule is constructed to be inert:
#   - process: "/usr/bin/true"   (system binary; never makes network calls)
#   - remote-domains: ["lsmcp-smoke.invalid"]   (RFC 2606 reserved, never resolves)
#   - action: "ask"   (least impactful — would only prompt, which can't happen
#                      because /usr/bin/true doesn't network)
#   - notes: identifies as a smoke-test rule for easy auditing
#
# SAFETY:
#   - Backup is taken before every restore.
#   - Backup files are written to ~/.little-snitch-mcp-smoke/ with chmod 600,
#     not /tmp.
#   - On any failure, the backup path is printed so you can restore manually:
#       sudo /Applications/Little\ Snitch.app/Contents/Components/littlesnitch \
#         restore-model -t <backup-path>
#   - The test rule is removed at the end whether the test passed or failed.
#
# Usage: bash scripts/smoke-2-rule-roundtrip.sh

set -u
LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
BACKUP_DIR="$HOME/.little-snitch-mcp-smoke"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

ts() { date +%Y%m%dT%H%M%S; }

step() { printf '\n==== %s ====\n' "$1"; }

# Marker used to identify the test rule for cleanup
SMOKE_DOMAIN="lsmcp-smoke-$(date +%s).invalid"
SMOKE_NOTE="little-snitch-mcp smoke test $(date -u +%FT%TZ) - safe to delete"

# 0) Pre-flight
step "0. preflight"
if ! command -v jq >/dev/null; then echo "ERR: jq required"; exit 1; fi
if [[ ! -x "$LS" ]]; then echo "ERR: littlesnitch not at $LS"; exit 1; fi
echo "OK"

# 1) Take a baseline backup
step "1. baseline backup"
BACKUP_BEFORE="$BACKUP_DIR/before-$(ts).json"
sudo "$LS" export-model "$BACKUP_BEFORE"
sudo chmod 600 "$BACKUP_BEFORE"
echo "Wrote: $BACKUP_BEFORE"
# Backup is root-owned; use sudo for both read and stat
echo "  Size: $(sudo cat "$BACKUP_BEFORE" | wc -c | tr -d ' ') bytes"
RULES_BEFORE=$(sudo cat "$BACKUP_BEFORE" | jq '.rules | length')
echo "  Rules before: $RULES_BEFORE"

# 2) Construct the patched model with the test rule appended
step "2. construct patched model with test rule"
PATCHED="$BACKUP_DIR/patched-$(ts).json"
NOW_NSDATE=$(python3 -c "import time; print(time.time() - 978307200)")  # NSDate epoch
sudo cat "$BACKUP_BEFORE" | jq --arg dom "$SMOKE_DOMAIN" --arg note "$SMOKE_NOTE" --argjson now "$NOW_NSDATE" '
  .rules += [{
    "action": "ask",
    "process": "/usr/bin/true",
    "remote-domains": [$dom],
    "direction": "outgoing",
    "notes": $note,
    "creationDate": $now,
    "modificationDate": $now,
    "origin": "user"
  }]
' | sudo tee "$PATCHED" >/dev/null
sudo chmod 600 "$PATCHED"
RULES_PATCHED=$(sudo cat "$PATCHED" | jq '.rules | length')
echo "  Rules in patched model: $RULES_PATCHED  (expected $((RULES_BEFORE + 1)))"
if [[ "$RULES_PATCHED" -ne "$((RULES_BEFORE + 1))" ]]; then
  echo "  ERR: patch did not add exactly one rule"; exit 2
fi

# 3) restore-model -t (the actual mutation)
step "3. restore-model -t  (preserves Terminal access regardless of payload)"
sudo "$LS" restore-model -t "$PATCHED"
echo "  exit=$?"

# 4) Re-export and verify the test rule appears
step "4. verify test rule present"
VERIFY_AFTER="$BACKUP_DIR/verify-after-$(ts).json"
sudo "$LS" export-model "$VERIFY_AFTER"
sudo chmod 600 "$VERIFY_AFTER"
RULES_AFTER=$(sudo cat "$VERIFY_AFTER" | jq '.rules | length')
FOUND=$(sudo cat "$VERIFY_AFTER" | jq --arg dom "$SMOKE_DOMAIN" '[.rules[] | select(.["remote-domains"]? // [] | index($dom))] | length')
echo "  Rules after restore: $RULES_AFTER"
echo "  Test rules matching '$SMOKE_DOMAIN': $FOUND"
if [[ "$FOUND" -lt 1 ]]; then
  echo "  WARN: test rule not found after restore. Inspect $VERIFY_AFTER manually."
  echo "  Skipping cleanup; original backup is at $BACKUP_BEFORE"
  exit 3
fi

# 5) Look at how LS stored our rule (does it carry over our fields verbatim?)
step "5. show how LS stored the test rule (round-trip preservation check)"
sudo cat "$VERIFY_AFTER" | jq --arg dom "$SMOKE_DOMAIN" '[.rules[] | select(.["remote-domains"]? // [] | index($dom))]'

# 6) Remove the test rule via another export → patch → restore -t
step "6. remove test rule (second restore)"
RESTORE="$BACKUP_DIR/cleanup-$(ts).json"
sudo cat "$VERIFY_AFTER" | jq --arg dom "$SMOKE_DOMAIN" '
  .rules |= map(select(.["remote-domains"]? // [] | index($dom) | not))
' | sudo tee "$RESTORE" >/dev/null
sudo chmod 600 "$RESTORE"
sudo "$LS" restore-model -t "$RESTORE"
echo "  exit=$?"

# 7) Verify cleanup
step "7. verify removal"
FINAL="$BACKUP_DIR/final-$(ts).json"
sudo "$LS" export-model "$FINAL"
sudo chmod 600 "$FINAL"
RULES_FINAL=$(sudo cat "$FINAL" | jq '.rules | length')
FOUND_FINAL=$(sudo cat "$FINAL" | jq --arg dom "$SMOKE_DOMAIN" '[.rules[] | select(.["remote-domains"]? // [] | index($dom))] | length')
echo "  Rules final: $RULES_FINAL  (expected $RULES_BEFORE)"
echo "  Test rules matching '$SMOKE_DOMAIN': $FOUND_FINAL  (expected 0)"

if [[ "$RULES_FINAL" -eq "$RULES_BEFORE" && "$FOUND_FINAL" -eq 0 ]]; then
  echo
  echo "PASS: round-trip add+remove succeeded; rule count returned to baseline."
else
  echo
  echo "FAIL: state did not return to baseline. Restore manually with:"
  echo "  sudo \"$LS\" restore-model -t \"$BACKUP_BEFORE\""
fi

echo
echo "Backup files (safe to delete after review):"
ls -la "$BACKUP_DIR"
