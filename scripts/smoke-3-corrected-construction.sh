#!/usr/bin/env bash
# Smoke test 3: rule construction round-trip with the EMPIRICALLY-CORRECT schema.
#
# Uses the field encodings discovered via inspect-user-rule.sh:
#   - dates are ISO-8601 strings ("YYYY-MM-DDThh:mm:ssZ"), not NSDate numbers
#   - remote-domains is a string for a single entry, not array
#   - origin is "frontend" (the GUI's value), not "user"
#   - direction omitted when default (outgoing)
#   - uid is the current user's numeric UID
#   - factoryID / protected / owner / lastUsed / useCount / etc. omitted
#
# Adds ONE inert test rule, verifies, removes it. Same safety harness as smoke 2.
#
# Usage: bash scripts/smoke-3-corrected-construction.sh

set -u
LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
BACKUP_DIR="$HOME/.little-snitch-mcp-smoke"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

ts() { date +%Y%m%dT%H%M%S; }
step() { printf '\n==== %s ====\n' "$1"; }

SMOKE_DOMAIN="lsmcp-smoke3-$(date +%s).invalid"
NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
USER_UID=$(id -u)

step "0. preflight"
command -v jq >/dev/null || { echo "ERR: jq required"; exit 1; }
[[ -x "$LS" ]] || { echo "ERR: littlesnitch not at $LS"; exit 1; }
echo "user uid: $USER_UID"
echo "now iso: $NOW_ISO"
echo "test domain: $SMOKE_DOMAIN"

step "1. baseline backup"
BACKUP_BEFORE="$BACKUP_DIR/before-$(ts).json"
sudo "$LS" export-model "$BACKUP_BEFORE"
sudo chmod 600 "$BACKUP_BEFORE"
echo "Wrote: $BACKUP_BEFORE"
echo "  Size: $(sudo cat "$BACKUP_BEFORE" | wc -c | tr -d ' ') bytes"
RULES_BEFORE=$(sudo cat "$BACKUP_BEFORE" | jq '.rules | length')
echo "  Rules before: $RULES_BEFORE"

step "2. construct patched model with correctly-shaped test rule"
PATCHED="$BACKUP_DIR/patched-$(ts).json"
sudo cat "$BACKUP_BEFORE" | jq \
  --arg dom "$SMOKE_DOMAIN" \
  --arg now "$NOW_ISO" \
  --argjson uid "$USER_UID" '
  .rules += [{
    "action": "ask",
    "process": "/bin/test",
    "remote-domains": $dom,
    "origin": "frontend",
    "creationDate": $now,
    "modificationDate": $now,
    "uid": $uid
  }]
' | sudo tee "$PATCHED" >/dev/null
sudo chmod 600 "$PATCHED"
RULES_PATCHED=$(sudo cat "$PATCHED" | jq '.rules | length')
echo "  Rules in patched model: $RULES_PATCHED  (expected $((RULES_BEFORE + 1)))"

echo "  patched rule:"
sudo cat "$PATCHED" | jq --arg dom "$SMOKE_DOMAIN" '.rules[] | select(.["remote-domains"] == $dom)'

step "3. restore-model -t (preserves Terminal access regardless of payload)"
sudo "$LS" restore-model -t "$PATCHED"
RC=$?
echo "  exit=$RC"
if [[ $RC -ne 0 ]]; then
  echo
  echo "FAIL: restore-model rejected the corrected payload."
  echo "Original backup at: $BACKUP_BEFORE"
  echo "Patched payload at: $PATCHED"
  exit 3
fi

step "4. verify test rule present"
VERIFY_AFTER="$BACKUP_DIR/verify-after-$(ts).json"
sudo "$LS" export-model "$VERIFY_AFTER"
sudo chmod 600 "$VERIFY_AFTER"
RULES_AFTER=$(sudo cat "$VERIFY_AFTER" | jq '.rules | length')
FOUND=$(sudo cat "$VERIFY_AFTER" | jq --arg dom "$SMOKE_DOMAIN" '
  [.rules[] | select(
    (.["remote-domains"]? == $dom) or
    ((.["remote-domains"]? // [] | type == "array") and (.["remote-domains"] | index($dom)))
  )] | length
')
echo "  Rules after restore: $RULES_AFTER"
echo "  Test rules matching '$SMOKE_DOMAIN': $FOUND"

step "5. show how LS stored our rule (round-trip preservation check)"
sudo cat "$VERIFY_AFTER" | jq --arg dom "$SMOKE_DOMAIN" '
  [.rules[] | select(
    (.["remote-domains"]? == $dom) or
    ((.["remote-domains"]? // [] | type == "array") and (.["remote-domains"] | index($dom)))
  )]
'

if [[ "$FOUND" -lt 1 ]]; then
  echo
  echo "FAIL: rule not found after restore. Inspect $VERIFY_AFTER manually."
  echo "Original backup at: $BACKUP_BEFORE"
  exit 4
fi

step "6. remove test rule via second restore"
RESTORE="$BACKUP_DIR/cleanup-$(ts).json"
sudo cat "$VERIFY_AFTER" | jq --arg dom "$SMOKE_DOMAIN" '
  .rules |= map(select(
    (.["remote-domains"]? == $dom) or
    ((.["remote-domains"]? // [] | type == "array") and (.["remote-domains"] | index($dom)))
    | not
  ))
' | sudo tee "$RESTORE" >/dev/null
sudo chmod 600 "$RESTORE"
sudo "$LS" restore-model -t "$RESTORE"
echo "  exit=$?"

step "7. verify removal"
FINAL="$BACKUP_DIR/final-$(ts).json"
sudo "$LS" export-model "$FINAL"
sudo chmod 600 "$FINAL"
RULES_FINAL=$(sudo cat "$FINAL" | jq '.rules | length')
FOUND_FINAL=$(sudo cat "$FINAL" | jq --arg dom "$SMOKE_DOMAIN" '
  [.rules[] | select(
    (.["remote-domains"]? == $dom) or
    ((.["remote-domains"]? // [] | type == "array") and (.["remote-domains"] | index($dom)))
  )] | length
')
echo "  Rules final: $RULES_FINAL  (expected $RULES_BEFORE)"
echo "  Test rules matching: $FOUND_FINAL  (expected 0)"

if [[ "$RULES_FINAL" -eq "$RULES_BEFORE" && "$FOUND_FINAL" -eq 0 ]]; then
  echo
  echo "PASS: round-trip add+remove succeeded with corrected schema."
  echo "  -> from-scratch rule construction is viable; no clone-template needed."
else
  echo
  echo "FAIL: state did not return to baseline. Restore manually with:"
  echo "  sudo \"$LS\" restore-model -t \"$BACKUP_BEFORE\""
fi

echo
echo "Backup files in $BACKUP_DIR (safe to delete after review):"
ls -la "$BACKUP_DIR"
