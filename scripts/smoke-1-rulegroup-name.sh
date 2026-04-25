#!/usr/bin/env bash
# Smoke test 1: probe what `rulegroup -e/-d` accepts as <name>.
#
# Builtins have name=null in the model. The CLI takes a "group name". This
# script tries multiple candidate strings (kind values, group IDs, common
# display names) and records exit code + stderr.
#
# SAFETY: For each candidate, we use the action (-e or -d) that matches the
# current isActive state so the call is a no-op even if the name is accepted.
# At the end we verify state is unchanged and revert if it isn't.
#
# Usage: bash scripts/smoke-1-rulegroup-name.sh

set -u
LS="/Applications/Little Snitch.app/Contents/Components/littlesnitch"

state_for() {
  local id="$1"
  sudo "$LS" export-model 2>/dev/null | jq -r ".groups.\"$id\".isActive // \"unknown\""
}

probe() {
  local candidate="$1"
  local action="$2"
  printf '  %s "%s"\n' "$action" "$candidate"
  local out rc
  out=$(sudo "$LS" rulegroup "$action" "$candidate" 2>&1) ; rc=$?
  printf '    exit=%d output=%q\n' "$rc" "$out"
}

revert_if_changed() {
  local id="$1" candidate="$2" pre="$3"
  local post; post=$(state_for "$id")
  if [[ "$pre" != "$post" ]]; then
    printf '  REVERT: %s.isActive changed %s -> %s, restoring via "%s"\n' "$id" "$pre" "$post" "$candidate"
    if [[ "$pre" == "true" ]]; then
      sudo "$LS" rulegroup -e "$candidate" >/dev/null 2>&1
    else
      sudo "$LS" rulegroup -d "$candidate" >/dev/null 2>&1
    fi
    local final; final=$(state_for "$id")
    printf '  after revert: %s.isActive=%s (target=%s)\n' "$id" "$final" "$pre"
  fi
}

PRE_AAAAAC=$(state_for "aaaaac")
PRE_AAAAAD=$(state_for "aaaaad")
echo "==== initial state ===="
echo "groups.aaaaac.isActive = $PRE_AAAAAC  (kind: builtinMacOSServices)"
echo "groups.aaaaad.isActive = $PRE_AAAAAD  (kind: builtinICloudServices)"

# Choose the no-op action per group: if currently active, use -e; if inactive, use -d.
case "$PRE_AAAAAC" in true) ACT_C="-e" ;; *) ACT_C="-d" ;; esac
case "$PRE_AAAAAD" in true) ACT_D="-e" ;; *) ACT_D="-d" ;; esac

echo
echo "==== baseline: definitely-missing name (expect exit 1) ===="
probe "lsmcp_does_not_exist_$$" "-e"

echo
echo "==== candidate: 'builtinMacOSServices' (the kind value) ===="
probe "builtinMacOSServices" "$ACT_C"
revert_if_changed "aaaaac" "builtinMacOSServices" "$PRE_AAAAAC"

echo
echo "==== candidate: 'builtinICloudServices' (the kind value) ===="
probe "builtinICloudServices" "$ACT_D"
revert_if_changed "aaaaad" "builtinICloudServices" "$PRE_AAAAAD"

echo
echo "==== candidate: 'aaaaac' (the group ID) ===="
probe "aaaaac" "$ACT_C"
revert_if_changed "aaaaac" "aaaaac" "$PRE_AAAAAC"

echo
echo "==== candidate: 'aaaaad' (the group ID) ===="
probe "aaaaad" "$ACT_D"
revert_if_changed "aaaaad" "aaaaad" "$PRE_AAAAAD"

echo
echo "==== candidate: 'macOS Services' (likely localized display) ===="
probe "macOS Services" "$ACT_C"
revert_if_changed "aaaaac" "macOS Services" "$PRE_AAAAAC"

echo
echo "==== candidate: 'iCloud Services' (likely localized display) ===="
probe "iCloud Services" "$ACT_D"
revert_if_changed "aaaaad" "iCloud Services" "$PRE_AAAAAD"

POST_AAAAAC=$(state_for "aaaaac")
POST_AAAAAD=$(state_for "aaaaad")
echo
echo "==== final state ===="
echo "groups.aaaaac.isActive = $POST_AAAAAC  (was $PRE_AAAAAC)"
echo "groups.aaaaad.isActive = $POST_AAAAAD  (was $PRE_AAAAAD)"
if [[ "$POST_AAAAAC" == "$PRE_AAAAAC" && "$POST_AAAAAD" == "$PRE_AAAAAD" ]]; then
  echo "OK: state preserved"
else
  echo "WARNING: state did not return to baseline. Inspect manually in LS GUI."
fi
