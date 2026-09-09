#!/usr/bin/env bash
# Exercises the "is every check on this head green" gate in the Dependabot
# auto-merge workflow.
#
# The lines are lifted out of the workflow itself rather than copied here. A test
# that re-implemented the gate would keep passing after the workflow drifted away
# from it, which is the failure this whole gate exists to prevent: pull request
# #13 was merged on a green CI while `Device tests` was failing.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="$root/.github/workflows/dependabot-auto-merge.yml"

block="$(awk '/# verdict:begin/ { on = 1; next } /# verdict:end/ { on = 0 } on' "$workflow" \
         | sed 's/^          //')"
if [ -z "${block//[[:space:]]/}" ]; then
  echo "could not find the verdict block in $workflow" >&2
  exit 1
fi
# Guard against lifting something that no longer decides anything.
for needle in 'check_runs' 'completed' 'success'; do
  case "$block" in
    *"$needle"*) ;;
    *) echo "the verdict block no longer mentions '$needle'; is it still the gate?" >&2; exit 1 ;;
  esac
done

failed=0

# The gate falls through when it is happy, so the marker below says "would merge".
verdict() {
  raw="$1" GITHUB_RUN_ID="${2:-999}" HEAD_SHA=deadbeef \
    bash -c "$block"$'\n''echo would-merge' 2>&1
}

expect() {
  local name="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    printf 'ok    %s\n' "$name"
  else
    printf 'FAIL  %s\n        got:  %s\n        want: %s\n' "$name" "$got" "$want"
    failed=1
  fi
}

# What pull request #13 actually looked like when it was merged.
expect "a red check blocks the merge" \
  "not green: Device tests(failure) ; doing nothing" \
  "$(verdict '{"check_runs":[
      {"status":"completed","conclusion":"success","name":"JVM modules"},
      {"status":"completed","conclusion":"failure","name":"Device tests"},
      {"status":"completed","conclusion":"skipped","name":"Callback origin contract"}]}')"

expect "all green merges, and a skipped job does not count against it" \
  "would-merge" \
  "$(verdict '{"check_runs":[
      {"status":"completed","conclusion":"success","name":"JVM modules"},
      {"status":"completed","conclusion":"success","name":"Device tests"},
      {"status":"completed","conclusion":"skipped","name":"Callback origin contract"}]}')"

# CI finishes in a minute or two; the emulator takes half an hour. Whichever
# lands last is the one that merges.
expect "a check still running defers to the run that finishes it" \
  "still running: Device tests ; leaving the merge to whichever finishes last" \
  "$(verdict '{"check_runs":[
      {"status":"completed","conclusion":"success","name":"JVM modules"},
      {"status":"in_progress","conclusion":null,"name":"Device tests"}]}')"

expect "cancelled is not success" \
  "not green: Device tests(cancelled) ; doing nothing" \
  "$(verdict '{"check_runs":[
      {"status":"completed","conclusion":"success","name":"JVM modules"},
      {"status":"completed","conclusion":"cancelled","name":"Device tests"}]}')"

expect "timed out is not success" \
  "not green: Device tests(timed_out) ; doing nothing" \
  "$(verdict '{"check_runs":[
      {"status":"completed","conclusion":"timed_out","name":"Device tests"}]}')"

expect "no checks at all is refused rather than assumed green" \
  "no checks reported for deadbeef; doing nothing" \
  "$(verdict '{"check_runs":[]}')"

# A workflow_run job reports against the default branch, so this workflow should
# never appear in its own list. If that ever changes it must not deadlock.
expect "this workflow does not block itself" \
  "would-merge" \
  "$(verdict '{"check_runs":[
      {"status":"completed","conclusion":"success","name":"JVM modules"},
      {"status":"in_progress","conclusion":null,"name":"merge",
       "details_url":"https://github.com/o/r/actions/runs/999/job/1"}]}')"

exit "$failed"
