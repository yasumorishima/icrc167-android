#!/usr/bin/env bash
# Every check that needs the emulator, run to the end even when one of them fails.
#
# The emulator runner stops at the first failing line of its script, so a red instrumented test
# used to hide what the fragment probe and the round trip would have said. Each check here runs
# regardless, and the job fails at the end if any of them did.
set -uo pipefail

failed=()

run() {
  local name="$1"
  shift
  echo
  echo "=== $name ==="
  if ! "$@"; then
    failed+=("$name")
  fi
}

# The timing test logs rather than asserts, so its numbers reach the CI log only through here.
# Printed straight after the instrumented tests, before anything clears logcat.
print_timing() {
  local lines
  lines="$(adb logcat -d -s ICRC167_TIMING:I | grep "ICRC167_TIMING cold_ms=" || true)"
  if [ -z "$lines" ]; then
    echo "no timing line in logcat"
    return 1
  fi
  echo "$lines"
}

run "instrumented tests" gradle --no-daemon --stacktrace :icrc167-android:connectedDebugAndroidTest
run "verification timing" print_timing
run "fragment probe" bash scripts/fragment-probe.sh
run "authentication round trip" bash scripts/auth-roundtrip.sh

if [ "${#failed[@]}" -gt 0 ]; then
  echo "::error::failed: ${failed[*]}"
  exit 1
fi
echo "every device check passed"
