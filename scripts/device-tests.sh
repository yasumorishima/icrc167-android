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

# Android Gradle plugin 9 stopped printing "Finished N tests", so the only record of how many
# instrumented tests ran is the JUnit XML it writes. A run with fewer test cases than the source
# declares, or with any failure, error or skip, fails here rather than passing quietly.
count_tests() {
  local expected xmls cases=0 bad=0 skipped=0 x
  expected="$(grep -rhE '^\s*@Test\b' icrc167-android/src/androidTest --include='*.kt' | wc -l)"
  mapfile -t xmls < <(find icrc167-android/build -path '*androidTest-results*' -name 'TEST-*.xml')
  if [ "${#xmls[@]}" -eq 0 ]; then
    echo "no JUnit XML under icrc167-android/build/**/androidTest-results"
    return 1
  fi
  for x in "${xmls[@]}"; do
    echo "$x"
    cases=$((cases + $(grep -o '<testcase ' "$x" | wc -l)))
    bad=$((bad + $(grep -oE '<(failure|error)[ >]' "$x" | wc -l)))
    skipped=$((skipped + $(grep -oE '<skipped' "$x" | wc -l)))
  done
  echo "$cases test cases ran, $expected declared; $bad failed, $skipped skipped"
  [ "$cases" -eq "$expected" ] && [ "$bad" -eq 0 ] && [ "$skipped" -eq 0 ]
}

# The timing test's numbers reach the CI log only through here.
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

# Start from an empty logcat, so the timing line below can only have come from this run.
adb logcat -c || true
run "instrumented tests" gradle --no-daemon --stacktrace :icrc167-android:connectedDebugAndroidTest
run "instrumented test count" count_tests
run "verification timing" print_timing
run "fragment probe" bash scripts/fragment-probe.sh
run "authentication round trip" bash scripts/auth-roundtrip.sh

if [ "${#failed[@]}" -gt 0 ]; then
  echo "::error::failed: ${failed[*]}"
  exit 1
fi
echo "every device check passed"
