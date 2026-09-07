#!/usr/bin/env bash
#
# A whole ICRC-167 return trip on a real Android system, without Internet Identity.
#
# The app starts an attempt and reports the session key it wants a delegation for. A
# stand-in signer produces a genuinely signed delegation over that key. The answer is
# delivered as an App Link, and the app has to parse the fragment, verify the chain and
# derive a principal — which must be the one the signer's root key implies.
#
# The app is force-stopped in between on purpose. On a real device the browser owns the
# foreground for as long as the user takes to authenticate, so the attempt has to be
# reconstructed from storage rather than found in memory.
#
set -euo pipefail

PKG="io.github.yasumorishima.icrc167.probe"
HOST="icrc167-probe.invalid"
CALLBACK="https://${HOST}/auth"
TAG="ICRC167AUTH"

fail() { echo "::error::$1"; adb logcat -d -s "${TAG}:I" | tail -20; exit 1; }

await() {
  for _ in $(seq 1 30); do
    if adb logcat -d -s "${TAG}:I" | grep -qE "$1"; then return 0; fi
    sleep 1
  done
  return 1
}

echo "== installing =="
gradle --no-daemon :probe:assembleDebug
adb install -r probe/build/outputs/apk/debug/probe-debug.apk
# .invalid can never pass Digital Asset Links verification, so approve the domain the way a
# user would. Link routing then behaves as it does for a verified one.
adb shell pm set-app-links-user-selection --user 0 --package "$PKG" true "$HOST" >/dev/null 2>&1 || true

echo
echo "== 1. the app starts an attempt =="
adb logcat -c
adb shell am start -n "${PKG}/.AuthProbeActivity" >/dev/null
await 'BEGIN\|' || fail "the app never reported a started attempt"

BEGIN="$(adb logcat -d -s "${TAG}:I" | grep -o 'BEGIN|.*' | head -1)"
echo "    $BEGIN"
PUBKEY="$(printf %s "$BEGIN" | sed -E 's/.*pubkey=([^|]*)\|.*/\1/')"
REQUEST_ID="$(printf %s "$BEGIN" | sed -E 's/.*\|id=([^|]*)\|.*/\1/')"
STATE="$(printf %s "$BEGIN" | sed -E 's/.*\|state=(.*)$/\1/')"
[ -n "$PUBKEY" ] && [ -n "$REQUEST_ID" ] && [ -n "$STATE" ] || fail "could not read the attempt back"

echo
echo "== 2. the process is reclaimed while the browser is in front =="
adb shell am force-stop "$PKG"

echo
echo "== 3. the stand-in signer answers =="
gradle --no-daemon -q :fake-signer:run \
  --args="${CALLBACK} ${PUBKEY} ${REQUEST_ID} ${STATE}" > signer-output.txt
URL="$(grep '^CALLBACK_URL=' signer-output.txt | head -1 | cut -d= -f2-)"
EXPECTED="$(grep '^EXPECTED_PRINCIPAL=' signer-output.txt | head -1 | cut -d= -f2-)"
[ -n "$URL" ] && [ -n "$EXPECTED" ] || fail "the signer produced no answer"
echo "    expected principal: $EXPECTED"

echo
echo "== 4. delivered as an App Link, into a fresh process =="
adb logcat -c
adb shell "am start -a android.intent.action.VIEW -d '${URL}'" >/dev/null
await 'SUCCESS\||FAILED\|' || fail "the app never reported an outcome"
adb logcat -d -s "${TAG}:I" | sed 's/^/    /'

if adb logcat -d -s "${TAG}:I" | grep -qF 'FAILED|'; then
  fail "the app rejected a valid delegation"
fi
ACTUAL="$(adb logcat -d -s "${TAG}:I" | grep -o 'SUCCESS|principal=[a-z0-9-]*' | head -1 | cut -d= -f2)"
[ "$ACTUAL" = "$EXPECTED" ] || fail "principal mismatch: expected $EXPECTED, got $ACTUAL"

echo
echo "PASS — the app rebuilt the attempt after being killed, verified the delegation,"
echo "       and derived $ACTUAL, which is the principal of the signer's root key."
