#!/usr/bin/env bash
#
# Does the URL fragment survive an Android App Link hand-off?
#
# ICRC-167 returns the delegation in the fragment and nowhere else, so if Android dropped or
# rewrote it, the transport could not be implemented on this platform. intent-filter matching
# ignores the fragment entirely, which is a good reason to check rather than assume.
#
# Two measurements, because they answer different questions:
#   A. explicit component  -> does an Intent carry the fragment at all?
#   B. implicit VIEW       -> does link routing deliver it to us, rather than the browser?
#
set -euo pipefail

PKG="io.github.yasumorishima.icrc167.probe"
HOST="icrc167-probe.invalid"
TAG="ICRC167PROBE"

# A response shaped like a real one: percent-encoded JSON containing the characters that a
# careless codec mangles ('&', '=', '+', '/', '%').
MESSAGE='{"jsonrpc":"2.0","id":"probe-1","result":{"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE","signerDelegation":[{"delegation":{"pubkey":"MCowBQYDK2VwAyEA","expiration":"1799999999000000000"},"signature":"2dn3omtjZXJ0aWZpY2F0ZQ=="}]}}'
STATE='s+t/a=te&x'

FRAGMENT="$(python3 - "$MESSAGE" "$STATE" <<'PY'
import sys, urllib.parse
print(urllib.parse.urlencode({"message": sys.argv[1], "state": sys.argv[2]}), end="")
PY
)"
EXPECTED_SHA="$(printf %s "$FRAGMENT" | sha256sum | cut -d' ' -f1)"
EXPECTED_LEN="$(printf %s "$FRAGMENT" | wc -c | tr -d ' ')"
URL="https://${HOST}/cb#${FRAGMENT}"

echo "fragment length : $EXPECTED_LEN"
echo "fragment sha256 : $EXPECTED_SHA"

echo "== building and installing =="
gradle --no-daemon :probe:assembleDebug
adb install -r probe/build/outputs/apk/debug/probe-debug.apk

wait_for_log() {
  for _ in $(seq 1 30); do
    if adb logcat -d -s "${TAG}:I" | grep -qF 'FRAGMENT'; then return 0; fi
    sleep 1
  done
  return 1
}

observed_sha() {
  adb logcat -d -s "${TAG}:I" | grep -oE 'sha256=[0-9a-f]{64}' | head -1 | cut -d= -f2
}

fail() { echo "::error::$1"; adb logcat -d -s "${TAG}:I" | tail -20; exit 1; }

echo
echo "== A. explicit component =="
adb logcat -c
adb shell "am start -n ${PKG}/.ProbeActivity -a android.intent.action.VIEW -d '${URL}'" >/dev/null
wait_for_log || fail "the probe activity logged nothing for the explicit start"
adb logcat -d -s "${TAG}:I" | sed 's/^/    /'

if adb logcat -d -s "${TAG}:I" | grep -qF 'FRAGMENT_ABSENT'; then
  fail "A: Android delivered the Intent without a fragment — ICRC-167 cannot work this way"
fi
ACTUAL_SHA="$(observed_sha)"
[ -n "$ACTUAL_SHA" ] || fail "A: no digest in the log"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  fail "A: fragment changed in transit. sent $EXPECTED_SHA, received $ACTUAL_SHA"
fi
echo "A: PASS — fragment arrived byte for byte ($EXPECTED_LEN bytes)"

echo
echo "== B. implicit VIEW through link routing =="
# The host is a reserved .invalid name, so Digital Asset Links verification can never
# succeed for it. Approving the domain as a user selection is the supported way to make
# the router behave as it would for a verified one, without inventing a real domain.
adb shell pm set-app-links-user-selection --user 0 --package "$PKG" true "$HOST" >/dev/null 2>&1 || true
adb shell pm get-app-links "$PKG" | sed 's/^/    /' || true

adb logcat -c
adb shell "am start -a android.intent.action.VIEW -d '${URL}'" >/dev/null
if ! wait_for_log; then
  fail "B: the link did not reach the app — it stayed with another handler"
fi
adb logcat -d -s "${TAG}:I" | sed 's/^/    /'
ACTUAL_SHA="$(observed_sha)"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  fail "B: fragment changed in transit. sent $EXPECTED_SHA, received $ACTUAL_SHA"
fi
echo "B: PASS — link routing delivered the fragment unchanged"

echo
echo "Both paths preserved the fragment. ICRC-167's return channel is viable on Android."
