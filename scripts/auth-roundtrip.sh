#!/usr/bin/env bash
#
# ICRC-167 return trips on a real Android system, without Internet Identity.
#
# A stand-in signer produces genuinely signed delegations over the session key the app asked
# for, and the answers are delivered as App Links. Four cases, because a passing positive
# case on its own proves almost nothing here: the principal is derived from the root public
# key in the response, so it would still match if signature checking were removed entirely.
#
#   A. a forged `state` is refused, and does not burn the sign-in the user is in the middle of
#   B. the same attempt then completes, across a process kill
#   C. a delegation whose signature does not check out is refused
#   D. a chain rooted in a canister signature reaches the verifier that can judge one
#
set -euo pipefail

PKG="io.github.yasumorishima.icrc167.probe"
HOST="icrc167-probe.invalid"
CALLBACK="https://${HOST}/auth"
TAG="ICRC167AUTH"
LOG="logcat.txt"

fail() {
  echo "::error::$1"
  if [ -f "$LOG" ]; then sed 's/^/    /' "$LOG"; fi
  exit 1
}

# `adb logcat | grep -q` returns 141 under pipefail, because grep exits first and adb takes
# SIGPIPE. Dump to a file and grep that.
dump() { adb logcat -d -s "${TAG}:I" > "$LOG"; }

await() {
  for _ in $(seq 1 30); do
    dump
    if grep -qE "$1" "$LOG"; then return 0; fi
    sleep 1
  done
  return 1
}

pid_of() { adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' || true; }

begin_attempt() {
  adb logcat -c
  adb shell am start -n "${PKG}/.AuthProbeActivity" >/dev/null
  await 'BEGIN\|' || fail "the app never reported a started attempt"
  local line
  line="$(grep -o 'BEGIN|.*' "$LOG" | tail -1)"
  echo "    $line"
  PUBKEY="$(printf %s "$line" | sed -E 's/.*pubkey=([^|]*)\|.*/\1/')"
  REQUEST_ID="$(printf %s "$line" | sed -E 's/.*\|id=([^|]*)\|.*/\1/')"
  STATE="$(printf %s "$line" | sed -E 's/.*\|state=(.*)$/\1/')"
  [ -n "$PUBKEY" ] && [ -n "$REQUEST_ID" ] && [ -n "$STATE" ] \
    || fail "could not read the attempt back"
}

# $1 = mode. Sets URL and EXPECTED.
answer() {
  gradle --no-daemon -q :fake-signer:run \
    --args="${CALLBACK} ${PUBKEY} ${REQUEST_ID} ${STATE} $1" > "signer-$1.txt"
  URL="$(grep '^CALLBACK_URL=' "signer-$1.txt" | head -1 | cut -d= -f2-)"
  EXPECTED="$(grep '^EXPECTED_PRINCIPAL=' "signer-$1.txt" | head -1 | cut -d= -f2-)"
  [ -n "$URL" ] && [ -n "$EXPECTED" ] || fail "the signer produced no answer for mode $1"
}

deliver() {
  adb logcat -c
  adb shell "am start -a android.intent.action.VIEW -d '$1'" >/dev/null
  await 'SUCCESS\||FAILED\||NOT_OURS' || fail "the app never reported an outcome"
  sed 's/^/    /' "$LOG"
}

echo "== installing =="
gradle --no-daemon :probe:assembleDebug
# Uninstall first: `install -r` keeps app data, so the first-run path that mints a session
# key would never be exercised.
adb uninstall "$PKG" >/dev/null 2>&1 || true
adb install probe/build/outputs/apk/debug/probe-debug.apk
adb shell pm set-app-links-user-selection --user 0 --package "$PKG" true "$HOST" >/dev/null 2>&1 || true

echo
echo "== A. an answer carrying somebody else's state =="
begin_attempt
PID_BEFORE="$(pid_of)"
[ -n "$PID_BEFORE" ] || fail "the app is not running after starting an attempt"
echo "    pid while the attempt was made: $PID_BEFORE"

adb shell am force-stop "$PKG"
[ -z "$(pid_of)" ] || fail "force-stop did not actually kill the app"
echo "    process killed, as it would be while the browser is in front"

answer wrong-state
deliver "$URL"
grep -q 'FAILED|' "$LOG" || fail "A: a forged state was not refused"
grep -q 'FAILED|.*state' "$LOG" || fail "A: refused, but not because of the state"
echo "A: PASS — refused"

echo
echo "== B. the same attempt still completes =="
# The forged answer above must not have consumed the pending sign-in.
answer valid
deliver "$URL"
if grep -q 'FAILED|' "$LOG"; then fail "B: the app rejected a valid delegation"; fi
ACTUAL="$(grep -o 'SUCCESS|principal=[a-z0-9-]*' "$LOG" | head -1 | cut -d= -f2)"
[ "$ACTUAL" = "$EXPECTED" ] || fail "B: principal mismatch: expected $EXPECTED, got $ACTUAL"
PID_AFTER="$(pid_of)"
[ -n "$PID_AFTER" ] && [ "$PID_AFTER" != "$PID_BEFORE" ] \
  || fail "B: expected a new process, saw '$PID_AFTER' against '$PID_BEFORE'"
echo "B: PASS — completed in pid $PID_AFTER (was $PID_BEFORE), principal $ACTUAL"

echo
echo "== C. a delegation whose signature does not check out =="
begin_attempt
answer bad-signature
deliver "$URL"
grep -q 'FAILED|' "$LOG" || fail "C: a forged signature was accepted"
grep -q 'BadSignature' "$LOG" || fail "C: refused, but not because of the signature"
echo "C: PASS — refused"

echo
echo "== D. a chain rooted in a canister signature =="
# Every real Internet Identity chain looks like this at hop 0. The signature here cannot be
# valid, so what matters is who refuses it. UnsupportedKey is what the client's default used
# to say -- for this chain and for every genuine one, so no real sign-in could complete.
begin_attempt
answer canister-root
deliver "$URL"
grep -q 'FAILED|' "$LOG" || fail "D: a canister signature that cannot be valid was accepted"
if grep -q 'UnsupportedKey' "$LOG"; then
  fail "D: nothing recognised the canister-signature key, so a real chain would be refused too"
fi
grep -q 'BadSignature(index=0)' "$LOG" || fail "D: refused, but not by the canister-signature verifier at hop 0"
echo "D: PASS — the canister-signature verifier judged hop 0"

echo
echo "All four hold: the client refuses a forged state without losing the attempt, completes"
echo "it in a fresh process, refuses a delegation whose signature does not verify, and hands a"
echo "canister-signature root to the verifier that can judge it."
