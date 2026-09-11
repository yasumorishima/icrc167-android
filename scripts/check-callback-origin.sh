#!/usr/bin/env bash
# Reads the two documents an ICRC-167 callback origin has to serve, the way the two things
# that consume them read them: Internet Identity fetches the callback list cross-origin and
# fails closed on a redirect, a wrong content type or a missing CORS header, and Android
# fetches assetlinks.json to decide whether the app may claim the link.
#
# One copy, called from both the CI job that measures a live origin and the deploy job that
# has just published one. Two copies is how they stop agreeing.
#
#   check-callback-origin.sh <origin> [expected-callbacks-json] [expected-assetlinks-json]
#
# With the second argument, the served list is compared against that file, which is what ties
# a deploy to the thing that was deployed rather than to whatever was already there. With the
# third, the served assetlinks.json is held to that file the same way.
set -euo pipefail

origin="${1:?usage: check-callback-origin.sh <origin> [expected-callbacks-json] [expected-assetlinks-json]}"
expected="${2:-}"
expected_links="${3:-}"
origin="${origin%/}"

fail() { echo "::error::$*"; exit 1; }
warn() { echo "::warning::$*"; }

body="$(mktemp)"
links="$(mktemp)"
trap 'rm -f "$body" "$links"' EXIT

echo "== ${origin}/.well-known/ii-auth-callbacks"
# The signer asks from its own origin. A rule that only answers same-origin requests would
# pass a plain fetch here and still fail at sign-in.
headers="$(curl -sS -D - -o "$body" -H "Origin: https://id.ai" --max-time 20 \
  "${origin}/.well-known/ii-auth-callbacks")"
echo "$headers"
echo "$headers" | head -1 | grep -q " 200 " || fail "expected 200, and no redirect"
echo "$headers" | grep -iq "^content-type: *application/json" \
  || fail "content-type must be application/json"
echo "$headers" | grep -iq "^access-control-allow-origin:" \
  || fail "the signer must be able to read this cross-origin"
echo "$headers" | grep -iq "^cache-control:.*no-store" \
  || warn "no-store is not set; the signer must see the current list"

size="$(wc -c < "$body")"
[ "$size" -le 8192 ] || fail "$size bytes is over the 8 KiB the signer reads"
jq -e '.callbacks | type == "array" and length > 0' "$body" > /dev/null \
  || fail "callbacks must be a non-empty array"
jq -e --arg o "$origin" 'all(.callbacks[]; startswith($o + "/"))' "$body" > /dev/null \
  || fail "a callback entry is not on this origin"

if [ -n "$expected" ]; then
  [ -s "$expected" ] || fail "$expected is missing or empty"
  diff <(jq -S . "$expected") <(jq -S . "$body") \
    || fail "the origin is serving a different callback list than the one in this commit"
  echo "served list matches $expected"
fi

echo "== ${origin}/.well-known/assetlinks.json"
headers="$(curl -sS -D - -o "$links" --max-time 20 "${origin}/.well-known/assetlinks.json")"
echo "$headers"
echo "$headers" | head -1 | grep -q " 200 " || fail "expected 200, and no redirect"
jq -e '.[0].target.package_name' "$links" > /dev/null || fail "no package_name in assetlinks.json"
# jq is happy with the template too, and a template here means Android will not route the
# callback into the app. Internet Identity does not read this file, so it is not fatal.
if grep -q REPLACE "$links"; then
  warn "assetlinks.json is still the template: Android will not hand the callback to the app"
fi

if [ -n "$expected_links" ]; then
  [ -s "$expected_links" ] || fail "$expected_links is missing or empty"
  if ! diff <(jq -S . "$expected_links") <(jq -S . "$links"); then
    fail "the origin is serving a different assetlinks.json than the one in this commit"
  fi
  echo "served assetlinks.json matches $expected_links"
fi

echo "both documents read back as the signer and the platform will read them"
