#!/usr/bin/env bash
# Checks that an APK is the package assetlinks.json names and is signed with the certificate it
# names. Android verifies an App Link by exactly this comparison, and silently: a mismatch fails
# nothing, the callback just stays in the browser. So it is measured here instead.
#
#   demo-signing-check.sh <apk> <assetlinks.json> [--expect-mismatch]
#
# --expect-mismatch inverts the verdict. The release workflow runs it on the debug build, whose
# key is not the release key, to show that the comparison can fail at all.
set -euo pipefail

usage="usage: demo-signing-check.sh <apk> <assetlinks.json> [--expect-mismatch]"
apk="${1:?$usage}"
links="${2:?$usage}"
mode="${3:-}"

fail() { echo "::error::$*"; exit 1; }

[ -s "$apk" ] || fail "$apk is missing or empty"
[ -s "$links" ] || fail "$links is missing or empty"
if grep -q REPLACE "$links"; then fail "$links is still the template"; fi

tools="$(ls -d "$ANDROID_HOME"/build-tools/*/ | sort -V | tail -1)"

want_package="$(jq -r '.[0].target.package_name' "$links")"
want_digest="$(jq -r '.[0].target.sha256_cert_fingerprints[0]' "$links" | tr -d ':' | tr 'A-F' 'a-f')"
[ "${#want_digest}" -eq 64 ] || fail "the fingerprint in $links is not 32 bytes of hex"

package="$("${tools}aapt2" dump packagename "$apk")"
certs="$("${tools}apksigner" verify --print-certs "$apk")"
signers="$(printf '%s' "$certs" | grep -c '^Signer #[0-9]* certificate SHA-256 digest:' || true)"
[ "$signers" -eq 1 ] || fail "expected exactly one signer, found $signers"
digest="$(printf '%s' "$certs" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p')"

echo "apk:        $package $digest"
echo "assetlinks: $want_package $want_digest"

match=no
if [ "$package" = "$want_package" ] && [ "$digest" = "$want_digest" ]; then match=yes; fi

if [ "$mode" = "--expect-mismatch" ]; then
  [ "$match" = no ] || fail "$apk matches assetlinks.json, but it was expected not to"
  echo "does not match, as expected"
else
  [ "$match" = yes ] || fail "$apk is not what assetlinks.json names, so Android would leave the callback in the browser"
  echo "matches: Android can hand the callback to this APK"
fi
