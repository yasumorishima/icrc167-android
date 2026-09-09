#!/usr/bin/env python3
"""Regenerates the canister-signature test vectors from the upstream files they come from.

The point of these vectors is that somebody else produced them, so they are extracted from
DFINITY's own sources rather than transcribed. Run this to check that the checked-in copies
still match upstream:

    python3 scripts/make-vectors.py && git diff --exit-code
"""
import json
import os
import re
import sys
import urllib.request

SOURCES = {
    "ii": "https://raw.githubusercontent.com/dfinity/internet-identity/main/"
          "src/sig-verifier-js/src/lib.rs",
    "sharded": "https://raw.githubusercontent.com/dfinity/ic/master/"
               "packages/ic-signature-verification/tests/verify_canister_sig.rs",
}

OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "icrc167-canister-sig", "src", "test", "resources", "vectors",
)

# From the same Internet Identity test. Asserted here so a changed vector is noticed as a
# changed vector, and not as a mysteriously failing verifier.
II_EXPIRATION = 1708469015156620577


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def write(name, value):
    value = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", value) or len(value) % 2:
        sys.exit("%s is not a whole number of hex bytes" % name)
    lines = [value[i:i + 64] for i in range(0, len(value), 64)]
    with open(os.path.join(OUT, name + ".hex"), "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("%-22s %5d bytes" % (name, len(value) // 2))


def main():
    os.makedirs(OUT, exist_ok=True)

    source = fetch(SOURCES["ii"])
    match = re.search(r'DELEGATION_CHAIN_JSON: &str = r#"(.*?)"#;', source, re.S)
    if not match:
        sys.exit("could not find DELEGATION_CHAIN_JSON; upstream has moved it")
    chain = json.loads(match.group(1))
    delegation = chain["delegations"][0]
    if int(delegation["delegation"]["expiration"], 16) != II_EXPIRATION:
        sys.exit("the Internet Identity vector changed; update II_EXPIRATION and the tests")
    write("ii-public-key", chain["publicKey"])
    write("ii-signature", delegation["signature"])
    write("ii-challenge", delegation["delegation"]["pubkey"])

    source = fetch(SOURCES["sharded"])
    marker = "fn should_accept_canister_sig_with_new_cert_format"
    if marker not in source:
        sys.exit("could not find %s; upstream has moved it" % marker)
    block = source[source.index(marker):]
    found = re.findall(r'hex::decode\(\s*"([0-9a-f]+)"\s*\)', block)
    if len(found) < 4:
        sys.exit("expected four hex literals in that test, found %d" % len(found))
    # In source order: the signature, the public key, the message, the root key.
    for name, value in zip(
        ["sharded-signature", "sharded-public-key", "sharded-message", "sharded-root-key"],
        found[:4],
    ):
        write(name, value)


if __name__ == "__main__":
    main()
