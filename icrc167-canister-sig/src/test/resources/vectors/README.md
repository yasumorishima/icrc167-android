# Certificate and canister-signature test vectors

Known answers, none of them produced by this repository. That matters more here than usual: the
principal a canister signature yields is derived from the public key that arrives in the same
response, so an implementation that skipped verification altogether would still agree with
itself. Only somebody else's signature, and the negative cases built from it, say anything.

## `live-*` — a certificate the IC issued

| file | what it is |
| --- | --- |
| `live-certificate.hex` | the `certificate=:…:` field of the `IC-Certificate` response header from `https://id.ai/`, captured 2026-09-09 |
| `live-canister-id.hex` | the canister that certificate is about, `00000000021000060101`, read out of its own tree |

Captured with:

```
curl -sS -D - -o /dev/null https://id.ai/ | grep -o 'certificate=:[^:]*:'
```

then base64-decoding the value. It verifies against the IC **mainnet** root key, its delegation
uses the sharded `/canister_ranges/<subnet>/<start>` shape, and — the reason it is here — it
carries `/subnet/<subnet_id>/type` = `system`.

That last point is load-bearing. The interface specification says a delegation's subnet type
must be present and must not be `cloud_engine`, and pruning a label is the one edit an attacker
can make to a witness without disturbing the root hash the subnet signed, so "refuse only when
it says `cloud_engine`" would enforce nothing. Verifying the rule is enforceable therefore means
showing that a certificate the network is issuing *today* carries the label; the two
canister-signature vectors below both predate it and cannot answer the question.

A certificate does not expire for the purposes of `verify_cert` — the time in it is a value to
read, not a validity window — so this fixture stays good.

## `ii-*` — a real Internet Identity login on mainnet, February 2024

Taken verbatim from `DELEGATION_CHAIN_JSON` in
[`dfinity/internet-identity`](https://github.com/dfinity/internet-identity),
`src/sig-verifier-js/src/lib.rs`.

| file | what it is |
| --- | --- |
| `ii-public-key.hex` | the canister-signature public key: canister `fgte5-ciaaa-aaaad-aaatq-cai`, 32-byte seed |
| `ii-signature.hex` | the canister signature over the chain's one delegation |
| `ii-challenge.hex` | the key the delegation is issued to (`CHALLENGE_HEX` in the same file) |

Expiration `1708469015156620577`; the identity is
`hf7wk-a35mp-bc6eb-ntvr2-aeu3d-naglw-n6ea3-qn5ps-jcanu-p2vro-5ae`. Its delegation carries the
whole canister range in one blob at `/subnet/<id>/canister_ranges`, the older of the two shapes.

It is signed two years before `/subnet/<id>/type` existed, so it is **refused**, and the tests
assert *where*: it passes CBOR, the canister's own witness, the delegation's BLS signature under
the real mainnet root key and the canister ranges, and stops at the missing type.

## `sharded-*` — DFINITY's vector for the current canister-ranges shape

Taken from `should_accept_canister_sig_with_new_cert_format` in
[`dfinity/ic`](https://github.com/dfinity/ic),
`packages/ic-signature-verification/tests/verify_canister_sig.rs`.

| file | what it is |
| --- | --- |
| `sharded-signature.hex` | the canister signature |
| `sharded-public-key.hex` | the canister-signature public key |
| `sharded-message.hex` | the message it signs |
| `sharded-root-key.hex` | the root key it was produced under — a test network's, **not** mainnet's |

Its delegation shards the ranges and carries no subnet type either, so it too is refused there
and the tests say so. Its ranges blob is what `CanisterRangesTest` decodes.

## Regenerating

`scripts/make-vectors.py` extracts the `ii-*` and `sharded-*` files from those two upstream
sources rather than transcribing them. The `live-*` files are a capture and cannot be
regenerated identically; recapture with the command above if a fresher one is ever wanted.
