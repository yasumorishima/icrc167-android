# Vectors

Both files are verbatim response bodies from mainnet, captured on 2026-09-10 with a
throwaway script (not with this library, so they can measure it).

| file | how it was produced |
| --- | --- |
| `whoami-anonymous-reply.cbor` | `whoami` on `kvusz-kaaaa-aaaad-aabwa-cai`, called anonymously through `https://icp-api.io/api/v2/canister/<id>/query`. The reply is the anonymous principal `2vxsx-fae`. |
| `rejected-reply.cbor` | the same canister, method `no_such_method_here`. Reject code 5, error code `IC0536`. |

Both arrive as CBOR tag 55799 wrapping an **indefinite-length** map, which is why this module
has its own reader instead of the strict one in `icrc167-certificate`.

The envelope hex strings in `EnvelopeTest` come from the same script, with fixed key seeds and
a fixed `ingress_expiry` so they are reproducible. That expiry is **not** the one the live
calls used, and mainnet would refuse it outright: it is a constant chosen for the fixture,
while the live calls used an expiry a few minutes ahead of the moment they were sent. The unfixed version of exactly those three envelopes
was accepted by mainnet on the same day, and a fourth with the signature moved to the wrong
key was refused with `Invalid signature` -- so the shape is measured, not assumed.

## The response-signature vectors

Captured the same way on 2026-09-10, by the same throwaway script, and they are what makes
`ResponseVerificationTest` a measurement rather than a restatement.

| file | what it is |
| --- | --- |
| `signed-request.hex` | the envelope of an anonymous `whoami` query |
| `signed-request-id.hex` | the request id of that content, computed independently |
| `signed-reply.cbor` | the answer, including the node signature |
| `subnet-certificate.cbor` | the certificate from a separate `read_state` of `/subnet`, carrying the node public keys |
| `response-hash.hex` | the digest the node signature covers, computed independently |
| `rejected-*` | the same five for a call to a method that does not exist |

The rejected set exists to settle one question the specification leaves open by wording:
`error_code` is optional, and the live signature verifies **only** when it is included in the
hashed map. Nothing here expires cryptographically -- the BLS signature over a certificate stays valid --
but the verifier refuses answers that are not recent, so the tests run it with the clock set
to the moment each answer was signed. A recording that verified without that would mean the
recency check was not there.

The delegation inside `subnet-certificate.cbor` was already about five minutes older than the
answer when it was recorded, which is how the two windows the specification asks for got
noticed: a single five-minute window put that recording seconds away from failing for ever.
