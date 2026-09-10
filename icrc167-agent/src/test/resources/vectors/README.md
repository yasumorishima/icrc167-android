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
