# icrc167-android

Internet Identity login for native **Android** apps, with no bridge server.

This implements the relying-party side of **ICRC-167 (Browser URL Transport)** — the mechanism
that lets a native app hand a user to Internet Identity in the browser and get a delegation
back, without a `postMessage` channel and without hosting a relay of your own.

An iOS implementation already exists ([`ICNativeClient`](https://github.com/humandebri/ICNativeClient),
Swift). This is the Android counterpart.

## Status

**Early, but the whole verification path is now there.** A real Internet Identity chain is
rooted in an IC canister signature, and checking one of those is checking a state-tree
certificate against the network root key — that is implemented, against the specification and
against certificates the IC actually issues. What has not happened yet is a round trip with a
real passkey on a real device.

| | |
|---|---|
| Request/response codec, `state` and id binding, replay refusal | done, tested |
| Delegation chain verification (walk, expiry, scope, session-key binding) | done, tested |
| Granted-scope checking against the request | done, tested |
| Ed25519 and ECDSA P-256 (IEEE P1363) signature verification | done, tested |
| Certificate machinery: CBOR reader, state-tree witness | done, tested |
| Canister-signature verification (BLS12-381, certificate chain, subnet scope) | done, tested |
| Android module (Custom Tabs, App Links, key storage) | done, exercised on an emulator |
| Calling a canister as the identity you were handed | done, round-tripped against mainnet |
| Checking the node signature on a query response | done, verified to the network root key |
| Callback origin (the two well-known documents) | live, and read back on every deploy |
| Demo app | not yet |

### Modules

| | |
|---|---|
| `icrc167-core` | The transport, delegation chains, principals. The only dependency it ships is `org.json`, and that is `compileOnly` because Android ships it — so its version has to match what the platform provides, and Dependabot is told to leave it alone. Compiling against a newer one links on a desktop JVM and fails on a device. |
| `icrc167-crypto` | Ed25519 and ECDSA P-256 signature verification, behind the interface the core injects. |
| `icrc167-certificate` | CBOR, the state-tree witness, and certificate verification. No dependencies at all: the pairing check arrives as an interface. |
| `icrc167-canister-sig` | That pairing check, over a vendored MIRACL Core, plus the canister-signature verifier. The Android module depends on it, because every Internet Identity chain has a canister signature at its root; JVM code that checks no certificate at all, neither a canister signature nor a query response, can leave it out. |
| `icrc167-agent` | The call side: CBOR envelopes, request signing, and just enough Candid to read a principal back. Depends on the core and on the certificate module, to check the node signature on an answer. Neither needs Android, so it runs on a plain JVM as well as in an app. |
| `icrc167-android` | Custom Tabs, App Links, session keys. Checks both signature schemes by default. |

Only the canister-signature module carries the pairing arithmetic. JVM code that checks no
certificate at all, neither a canister signature nor a query response, leaves MIRACL out.

Nothing here has been through a real Internet Identity round trip yet. When it has, this
table will say so. The calls in *Asking a canister who you are* are real ones against mainnet,
but the chain they carry is one this repository signs for itself.

A chain mixes schemes — Internet Identity signs the root hop with a canister signature and
the rest with keys WebCrypto produced — so both verifiers are needed. `Icrc167Client` wires
them together by default; anything else that checks a chain should do the same:

```kotlin
DelegationChainVerifier(
    CompositeSignatureVerifier(StandardSignatureVerifier(), CanisterSignatureVerifier()),
)
```

A verifier that does not recognise a key answers `SignatureCheck.UNSUPPORTED_KEY`, which is
deliberately a different answer from `INVALID`: it is what lets the composite try the next
one. A chain that ends there is rejected as `ChainRejection.UnsupportedKey` rather than
`BadSignature`, so "the check must be broken" is never the obvious conclusion when a scheme is
simply not compiled in.

### What the canister-signature tests can and cannot show

The arithmetic is fixed on RFC 9380's own hash-to-curve vectors, and certificate verification
on a certificate captured from `id.ai` — the real mainnet root key, a real subnet delegation,
the sharded canister ranges, and a set of negative cases built by rewriting that certificate
(most sharply: pruning a label, which leaves the root hash and therefore the signature
untouched, and must still be refused).

The two canister signatures in the public record — DFINITY's own, in `internet-identity` and
in `ic-signature-verification` — are older than the rule that a delegation must state its
subnet's type. The type reached the state tree in `dfinity/portal` `db5ec5e9`
(2026-03-17) and the rule about it in `75816500` (2026-05-05), both later than either
vector. Both are therefore refused, and
the tests assert *where*: each gets through CBOR, the canister's witness, the delegation's BLS
signature under the real root key and the canister ranges, and stops at the missing type. The
accepting path is exercised on certificates built in the tests, with the pairing stubbed. If a
canister signature issued under the current rules turns up, it belongs in
`icrc167-canister-sig/src/test/resources/vectors`.

### Where the state tree is pinned

`lookupPath` keeps *absent* and *unknown* apart. Given a witness with a subtree pruned away,
a path that would have run through it is unproved, not missing; answering "absent" there
accepts an absence the subnet never signed for. The tests use two published witnesses that
describe the same state — the second is the first with parts pruned — so they must
reconstruct to the same root hash, and the same label reads as provably absent in one and
unknown in the other.

### Scope

Requesting `targets` does not guarantee a scoped delegation. Under ICRC-34 a signer that
cannot establish trust for the target canisters falls back to an ordinary relying-party
delegation, which is legitimate and yields a *different principal*. So an unscoped answer is
reported through `Authenticated.effectiveTargets` rather than refused, while a scope wider
than the one requested — authority nobody asked for — is rejected.

### The hash is pinned to the specification, not to itself

The bytes a delegation signature covers are `\x1Aic-request-auth-delegation` followed by the
representation-independent hash of the delegation. Everywhere in a test suite the same
function produces both the signed and the verified bytes, so a hash that disagreed with the
IC would pass every round trip while being useless against a replica. The published
request-id example is checked directly:

```
hash_of_map({request_type: "call", sender: 0x04, ingress_expiry: 1685570400000000000,
             canister_id: 0x00000000000004D2, method_name: "hello", arg: "DIDL\x00\xFD*"})
  = 1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101
```

## The fragment survives the hand-off

ICRC-167 returns the delegation in the URL fragment and nowhere else, while `intent-filter`
matching ignores the fragment entirely — so whether Android preserves it decides whether the
transport is implementable at all. It is measured on an emulator rather than assumed
(`.github/workflows/fragment-probe.yml`), over a realistic percent-encoded payload:

```
sent                         379 bytes  sha256 e17b6549…4850
explicit component start     379 bytes  sha256 e17b6549…4850
implicit VIEW (link routing) 379 bytes  sha256 e17b6549…4850
```

## The round trip runs on a device

A stand-in signer produces a genuinely signed delegation over the session key the app asked
for, and the answer is delivered as an App Link
(`.github/workflows/fragment-probe.yml`). No Internet Identity, no passkey, no network, no
real domain — but every step the app performs is the real one.

There are four cases, and the negative ones carry the weight. **A passing positive case on
its own proves almost nothing here**: the principal is derived from the root public key in
the response, so it would still come out right if signature checking were removed entirely.

```
A. an answer carrying somebody else's state   → refused, attempt survives
B. the same attempt then completes            → SUCCESS, in a different pid
C. a signature that does not check out        → refused, BadSignature
D. a root key naming canister signatures      → refused, BadSignature at hop 0
```

`B` asserts the process id actually changed, and `A` asserts the process was gone before the
answer arrived, so the attempt is demonstrably reconstructed from storage rather than found
in memory. On a real device the browser owns the foreground for as long as the user takes to
authenticate, so that is the only path that matters. That `B` succeeds *after* `A` is what
shows a forged callback cannot burn a sign-in the user is still in the middle of.

`D` is about wiring, not cryptography. Its signature cannot be valid, so the question is only
*who* refuses it: `BadSignature` means the canister-signature verifier took the key,
`UnsupportedKey` means nothing recognised the scheme. Until 2026-09-11 the client's default
gave the second answer — to this chain and to every genuine Internet Identity chain, so no
real sign-in could have completed. Whether a *valid* canister signature issued today is
accepted is a separate question, and only a real sign-in answers it.

What this does *not* establish: that a real Internet Identity round trip works. Verifying
the chain is covered elsewhere — see the canister-signature section above — but nothing here
exercises Custom Tabs, Digital Asset Links verification, or the signer's own callback
matching, and no sign-in with a real passkey has happened yet.

The same run also pins down a trap worth stating plainly. `Uri.getFragment()`
percent-decodes the *whole* fragment before you can split it:

```
encodedFragment  …&state=s%2Bt%2Fa%3Dte%26x
getFragment()    …&state=s+t/a=te&x
```

The `%26` becomes a separator, inventing a parameter that was never sent, and `%2B` becomes
a `+` that the next decode turns into a space. Parse `encodedFragment`, never `getFragment()`.

### The specification is a draft

ICRC-167 is at **IDEA** stage in the identity working group. The spec text lives in an
[open pull request](https://github.com/dfinity/wg-identity-authentication/pull/246); the
number `167` is [an empty placeholder issue](https://github.com/dfinity/ICRC/issues/167) in
the ICRC repository. The transport is nonetheless live: Internet Identity serves it at
`https://id.ai/authorize`, and DFINITY's own reference relying party runs it in production.

Expect the wire format to move. The parts that would move are deliberately kept in one place.

## How it works

1. The app generates a session key pair and opens the browser at
   `https://id.ai/authorize#message=…&callback=…&state=…`
2. The user authenticates with a passkey.
3. Internet Identity fetches `/.well-known/ii-auth-callbacks` from the callback's own origin
   and returns the delegation **only** to a URL declared there, byte for byte.
4. The browser navigates to that callback; Android App Links routes it into the app.
5. The app checks the chain and can then sign calls to canisters as that user.

Both the request and the response ride in the URL **fragment**, so the payload — which
contains a delegation — never reaches any server or proxy log.

## Asking a canister who you are

A delegation chain that verifies locally is still only this library agreeing with itself. The
outside check is to make a call with it and let a canister say which principal it saw:

```kotlin
val agent = IcAgent()
val identity = DelegatedIdentity(chain, sessionKey::sign)
val seen = agent.whoami(Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai"), identity)
// seen == identity.sender
```

That canister is the relying party DFINITY runs, and it exports `whoami`.

The envelopes are pinned byte for byte against fixtures a separate script produced, and that
script's output is what mainnet accepted: an anonymous call, a call signed by a key speaking
for itself, and a call signed by a session key under a delegation the script made — with a
fourth, signed by the wrong key, refused as `Invalid signature`. The `Live IC` workflow
repeats all four against the network every Monday, because a fixture cannot notice the network
changing its mind.

The endpoint is `/api/v3/canister/<id>/query`. The v2 path still answers — measured the same
day — but the specification marks it deprecated, so v3 is the default and the version is a
constructor argument.

### The answer is checked, not just read

A query reply is otherwise whatever answered: the principal in a `whoami` reply is a string a
boundary node could write itself. So `verifiedWhoami` above is the interesting call, and this
is what it does, as the specification defines it — fetch the subnet certificate in a
*separate* `read_state`, verify it to the network root key, read the public key of the
answering node out of the certified tree, and check the signature over the byte 0x0B followed
by `ic-response` and a hash of the answer, the timestamp and the request id. Every signature
in the response has to verify, not one of them.

```kotlin
val verifier = QueryResponseVerifier(CertificateVerifier(MiraclBls), StandardSignatureVerifier())
val seen = IcAgent().verifiedWhoami(canister, DelegatedIdentity(chain, sessionKey::sign), verifier)
```

Three details were settled by measuring rather than by reading. A **nested map** hashes to its
own digest, used as it stands — wrapping that digest in a blob hashes it twice and the live
signature refuses it. **`error_code`** is optional in a rejection and is part of what is
signed when it is present. And a subnet certificate has no expiry of its own, which is why the
recorded exchanges in the tests still verify to the root key with the real pairing.

**Age is part of the check, and it takes two windows.** The specification leaves the numbers
to the client and says what is reasonable: five minutes for the signatures and the
certificate, matching the ingress expiry mainnet enforces, and **at least a week** for a
delegation, because mainnet only refreshes those when replicas are upgraded. One window for
both would be wrong in a way that shows up in production rather than in a test — live
delegations measured on 2026-09-10 were already 37 to 204 seconds old. Both are constructor
arguments. Without any of it a captured answer replays for ever and a stale certificate keeps
a rotated-out node authoritative, which is also why the recorded exchanges in the tests are
verified with the clock set to the moment they were signed.


## What you have to host

ICRC-167 puts the trust anchor on the relying party's origin, so an app alone is not enough.
The callback origin must serve, without redirects:

- `/.well-known/ii-auth-callbacks` — `application/json`, CORS-readable, listing the exact
  callback URL. Internet Identity refuses the flow if this does not match byte for byte.
- `/.well-known/assetlinks.json` — Digital Asset Links, so Android verifies the app owns the
  domain and routes the callback to it instead of leaving it in the browser.

This one is live at `https://callback-origin.vercel.app`, deployed from `callback-origin/` by
`.github/workflows/deploy-callback-origin.yml`. Two things about the host were measured rather
than assumed on 2026-09-10: Vercel does serve a dot-directory, and the per-deployment URL and
the team-scoped one both answer `302` (deployment protection), which the signer refuses — only
the stable project domain works. The `assetlinks.json` there is still a template, because
there is no app to fingerprint yet; Internet Identity does not read that file, so the browser
half of the flow does not wait for it.

Both are read back rather than trusted: `scripts/check-callback-origin.sh` fetches them the
way the signer and the platform do, and two workflows call it — the CI job `well-known`,
which runs when the repository variable `CALLBACK_ORIGIN` is set, and the deploy job, which
also compares the served callback list against the one in the commit it just published.

Note that **GitHub Pages is not suitable** as this origin: serving an extensionless path with
`application/json` there requires the directory-plus-`index.json` trick, which introduces a
301 redirect, and the specification requires the signer to refuse redirects.

## Building

There is no Gradle wrapper committed; CI provisions Gradle.

```
gradle :icrc167-core:test :icrc167-agent:test
```

The round trip against mainnet is off by default. To run it:

```
gradle :icrc167-agent:test --tests "*LiveIcTest*" -Dicrc167.live=1
```

Dependencies are pulled in weekly rather than waited for. Patch and minor bumps are merged
once **every** check on the head is finished and green; majors are left open
(`.github/dependabot.yml`, `.github/workflows/dependabot-auto-merge.yml`). Every check, not
just CI: gating on CI alone is how an `androidx.browser` bump landed on main over a failing
`Device tests` and left the Android build broken.

`bcprov-jdk18on` and `bcutil-jdk18on` are deliberately on **different** versions (1.85.2 and 1.85): 1.85.2 was a bcprov-only
release. That mismatch is correct — do not align them.

## Licence

MIT. See [LICENSE](LICENSE).

`icrc167-canister-sig` vendors [MIRACL Core](https://github.com/miracl/core), which is
licensed under Apache-2.0 ([its licence](icrc167-canister-sig/src/miracl/java/LICENSE.txt),
with where it came from in `PROVENANCE` beside it). `icrc167-android` depends on that module,
so an app built on it ships MIRACL and has to carry that licence as well.

This project is not affiliated with DFINITY.
