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
| Demo app | not yet |

### Modules

| | |
|---|---|
| `icrc167-core` | The transport, delegation chains, principals. Only dependency is `org.json`, and that is `compileOnly` because Android ships it — so its version has to match what the platform provides, and Dependabot is told to leave it alone. Compiling against a newer one links on a desktop JVM and fails on a device. |
| `icrc167-crypto` | Ed25519 and ECDSA P-256 signature verification, behind the interface the core injects. |
| `icrc167-certificate` | CBOR, the state-tree witness, and certificate verification. No dependencies at all: the pairing check arrives as an interface. |
| `icrc167-canister-sig` | That pairing check, over a vendored MIRACL Core, plus the canister-signature verifier. Optional — an app that never meets one does not ship the arithmetic. |
| `icrc167-android` | Custom Tabs, App Links, session keys. |

An app that does not need certificates never pulls them in.

Nothing here has been through a real Internet Identity round trip yet. When it has, this
table will say so.

A chain mixes schemes — Internet Identity signs the root hop with a canister signature and
the rest with keys WebCrypto produced — so wire both verifiers together:

```kotlin
DelegationChainVerifier(
    CompositeSignatureVerifier(StandardSignatureVerifier(), CanisterSignatureVerifier()),
)
```

A verifier that does not recognise a key answers `UnsupportedKey`, which is deliberately a
different answer from `BadSignature`: it is what lets the composite try the next one, and it
keeps "the check must be broken" from being the obvious conclusion when a scheme is simply not
compiled in.

### What the canister-signature tests can and cannot show

The arithmetic is fixed on RFC 9380's own hash-to-curve vectors, and certificate verification
on a certificate captured from `id.ai` — the real mainnet root key, a real subnet delegation,
the sharded canister ranges, and a set of negative cases built by rewriting that certificate
(most sharply: pruning a label, which leaves the root hash and therefore the signature
untouched, and must still be refused).

The two canister signatures in the public record — DFINITY's own, in `internet-identity` and
in `ic-signature-verification` — are older than the rule that a delegation must state its
subnet's type, which the IC added to the state tree in 2026. Both are therefore refused, and
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

There are three cases, and the negative ones carry the weight. **A passing positive case on
its own proves almost nothing here**: the principal is derived from the root public key in
the response, so it would still come out right if signature checking were removed entirely.

```
A. an answer carrying somebody else's state   → refused, attempt survives
B. the same attempt then completes            → SUCCESS, in a different pid
C. a signature that does not check out        → refused, BadSignature
```

`B` asserts the process id actually changed, and `A` asserts the process was gone before the
answer arrived, so the attempt is demonstrably reconstructed from storage rather than found
in memory. On a real device the browser owns the foreground for as long as the user takes to
authenticate, so that is the only path that matters. That `B` succeeds *after* `A` is what
shows a forged callback cannot burn a sign-in the user is still in the middle of.

What this does *not* establish: that a real Internet Identity chain verifies. That chain is
rooted in a canister signature, which is still unimplemented. Nor does it exercise Custom
Tabs, Digital Asset Links verification, or the signer's own callback matching.

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

## What you have to host

ICRC-167 puts the trust anchor on the relying party's origin, so an app alone is not enough.
The callback origin must serve, without redirects:

- `/.well-known/ii-auth-callbacks` — `application/json`, CORS-readable, listing the exact
  callback URL. Internet Identity refuses the flow if this does not match byte for byte.
- `/.well-known/assetlinks.json` — Digital Asset Links, so Android verifies the app owns the
  domain and routes the callback to it instead of leaving it in the browser.

The CI job `well-known` measures both against a live origin rather than trusting that they
were deployed correctly. It runs when the repository variable `CALLBACK_ORIGIN` is set.

Note that **GitHub Pages is not suitable** as this origin: serving an extensionless path with
`application/json` there requires the directory-plus-`index.json` trick, which introduces a
301 redirect, and the specification requires the signer to refuse redirects.

## Building

There is no Gradle wrapper committed; CI provisions Gradle.

```
gradle :icrc167-core:test
```

Dependencies are pulled in weekly rather than waited for. Patch and minor bumps are merged once CI is green; majors are left open
(`.github/dependabot.yml`, `.github/workflows/dependabot-auto-merge.yml`).

`bcprov-jdk18on` and `bcutil-jdk18on` are deliberately on **different** versions (1.85.2 and 1.85): 1.85.2 was a bcprov-only
release. That mismatch is correct — do not align them.

## Licence

MIT. See [LICENSE](LICENSE).

This project is not affiliated with DFINITY.
