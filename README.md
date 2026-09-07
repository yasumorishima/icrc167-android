# icrc167-android

Internet Identity login for native **Android** apps, with no bridge server.

This implements the relying-party side of **ICRC-167 (Browser URL Transport)** — the mechanism
that lets a native app hand a user to Internet Identity in the browser and get a delegation
back, without a `postMessage` channel and without hosting a relay of your own.

An iOS implementation already exists ([`ICNativeClient`](https://github.com/humandebri/ICNativeClient),
Swift). This is the Android counterpart.

## Status

**Early. The protocol core is implemented and tested; the Android layer is not written yet.**

| | |
|---|---|
| Request/response codec, `state` and id binding, replay refusal | done, tested |
| Delegation chain verification (walk, expiry, scope, session-key binding) | done, tested |
| Granted-scope checking against the request | done, tested |
| Ed25519 and ECDSA P-256 (IEEE P1363) signature verification | done, tested |
| Canister-signature verification | not yet — needs IC certificate + BLS |
| Android module (Custom Tabs, App Links, key storage) | done, exercised on an emulator |
| Demo app | not yet |

Nothing here has been through a real Internet Identity round trip yet. When it has, this
table will say so.

Because canister signatures are not verified yet, a real Internet Identity chain is
currently rejected at hop 0 with `UnsupportedKey` — deliberately a different answer from
`BadSignature`, so that "the check must be broken" is never the obvious conclusion.

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

```
1. the app starts an attempt
   BEGIN|pubkey=MCowBQYDK2VwAyEAM/7v…|id=asaHhAkJLec|state=SM6NGB_u09PVdjc1Jmu_rg
2. the process is reclaimed while the browser is in front   (am force-stop)
3. the stand-in signer answers
   expected principal: febb4-idpcp-…-opnfv-xqe
4. delivered as an App Link, into a fresh process
   pid 5891  SUCCESS|principal=febb4-idpcp-…-opnfv-xqe
             SUCCESS|hops=1|scope=null
```

The process id changes between step 1 and step 4, which is the point: the attempt is
reconstructed from storage, not found in memory. On a real device the browser owns the
foreground for as long as the user takes to authenticate, so that is the only path that
matters. The principal is derived by the app from the root key inside the delegation, and it
has to equal the one the signer computed independently.

What this does *not* establish: that a real Internet Identity chain verifies. That chain is
rooted in a canister signature, which is still unimplemented.

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

## Licence

MIT. See [LICENSE](LICENSE).

This project is not affiliated with DFINITY.
