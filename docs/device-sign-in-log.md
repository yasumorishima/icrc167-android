# Device sign-in log

Dated records of signing in with the demo app on a real phone, moved verbatim from the
[README](../README.md). The README keeps the current state; this file keeps how it was reached.

### The first real sign-in

On 2026-09-14 the demo (`demo-d07dc3e`) signed in on a Sony XQ-BT44 (Android 12). The Custom Tab
was Microsoft Edge 152, and the passkey prompt came from Google Play services. The screen read:

| verdict | |
|---|---|
| PASS | the canister sees the principal the chain names |
| PASS | an anonymous call is seen as `2vxsx-fae` |
| PASS | a key the chain does not name is refused (`400: Invalid signature`) |

| TIME | total | of which BLS |
|---|---|---|
| checking the answer, including the Keystore | 473 ms | 332 ms |
| whoami as the signed-in identity, two HTTP calls | 1227 ms | 254 ms |
| whoami anonymously, two HTTP calls | 1133 ms | 219 ms |

These are one run on one phone, not a distribution.

Two things were changed:

- **The lifetime check refused every real answer.** Internet Identity's URL transport returns
  two hops. The canister-signed hop to an ephemeral key expired 7.999 h out for an 8 h request.
  The hop from that key to the session key expired 720 h out (`OUTER_DELEGATION_EXPIRATION_MS`
  in internet-identity `src/frontend/src/lib/utils/transport/url.ts`). Each hop used to be
  compared with the request on its own. A chain is usable only while every hop is, so the
  earliest expiration is what is now compared (#33, `Icrc167LifetimeTest`).
- **An installed Internet Identity web app took the link.** Chrome had installed `id.ai` as a web
  app on that phone, and that web app claims `id.ai` links. A Custom Tab launch and a plain
  `ACTION_VIEW` both opened in it.
  - On that phone Chrome never showed the passkey prompt. DevTools over wireless debugging
    showed II's `navigator.credentials.get` still pending: a second request was refused with
    `A request is already pending`.
  - With the web app removed and Edge as the default browser, the same flow completed.
  - The next day, on newer browser builds, the same missing prompt happened without the web app
    (see below).

  `launch` now addresses the Custom Tab to a browser by package (`preferredBrowserPackage`: the
  default browser, else a Custom Tabs browser). That stops two routes to such a web app:
  Android resolving the link to an app approved for the site, which `BrowserChoiceTest` measures
  on the emulator with a stand-in claimant and two mutations; and Chrome passing a link from
  another app to a WebAPK, which, in Chromium's source, it does not do when the intent names
  Chrome. Which route moved the page on that phone is not known.

### On 2026-09-15 the stall did not need the web app

On 2026-09-15 the same phone was tried again (`demo-86f5fb4`), and the missing prompt turned out
not to need the web app:

- With the web app installed again, Chrome and Edge opened the page in their own Custom Tab, not
  in the web app, and the prompt still did not come. Brave was tried only after the web app had
  been removed again.
- Chrome, after the web app was removed, stopped in the same way.
- The request that stops is the one II makes for an identity it has remembered in that browser.
  Recorded over DevTools in Chrome and Brave, it is `navigator.credentials.get` with
  `userVerification: "required"` and an 11-entry `allowCredentials` whose entries carry no
  `transports`. During that request Google Play services (26.33.32) logged
  `Transport smart-card not supported`. The same line was logged in the Edge run, which was not
  hooked. No answer came within the 25 to 45 s that were watched (the request's own timeout is
  60 s), and in the runs left for about three minutes the page stayed on `id.ai/authorize` (Chrome
  showed "Authenticating...").
- The browsers were Chromium 153 builds: Chrome 153.0.8010.36, Edge 153.0.4234.32, and Brave
  reporting Chrome/153.0.8010.37.
- A request with an empty `allowCredentials` (II's "Sign in with passkey", tried in Brave)
  brought the prompt, and that sign-in finished with the same three PASS lines. TIME: checking
  the answer 426 ms (BLS 340 ms), signed-in whoami 1478 ms (BLS 237 ms), anonymous whoami
  1079 ms (BLS 226 ms). A later sign-in in the same Brave sent the 11-entry list and stopped
  with the same log line.
- In Chrome, with II's own call held back, the same 11 credential ids were sent again from the
  page. Without `transports`, Play services logged the same line and no answer came in 35 s. With
  `transports: ["internal", "hybrid"]` on each entry, that line was not logged, the prompt came,
  and the request resolved in 5.3 s. That is one run of each.
- The Edge that completed on 2026-09-14 was version 152. The Edge on the phone the next day was
  153, installed at 07:39 that morning. Whether 152 avoids the failure was not measured.

This library opens `id.ai/authorize` and does not make or change the page's
`navigator.credentials.get` call.

Reported to Internet Identity as
[dfinity/internet-identity#4334](https://github.com/dfinity/internet-identity/issues/4334).

### Chromium stopped sending the transport

The browser side of that stall has a fix upstream, and the fix stops the transport from being
sent rather than making it readable. Chromium's
[crbug 555599813](https://issues.chromium.org/issues/555599813) records the same mechanism this
page measured: GmsCore cannot unmarshal `AuthenticatorTransport.SMART_CARD` and hangs when
`allowCredentials[].transports` carries smart-card, or when the relying party omits transports
and Blink fills in every known transport.
[CL 8385662](https://chromium-review.googlesource.com/c/chromium/src/+/8385662) makes
`Fido2Api.transportToString` return null for `SMART_CARD` behind
`kWebAuthnFilterSmartCardTransport`, which is `FEATURE_ENABLED_BY_DEFAULT`. It landed on `main`
on 2026-09-10 and was merged to `branch-heads/8010` (M153) and to `8037` (M154) on 2026-09-14,
those dates being Gerrit's, in UTC.

Reading `components/webauthn/features.cc` at each tag, the flag is absent at every tag from
`153.0.8010.36` through `.46` and present from `.47` on, and Chromium Dash lists `.47` as an
Android stable release whose predecessor on that platform was `.37`. So `.47` is the first
Android stable build carrying it, and every browser on the phone on 2026-09-15 was older.

The change is Chromium's rather than Play services': Chrome stops sending the transport instead
of Play services learning to read it, and the CL calls itself a temporary workaround. Whether
Play services has been changed since has not been measured here. Because the change is the
browser's, it arrives with each Chromium browser's own release: Brave took Chromium
153.0.8010.48 in release 1.95.102 on 2026-09-16, Android APKs included, while the Edge on the
phone, 153.0.4234.32, is still the current Edge for Android stable, released 2026-09-14, and
Edge does not publish which Chromium build it carries. This library opens a Custom Tab in
whichever browser it is pointed at, so which browser a phone carries is what decides the
outcome. It has not been measured on the phone again.

## A note the first real sign-in superseded

This paragraph stood under *Modules* in the README. It predates the sign-in of 2026-09-14 and
no longer holds:

Nothing here has been through a real Internet Identity round trip yet. When it has, this
table will say so. The calls in *Asking a canister who you are* are real ones against mainnet,
but the chain they carry is one this repository signs for itself.
