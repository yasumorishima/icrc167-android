# The callback origin

ICRC-167 puts the trust anchor on the relying party's own origin, so an Android app is not
enough on its own. A domain you control has to serve two documents, and Internet Identity
will refuse the flow if either is wrong.

| path | why |
|---|---|
| `/.well-known/ii-auth-callbacks` | Internet Identity fetches this and returns the delegation **only** to a URL listed here, matched byte for byte. Its own fetch refuses redirects, requires `application/json`, sends no credentials and does not cache. |
| `/.well-known/assetlinks.json` | Android verifies the app owns the domain and routes the callback into it instead of leaving it in the browser. |

Both must answer `200` directly. **A redirect fails the flow**, which is why `trailingSlash`
is off here.

## Filling these in

`ii-auth-callbacks` lists the exact callback URL the app will ask for — same scheme, host and
path, no fragment, no trailing slash surprises. `assetlinks.json` needs the app's package name
and the SHA-256 fingerprint of the certificate it is *actually signed with*. Release and debug
builds have different fingerprints; list every one you ship.

```
keytool -list -v -keystore <keystore> -alias <alias> | grep 'SHA256:'
```

If CI builds the app, its signing key has to be fixed (a keystore in secrets) — otherwise the
fingerprint changes on every build and link verification silently stops working.

## Why not GitHub Pages

Serving an extensionless path as `application/json` on GitHub Pages means the
directory-plus-`index.json` trick, and that introduces a `301`. Internet Identity refuses
redirects at this path, so the flow dies with nothing useful to look at. GitHub Pages also
offers no way to set a header. Measured, not assumed:

```
https://<user>.github.io/.well-known/apple-app-site-association
  → 301 → .../apple-app-site-association/ → 200 application/json
```

## Checking it

`scripts/check-callback-origin.sh` measures a live origin — status, exact content type,
CORS, size, and the shape of the JSON — rather than trusting that a deploy did what it looked
like it did. One copy, two callers:

| workflow | when | extra |
| --- | --- | --- |
| `ci.yml`, job `well-known` | the repository variable `CALLBACK_ORIGIN` is set, with no trailing slash | — |
| `deploy-callback-origin.yml` | after every deploy | also diffs the served callback list against the one in that commit, so a deploy that did not reach the origin cannot pass |

## Two ways to production is one too many

Vercel connects a project to the repository on its own, and then deploys the **repository
root** on every push. The documents here live in a subdirectory, so that path served a 404
over the top of a working origin on 2026-09-10 -- caught because the check that runs after a
deploy asked the origin what it was serving, and the answer had gone from 200 to NOT_FOUND
between two merges.

That path also has no template guard and reads nothing back. So the project is detached from
the repository (`deploy-callback-origin.yml` has a one-shot `disconnect_git` input), and the
only way to production is the workflow that checks its own work. If a Vercel check ever
appears on a pull request again, the integration has been reconnected and should be detached
again rather than worked around.
