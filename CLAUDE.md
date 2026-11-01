# CLAUDE.md

A Kotlin implementation of ICRC-167 sign-in for Android: delegation chains, certificate and
canister-signature (BLS12-381) verification, an IC agent, an Android library, and a demo app.
README.md is the design record; read the relevant section before changing behaviour.
Write code, comments and commit messages in English, matching the existing style.

## Layout

- `icrc167-core` / `icrc167-crypto` / `icrc167-certificate` / `icrc167-canister-sig` / `icrc167-agent` — plain JVM modules, unit-tested against recorded vectors in `src/test/resources/vectors/`
- `icrc167-android` — the Android library; `demo` — the demo app; `probe` — a tiny app used to check what D8 does to MIRACL
- `icrc167-canister-sig/src/miracl/` — vendored MIRACL (`scripts/vendor-miracl.sh`); do not edit by hand
- `fake-signer` — a stand-in signer for tests; `callback-origin` — the static site (Vercel) that hosts the App Link callback and `.well-known` files
- `.github/workflows/` — CI is the source of truth for what is checked

## Running checks

There is no Gradle wrapper. In a Claude Code cloud container, run once:

```bash
bash scripts/cloud-setup.sh   # JDK 17, Gradle 9.6.1, Maven Central mirror, Android SDK 36 (~30 s)
```

Then plain `gradle` works:

```bash
gradle --no-daemon :icrc167-core:test :icrc167-crypto:test :icrc167-certificate:test :icrc167-canister-sig:test :icrc167-agent:test
gradle --no-daemon :icrc167-android:assembleDebug :icrc167-android:assembleDebugAndroidTest :demo:assembleDebug :demo:assembleDebugAndroidTest
bash scripts/test-head-green-gate.sh
gradle --no-daemon :icrc167-agent:test --tests "*LiveIcTest*" -Dicrc167.live=1   # against mainnet; free, no secrets
```

Measured on 2026-11-01: 216 JVM tests pass (6 skipped = the live tests, off by default), both
Android assemblies build, the live test passes 6/6.

What the setup script works around:
- Maven Central returns 429 to the shared egress IP. A user-level init script
  (`~/.gradle/init.d/`) points it at Google's mirror; the repository's build is unchanged.
- The image has Gradle 8.14 and JDK 21 only; AGP 9.5 needs Gradle 9.6+, the toolchain is 17.

Not possible in the cloud container: the device tests (`scripts/device-tests.sh`, emulator) —
there is no `/dev/kvm`. Leave those to the CI emulator job.

## Rules

- `bcprov-jdk18on` and `bcutil-jdk18on` are on different versions on purpose. Do not align them.
- Do not deploy or release from a session: `deploy-callback-origin.yml` (Vercel) and `demo-release.yml` (keystore) use secrets and are for a person to run.
- Prefer measured claims: when a comment or README states a fact, it was checked. Keep it that way.
