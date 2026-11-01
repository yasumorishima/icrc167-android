#!/usr/bin/env bash
# Prepare a fresh Claude Code cloud container (or any bare Ubuntu box) to run what CI runs.
#
#   bash scripts/cloud-setup.sh
#
# Safe to run again: every step checks first. Afterwards plain `gradle ...` works from the
# repository root, for the JVM tests and for the Android builds alike.
#
# What it fixes, and why each was measured to be needed (2026-11-01):
#   - The image ships Gradle 8.14 and JDK 21. AGP 9.5 needs Gradle 9.6+, and the modules ask
#     for a JDK 17 toolchain, which Gradle will not download (no toolchain repository).
#   - Maven Central answers 429 to the shared egress IP. Google's mirror of it does not, so a
#     user-level init script points every repo.maven.apache.org repository at the mirror.
#     Nothing in the repository's own build changes.
#   - No Android SDK. compileSdk is 36.
#
# Not covered: the device tests (scripts/device-tests.sh). There is no /dev/kvm, so no emulator.
set -euo pipefail

GRADLE_VERSION="${GRADLE_VERSION:-9.6.1}"
ANDROID_PLATFORM="${ANDROID_PLATFORM:-android-36}"
ANDROID_BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-36.0.0}"
TOOLS="$HOME/.local/opt"
BIN="$HOME/.local/bin"
SDK="${ANDROID_HOME:-$TOOLS/android-sdk}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$TOOLS" "$BIN" "$HOME/.gradle/init.d"

echo "==> JDK 17"
JDK17=/usr/lib/jvm/java-17-openjdk-amd64
if [ ! -x "$JDK17/bin/javac" ]; then
  if command -v apt-get >/dev/null; then
    apt-get install -y -q openjdk-17-jdk-headless >/dev/null 2>&1 ||
      { apt-get update -q >/dev/null && apt-get install -y -q openjdk-17-jdk-headless >/dev/null; }
  fi
fi
[ -x "$JDK17/bin/javac" ] || { echo "JDK 17 not found at $JDK17" >&2; exit 1; }

echo "==> Gradle $GRADLE_VERSION"
if [ ! -x "$TOOLS/gradle-$GRADLE_VERSION/bin/gradle" ]; then
  curl -fsSL -o "$TOOLS/gradle.zip" "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"
  unzip -q -o "$TOOLS/gradle.zip" -d "$TOOLS"
  rm -f "$TOOLS/gradle.zip"
fi
ln -sfn "$TOOLS/gradle-$GRADLE_VERSION/bin/gradle" "$BIN/gradle"

echo "==> Maven Central mirror (user-level init script)"
cat > "$HOME/.gradle/init.d/maven-central-mirror.gradle" <<'EOF'
// Written by scripts/cloud-setup.sh. Maven Central rate-limits the shared egress IP (429),
// so every repository that points at it is moved to Google's mirror of the same content.
def mirror = "https://maven-central.storage-download.googleapis.com/maven2/"
def rewrite = { RepositoryHandler repos ->
  repos.withType(MavenArtifactRepository).configureEach { r ->
    def u = r.url.toString()
    if (u.contains("repo.maven.apache.org") || u.contains("repo1.maven.org")) r.url = mirror
  }
}
beforeSettings { s ->
  rewrite(s.pluginManagement.repositories)
  rewrite(s.dependencyResolutionManagement.repositories)
  rewrite(s.buildscript.repositories)
}
allprojects { rewrite(buildscript.repositories); rewrite(repositories) }
EOF

echo "==> Toolchain path"
props="$HOME/.gradle/gradle.properties"
touch "$props"
grep -q '^org.gradle.java.installations.paths=' "$props" ||
  echo "org.gradle.java.installations.paths=$JDK17" >> "$props"

echo "==> Android SDK ($ANDROID_PLATFORM, build-tools $ANDROID_BUILD_TOOLS)"
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  name=$(curl -fsSL https://dl.google.com/android/repository/repository2-1.xml |
    grep -o 'commandlinetools-linux-[0-9]*_latest.zip' | head -1)
  mkdir -p "$SDK/cmdline-tools"
  curl -fsSL -o "$TOOLS/clt.zip" "https://dl.google.com/android/repository/$name"
  rm -rf "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
  unzip -q -o "$TOOLS/clt.zip" -d "$SDK/cmdline-tools"
  mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
  rm -f "$TOOLS/clt.zip"
fi
if [ ! -d "$SDK/platforms/$ANDROID_PLATFORM" ] || [ ! -d "$SDK/build-tools/$ANDROID_BUILD_TOOLS" ]; then
  (yes || true) | "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null 2>&1 || true
  "$SDK/cmdline-tools/latest/bin/sdkmanager" "platforms;$ANDROID_PLATFORM" \
    "build-tools;$ANDROID_BUILD_TOOLS" "platform-tools" >/dev/null
fi
# local.properties is gitignored; AGP reads sdk.dir from it, so no ANDROID_HOME is needed.
echo "sdk.dir=$SDK" > "$ROOT/local.properties"

echo
echo "Ready. $(gradle --version 2>/dev/null | grep '^Gradle')  /  SDK $SDK"
echo "  gradle --no-daemon :icrc167-core:test :icrc167-crypto:test :icrc167-certificate:test :icrc167-canister-sig:test :icrc167-agent:test"
echo "  gradle --no-daemon :icrc167-android:assembleDebug :demo:assembleDebug"
echo "  (the min-sdk job's dexdump needs ANDROID_HOME=$SDK)"
