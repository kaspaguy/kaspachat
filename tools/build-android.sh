#!/usr/bin/env bash
# Builds the unsigned release APK of the KaspaChat Android app (the Capacitor one in mobile/) and writes SHA256SUMS
# for its contents. The APK signature differs per signing key, so what is published and compared is the hash of every
# file inside the APK except META-INF/ (the signature), plus the hash of the unsigned APK itself.
# Needs: JDK 21, Android SDK (ANDROID_HOME), NDK 30.0.16248370, the same Node major as tools/build-web.sh.
# Usage: tools/build-android.sh <empty output dir>
set -euo pipefail
out=${1:?usage: build-android.sh <empty output dir>}
[ -e "$out" ] && [ -n "$(ls -A "$out")" ] && { echo "$out is not empty" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1767225600}
(cd "$root/protocol" && npm ci --silent --no-audit --no-fund --ignore-scripts)
(cd "$root/app" && npm ci --silent --no-audit --no-fund --ignore-scripts)
(cd "$root/mobile" && npm ci --silent --no-audit --no-fund --ignore-scripts && npm run -s sync)
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$root/mobile/android" && env -u KC_SIGNING ./gradlew --no-daemon -q clean assembleRelease)
apk=$(ls "$root"/mobile/android/app/build/outputs/apk/release/*.apk | head -1)
mkdir -p "$out/contents"
cp "$apk" "$out/kaspachat-unsigned.apk"
(cd "$out/contents" && unzip -q -o "$out/kaspachat-unsigned.apk" && rm -rf META-INF && find . -type f | sort | xargs sha256sum > "$out/SHA256SUMS")
(cd "$out" && sha256sum kaspachat-unsigned.apk >> SHA256SUMS)
rm -rf "$out/contents"
echo "$(wc -l < "$out/SHA256SUMS") hashes"
tail -1 "$out/SHA256SUMS"
