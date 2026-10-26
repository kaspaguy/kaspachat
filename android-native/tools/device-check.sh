#!/usr/bin/env bash
# Verifies the app on a connected phone or a running emulator (adb devices must list exactly one):
#  1. JVM unit tests (QR/URI/sompi, the JNI bridge against protocol/vectors/v1.json, API paths)
#  2. instrumented tests on the device (Keystore vault, passcode throttle, SQLCipher database, lock)
#  3. installs the debug build, launches it, and checks the app wrote nothing to Logcat
# Usage: tools/device-check.sh            (from android-native/)
set -euo pipefail
cd "$(dirname "$0")/.."
ADB="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/opt/android-sdk}}/platform-tools/adb"
PKG=com.kaspaguy.kaspachat.android

[ "$("$ADB" devices | grep -c 'device$')" = 1 ] || { echo "Connect exactly one device (adb devices)"; exit 1; }
echo "== device: $("$ADB" shell getprop ro.product.model) / Android $("$ADB" shell getprop ro.build.version.release) / $("$ADB" shell getprop ro.product.cpu.abi)"

./gradlew -q :app:testDebugUnitTest
echo "== unit tests passed"

./gradlew -q :app:connectedDebugAndroidTest -PskipRust
echo "== device tests passed (vault, throttle, encrypted database, lock)"

./gradlew -q :app:installDebug -PskipRust
"$ADB" logcat -c
"$ADB" shell am start -W -n "$PKG/.MainActivity" >/dev/null
sleep 5
PID="$("$ADB" shell pidof "$PKG" | tr -d '\r')"
[ -n "$PID" ] || { echo "app did not start"; exit 1; }
# The app itself never logs; only system/runtime lines may show up under its pid.
if "$ADB" logcat -d --pid="$PID" | grep -iE 'kaspa(test)?:|mnemonic|phrase|seed|claim|[0-9a-f]{64}'; then
  echo "!! something sensitive-looking was logged (above)"; exit 1
fi
echo "== app running (pid $PID), nothing sensitive in Logcat"
echo "Now walk through the manual checklist in README.md (screenshots on the phrase screen, top-up QR)."
