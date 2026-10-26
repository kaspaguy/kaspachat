#!/usr/bin/env bash
# Builds the Apple test builds on a Mac, from this checkout: the iPhone app (with the Tor built into it) and the Mac
# desktop app. Testnet builds: they carry the testnet login from native-build.env, so keep them in the test group.
#   tools/build-apple.sh [--sim] [--universal] [--no-ios] [--no-mac]
#     --sim        also start the iPhone app in the iOS Simulator
#     --universal  Mac app for Apple silicon and Intel (default: this Mac's chip only)
#   KC_ENV=<file>  testnet settings (default: ./native-build.env)
#   KC_OUT=<dir>   where the builds go (default: ~/KaspaChat-builds)
# Needs: Xcode with the iOS platform installed, Node 22+, Rust (rustup). Signing for a real iPhone is done in Xcode.
# (macOS bash 3.2 with pipefail: no grep -q or head at the end of a pipe, they can fail the pipe on SIGPIPE.)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SIM=0 UNIVERSAL=0 IOS=1 MAC=1
for a in "$@"; do
  case $a in
    --sim) SIM=1 ;; --universal) UNIVERSAL=1 ;; --no-ios) IOS=0 ;; --no-mac) MAC=0 ;;
    *) echo "unknown option $a (see the top of $0)"; exit 2 ;;
  esac
done
say() { echo; echo "== $*"; }
die() { echo; echo "!! $*"; exit 1; }

say "checks"
[ "$(uname -s)" = Darwin ] || die "run this on a Mac"
xcodebuild -version >/dev/null 2>&1 || die "Xcode isn't set up: install it from the App Store, then run: sudo xcode-select -s /Applications/Xcode.app && sudo xcodebuild -runFirstLaunch"
[ $IOS = 0 ] || xcrun simctl list runtimes 2>/dev/null | grep '^iOS' >/dev/null || die "the iOS platform isn't installed: xcodebuild -downloadPlatform iOS"
command -v node >/dev/null && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ] || die "Node 22 or newer is needed (https://nodejs.org or: brew install node@22)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v rustup >/dev/null || die "Rust isn't installed: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   (then open a new terminal)"
ENV_FILE=${KC_ENV:-$ROOT/native-build.env}
[ -f "$ENV_FILE" ] || die "no $ENV_FILE. Create it with the testnet settings (see the README)"
for k in VITE_API_ORIGIN VITE_API_AUTH VITE_API_ONION; do grep -q "^$k=." "$ENV_FILE" || die "$ENV_FILE has no $k"; done
VER=$(node -p "require('$ROOT/mobile/package.json').version")
REV=$(git -C "$ROOT" describe --tags --always --dirty)
OUT=${KC_OUT:-$HOME/KaspaChat-builds}/$VER-$REV
mkdir -p "$OUT"
LOG=$OUT/logs; mkdir -p "$LOG"
echo "KaspaChat $VER ($REV), builds to $OUT"

say "web app and packages"
for d in protocol app mobile desktop; do (cd "$ROOT/$d" && npm ci --no-audit --no-fund --silent) >>"$LOG/npm.log" 2>&1 || die "npm ci in $d (see $LOG/npm.log)"; done
set -a; . "$ENV_FILE"; set +a

if [ $IOS = 1 ]; then
  say "Tor for iOS (Rust, first run takes a while)"
  TARGETS="aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios"
  rustup target add $TARGETS >>"$LOG/rust.log" 2>&1
  export IPHONEOS_DEPLOYMENT_TARGET=15.0
  T=$ROOT/tor/target
  for t in $TARGETS; do
    # A static library keeps its symbols: the app links kc_tor_start from it.
    (cd "$ROOT/tor" && CARGO_PROFILE_RELEASE_STRIP=false cargo rustc --lib --release --target "$t" --crate-type staticlib -- --print native-static-libs) >"$LOG/tor-$t.log" 2>&1 || die "Tor build for $t (see $LOG/tor-$t.log)"
  done
  # The libraries the Xcode project links for it (mobile/ios/scripts/add-tor.rb) must cover what rustc asks for.
  need=$(sed -n 's/.*native-static-libs: //p' "$LOG/tor-aarch64-apple-ios.log" | tail -1 | sed 's/-framework /-framework:/g')
  have=$(grep '^TOR_LDFLAGS' "$ROOT/mobile/ios/scripts/add-tor.rb" | grep -oE "'[^']+'" | tr -d "'" | paste -sd' ' - | sed 's/-framework /-framework:/g')
  for f in $need; do
    case " -lSystem -lc -lm $have " in *" $f "*) ;; *) die "the Tor library also needs ${f/:/ }: add it to TOR_LDFLAGS in mobile/ios/scripts/add-tor.rb, run that script, and tell Claude" ;; esac
  done
  mkdir -p "$T/ios-sim"
  lipo -create "$T/aarch64-apple-ios-sim/release/libkaspachat_tor.a" "$T/x86_64-apple-ios/release/libkaspachat_tor.a" -output "$T/ios-sim/libkaspachat_tor.a"
  XCF=$ROOT/mobile/ios/App/KaspaChatTor.xcframework
  rm -rf "$XCF"
  xcodebuild -create-xcframework \
    -library "$T/aarch64-apple-ios/release/libkaspachat_tor.a" -headers "$ROOT/tor/include" \
    -library "$T/ios-sim/libkaspachat_tor.a" -headers "$ROOT/tor/include" \
    -output "$XCF" >"$LOG/xcframework.log" 2>&1 || die "xcframework (see $LOG/xcframework.log)"
  nm -gU "$T/aarch64-apple-ios/release/libkaspachat_tor.a" 2>/dev/null | grep '_kc_tor_start$' >/dev/null || die "kc_tor_start is missing from the iOS library"

  say "iPhone app for the Simulator"
  (cd "$ROOT/mobile" && npm run -s web && npx cap sync ios) >"$LOG/ios-sync.log" 2>&1 || die "web build or cap sync (see $LOG/ios-sync.log)"
  DD=$ROOT/build/apple/ios-sim
  xcodebuild -project "$ROOT/mobile/ios/App/App.xcodeproj" -scheme App -configuration Debug -sdk iphonesimulator \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath "$DD" CODE_SIGNING_ALLOWED=NO build \
    >"$LOG/ios-build.log" 2>&1 || { grep -E 'error:' "$LOG/ios-build.log" | head -20; die "iOS build (see $LOG/ios-build.log)"; }
  APP=$DD/Build/Products/Debug-iphonesimulator/App.app
  ditto -c -k --keepParent "$APP" "$OUT/KaspaChat-$VER-ios-simulator.app.zip"
  if [ $SIM = 1 ]; then
    dev=$(xcrun simctl list devices available | grep -oE 'iPhone[^(]*\([0-9A-F-]{36}\)' | sed -n '1s/.*(\(.*\))/\1/p')
    [ -n "$dev" ] || die "no iPhone simulator: add one in Xcode → Window → Devices and Simulators"
    xcrun simctl boot "$dev" 2>/dev/null || true
    open -a Simulator
    xcrun simctl install "$dev" "$APP"
    xcrun simctl launch "$dev" com.kaspaguy.kaspachat >/dev/null
    echo "started in the Simulator"
  fi
fi

if [ $MAC = 1 ]; then
  say "Mac desktop app"
  if [ $UNIVERSAL = 1 ]; then
    rustup target add aarch64-apple-darwin x86_64-apple-darwin >>"$LOG/rust.log" 2>&1
    (cd "$ROOT/desktop" && npm run -s web && npx tauri build --target universal-apple-darwin) >"$LOG/mac-build.log" 2>&1 || die "Mac build (see $LOG/mac-build.log)"
    B=$ROOT/desktop/src-tauri/target/universal-apple-darwin/release/bundle
  else
    (cd "$ROOT/desktop" && npm run -s build) >"$LOG/mac-build.log" 2>&1 || die "Mac build (see $LOG/mac-build.log)"
    B=$ROOT/desktop/src-tauri/target/release/bundle
  fi
  cp "$B"/dmg/*.dmg "$OUT/"
fi

say "done"
(cd "$OUT" && shasum -a 256 ./*.zip ./*.dmg 2>/dev/null | tee SHA256SUMS)
echo
echo "Builds: $OUT"
[ $IOS = 0 ] || echo "iPhone: open mobile/ios/App/App.xcodeproj in Xcode, choose your team under Signing & Capabilities (App and NotificationService), pick your iPhone and press Run."
[ $MAC = 0 ] || echo "Mac: open the .dmg and drag KaspaChat to Applications (unsigned test build: right-click → Open the first time)."
