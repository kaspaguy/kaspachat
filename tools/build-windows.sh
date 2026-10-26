#!/usr/bin/env bash
# Builds the Windows (x64) desktop installer on Linux, from this checkout: cross-compiled with cargo-xwin
# for x86_64-pc-windows-msvc, packed by Tauri's NSIS bundler. Testnet build: it carries the testnet login from
# native-build.env, so hand it only to testers. Unsigned (no Windows code-signing certificate): SmartScreen warns
# ("Windows protected your PC" -> More info -> Run anyway).
#   tools/build-windows.sh
#   KC_ENV=<file>   testnet settings (default: ./native-build.env)
#   KC_OUT=<dir>    where the installer goes (default: ./builds)
#   KC_JOBS=<n>     cargo jobs (default 6, so other services keep CPU); runs under nice -n 10
# Run it from a separate clone (for example ../kc-win), never from a deployed tree.
# One-time setup on the build box (Ubuntu):
#   apt-get install -y nsis lld llvm clang
#   rustup target add x86_64-pc-windows-msvc
#   cargo install --locked cargo-xwin      (downloads the MSVC CRT + Windows SDK on first use, into ~/.cache/cargo-xwin)
# Output: $KC_OUT/KaspaChat_<ver>_x64-setup.exe and SHA256SUMS-<ver>-windows.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
say() { echo; echo "== $*"; }
die() { echo; echo "!! $*"; exit 1; }
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH=$HOME/.cargo/bin:$PATH

TARGET=x86_64-pc-windows-msvc
ENV_FILE=${KC_ENV:-./native-build.env}
OUT=${KC_OUT:-./builds}
export CARGO_BUILD_JOBS=${KC_JOBS:-6}

say "checks"
case "$ROOT" in /opt/*) die "don't build in $ROOT; use a separate clone (git clone <repo> ../kc-win)";; esac
for c in makensis lld-link llvm-rc llvm-lib clang-cl cargo-xwin node npm; do command -v $c >/dev/null || die "$c is missing (see the setup lines at the top of $0)"; done
rustup target list --installed | grep -qx $TARGET || die "Rust target missing: rustup target add $TARGET"
free_gb=$(df -BG --output=avail "$ROOT" | tail -1 | tr -dc 0-9)
[ "$free_gb" -ge 50 ] || die "only ${free_gb} GB free, need 50"
[ -f "$ENV_FILE" ] || die "no $ENV_FILE"
for k in VITE_API_ORIGIN VITE_API_AUTH VITE_API_ONION; do grep -q "^$k=." "$ENV_FILE" || die "$ENV_FILE has no $k"; done
VER=$(node -p "require('$ROOT/desktop/package.json').version")
CONF_VER=$(node -p "require('$ROOT/desktop/src-tauri/tauri.conf.json').version")
[ "$VER" = "$CONF_VER" ] || die "desktop/package.json says $VER but tauri.conf.json says $CONF_VER"
REV=$(git -C "$ROOT" describe --tags --always --dirty)
LOG=$ROOT/build/windows-logs; mkdir -p "$LOG" "$OUT"
echo "KaspaChat $VER ($REV) for Windows x64; logs in $LOG"

say "packages"
for d in protocol app desktop; do (cd "$ROOT/$d" && nice -n 10 npm ci --no-audit --no-fund --silent) >>"$LOG/npm.log" 2>&1 || die "npm ci in $d (see $LOG/npm.log)"; done

say "web app (testnet settings) and Windows build (first run downloads the MSVC SDK and takes a while)"
set -a; . "$ENV_FILE"; set +a
(cd "$ROOT/desktop" && nice -n 10 npm run -s web) >"$LOG/web.log" 2>&1 || die "web build (see $LOG/web.log)"
(cd "$ROOT/desktop" && nice -n 10 npx tauri build --runner cargo-xwin --target $TARGET --bundles nsis) >"$LOG/tauri.log" 2>&1 \
  || { grep -E '^error|error:' "$LOG/tauri.log" | head -20; die "Windows build (see $LOG/tauri.log)"; }

B=$ROOT/desktop/src-tauri/target/$TARGET/release/bundle/nsis
EXE=$B/KaspaChat_${VER}_x64-setup.exe
[ -f "$EXE" ] || die "no installer at $EXE (found: $(ls "$B" 2>/dev/null))"
NAME=KaspaChat_${VER}_x64-setup.exe
install -m 600 "$EXE" "$OUT/$NAME"
(cd "$OUT" && sha256sum "$NAME" > "SHA256SUMS-$VER-windows" && chmod 600 "SHA256SUMS-$VER-windows" && cat "SHA256SUMS-$VER-windows")
ls -l "$OUT/$NAME"
say "done: $OUT/$NAME (unsigned; SmartScreen will warn)"
