#!/usr/bin/env bash
# Run the Kaspaveil contract tests against the real rusty-kaspa script engine, using
# Silverscript's own test harness at a pinned commit.
set -euo pipefail
SILVERSCRIPT_REV=3ed973335b59269293564805cc2c58a14595ec03
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${SILVERSCRIPT_DIR:-$HERE/.silverscript}"

if [ ! -d "$WORK/.git" ]; then
  git clone -q https://github.com/kaspanet/silverscript "$WORK"
fi
git -C "$WORK" fetch -q --depth 1 origin "$SILVERSCRIPT_REV" 2>/dev/null || true
git -C "$WORK" checkout -q "$SILVERSCRIPT_REV"

T="$WORK/silverscript-lang/tests"
mkdir -p "$T/kaspaveil"
cp "$HERE"/*.sil "$T/kaspaveil/"
cp "$HERE"/tests/*.rs "$T/"
cd "$WORK"
cargo test -q -p silverscript-lang --test treasury_engine_tests "$@"
