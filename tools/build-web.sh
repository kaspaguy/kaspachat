#!/usr/bin/env bash
# Builds the KaspaChat web app from this checkout and writes SHA256SUMS next to it, so anyone can compare their
# build with the hashes published for a release. Same Node major version and `npm ci` give the same bytes.
# Usage: tools/build-web.sh <empty output dir>
set -euo pipefail
out=${1:?usage: build-web.sh <empty output dir>}
[ -e "$out" ] && [ -n "$(ls -A "$out")" ] && { echo "$out is not empty" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
(cd "$root/protocol" && npm ci --silent --no-audit --no-fund --ignore-scripts)
(cd "$root/app" && npm ci --silent --no-audit --no-fund --ignore-scripts && npm run -s build)
mkdir -p "$out"
cp -r "$root/app/dist/." "$out/"
(cd "$out" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
echo "node $(node -v), $(wc -l < "$out/SHA256SUMS") files"
sha256sum "$out/SHA256SUMS"
