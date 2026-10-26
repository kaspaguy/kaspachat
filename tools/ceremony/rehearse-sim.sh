#!/usr/bin/env bash
# Simulated ceremony on one machine: three holder folders, one transfer folder. Rehearses key generation,
# a relay-key replacement signature, losing holder 2's share, repairing it with holders 1 and 3 (RTS), a signature
# by the repaired holder, a corrupted repair value being caught, and a stolen-share drill: refresh, after which the
# thief's old share can't sign with the refreshed ones. Usage: rehearse-sim.sh <tool> <workdir> <potCovHex> <relayPubHex>
set -euo pipefail
C=$1 W=$2 COV=$3 RELAY=$4 NONCE=0
rm -rf "$W"; mkdir -p "$W"/h1 "$W"/h2 "$W"/h3 "$W"/xfer; chmod 700 "$W"/h*
X=$W/xfer
step() { echo "== $*"; }

step "key generation"
for i in 1 2 3; do $C dkg1 $i "$W/h$i" "$X" >/dev/null; done
for i in 1 2 3; do $C dkg2 $i "$W/h$i" "$X" >/dev/null; done
ROOTS=$(for i in 1 2 3; do $C dkg3 $i "$W/h$i" "$X" | grep -o 'ROOT KEY.*' | awk '{print $NF}'; done | sort -u)
[ "$(echo "$ROOTS" | wc -l)" = 1 ] || { echo "FAIL: holders disagree on the root key"; exit 1; }
echo "root key $ROOTS (all three agree)"

sign() { # sign <a> <b>
  $C commit $1 "$W/h$1" "$X" >/dev/null; $C commit $2 "$W/h$2" "$X" >/dev/null
  $C package "$X" "$COV" "$RELAY" $NONCE $1 $2 >/dev/null
  $C sign $1 "$W/h$1" "$X" >/dev/null; $C sign $2 "$W/h$2" "$X" >/dev/null
  $C aggregate "$X" | grep -o 'REPLACEMENT SIGNATURE.*' | cut -c1-70
  NONCE=$((NONCE + 1))
  rm -f "$X"/commit-from-* "$X"/share-from-* "$X"/package.json
}
step "relay-key replacement signed by holders 1 and 2"; sign 1 2

step "holder 2 loses their share"
cp "$W/h2/key.json" "$W/original-h2-key.json"   # kept only so the rehearsal can compare
rm "$W/h2/key.json"

step "repair: holders 1 and 3 help holder 2"
$C repair1 1 "$W/h1" "$X" 2 3 >/dev/null; $C repair1 3 "$W/h3" "$X" 2 1 >/dev/null
$C repair2 1 "$W/h1" "$X" 2 3 >/dev/null; $C repair2 3 "$W/h3" "$X" 2 1 >/dev/null
cp "$X/repair2-from-1-to-2.json" "$W/sigma1.bak"; cp "$X/repair2-from-3-to-2.json" "$W/sigma3.bak"
$C repair3 2 "$W/h2" "$X" 1 3 | grep -o 'REPAIRED.*'
python3 - "$W" <<'EOF'
import json, sys
w = sys.argv[1]
a, b = json.load(open(f"{w}/original-h2-key.json")), json.load(open(f"{w}/h2/key.json"))
assert a["signing_share"] == b["signing_share"] and a["verifying_share"] == b["verifying_share"], "repaired share differs"
print("repaired share is identical to the lost one")
EOF
left=$(ls "$W/h1" "$W/h3" "$X" | grep -c 'repair' || true)
[ "$left" = 0 ] || { echo "FAIL: repair secrets left behind"; exit 1; }
echo "no repair secrets left on any device or the transfer stick"

step "replacement signed by the repaired holder 2 and holder 3"; sign 2 3

step "a corrupted repair value is caught"
rm "$W/h2/key.json"; cp "$W/sigma1.bak" "$X/repair2-from-1-to-2.json"; cp "$W/sigma3.bak" "$X/repair2-from-3-to-2.json"
python3 - "$X/repair2-from-3-to-2.json" <<'EOF'
import sys
p = sys.argv[1]
# flip one hex digit of the serialized scalar
txt = open(p).read(); i = next(k for k in range(len(txt) - 1, 0, -1) if txt[k] in "0123456789abcdef")
open(p, "w").write(txt[:i] + ("1" if txt[i] != "1" else "2") + txt[i + 1:])
EOF
if $C repair3 2 "$W/h2" "$X" 1 3 >/dev/null 2>"$W/err.txt"; then echo "FAIL: corrupted repair accepted"; exit 1; fi
grep -o 'REPAIR FAILED[^"]*' "$W/err.txt" | head -1
[ ! -f "$W/h2/key.json" ] && echo "no key written from the corrupted repair"
cp "$W/original-h2-key.json" "$W/h2/key.json"; rm -f "$W"/sigma*.bak "$X"/repair2-*
step "refresh drill: holder 3's device is stolen (a thief copies the share; holder 3 restores from backup)"
mkdir -p "$W/thief"; chmod 700 "$W/thief"; cp "$W/h3/key.json" "$W/thief/key.json"
for i in 1 2 3; do $C refresh1 $i "$W/h$i" "$X" >/dev/null; done
for i in 1 2 3; do $C refresh2 $i "$W/h$i" "$X" >/dev/null; done
AFTER=$(for i in 1 2 3; do $C refresh3 $i "$W/h$i" "$X" | grep -o 'ROOT KEY.*' | awk '{print $NF}'; done | sort -u)
[ "$AFTER" = "$ROOTS" ] || { echo "FAIL: root key changed by the refresh"; exit 1; }
echo "root key unchanged after refresh: $AFTER"
for i in 1 2 3; do $C refresh-commit $i "$W/h$i" "$X" >/dev/null; done
cmp -s "$W/h3/key.json" "$W/thief/key.json" && { echo "FAIL: holder 3's share did not change"; exit 1; }
left=$(ls "$W/h1" "$W/h2" "$W/h3" "$X" | grep -c 'refresh2\|secret\|key.new' || true)
[ "$left" = 0 ] || { echo "FAIL: refresh secrets left behind"; exit 1; }
echo "every share replaced; no refresh secrets left"

step "refreshed holders 1 and 2 sign a replacement"; sign 1 2

step "the thief's old share plus a refreshed share cannot sign"
$C commit 1 "$W/h1" "$X" >/dev/null; $C commit 3 "$W/thief" "$X" >/dev/null
$C package "$X" "$COV" "$RELAY" $NONCE 1 3 >/dev/null
$C sign 1 "$W/h1" "$X" >/dev/null; $C sign 3 "$W/thief" "$X" >/dev/null
if $C aggregate "$X" >/dev/null 2>"$W/err.txt"; then echo "FAIL: old share still signs"; exit 1; fi
echo "refused: $(grep -o 'aggregate: [A-Za-z]*' "$W/err.txt" | head -1)"
rm -f "$X"/commit-from-* "$X"/share-from-* "$X"/package.json

step "refreshed holder 3 still signs with holder 1"; sign 1 3
echo "== rehearsal passed"
