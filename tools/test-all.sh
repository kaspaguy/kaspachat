#!/usr/bin/env bash
# Every Kaspaveil test suite against this tree; prints PASS/FAIL per suite and exits non-zero if any failed.
# Needs Node 22.18+ (runs .ts directly), Rust (cargo), python3, mongod (a throwaway one is started on a free port),
# and the Silverscript debugger built at the commit pinned in contracts/tools/run_engine_tests.sh with
# contracts/tools/debugger_utxo_daa.patch applied: SILVERSCRIPT_DIR=<that checkout>. Usage: tools/test-all.sh [logdir]
set -u
T=$(cd "$(dirname "$0")/.." && pwd)
L=${1:-$(mktemp -d)}; mkdir -p "$L"
DEBUGGER=${SILVERSCRIPT_DIR:-$T/contracts/.silverscript}/target/release/cli-debugger
fail=0
st() {
  local n=$1; shift
  if ( "$@" ) > "$L/$n.log" 2>&1; then echo "PASS $n"; else echo "FAIL $n (log: $L/$n.log)"; fail=1; fi
}

# A throwaway MongoDB for the relay, indexer and app stack tests.
M=$(mktemp -d); PORT=$((27100 + RANDOM % 800))
mongod --dbpath "$M" --port $PORT --bind_ip 127.0.0.1 --fork --logpath "$M/mongod.log" >/dev/null
trap 'mongod --dbpath "$M" --shutdown >/dev/null 2>&1; rm -rf "$M"' EXIT
export TEST_MONGO_URL=mongodb://127.0.0.1:$PORT

for p in protocol relay indexer app; do (cd "$T/$p" && npm ci --silent --no-audit --no-fund --ignore-scripts); done
st protocol           bash -c "cd $T/protocol && npm test"
st vectors-reproduce  bash -c "cd $T/protocol && cp vectors/v1.json $L/v1.before.json && npm run -s vectors && cmp vectors/v1.json $L/v1.before.json"
st bouncer            bash -c "cd $T/bouncer && npm test"
st swaprelay          bash -c "cd $T/swaprelay && npm test"
st relay              bash -c "cd $T/relay && npm test"
st indexer            bash -c "cd $T/indexer && npm test"
st app-build          bash -c "cd $T/app && npm run build"
st app-stack          bash -c "cd $T/app && npm test"
st reserved-reproduce bash -c "rm -rf $L/reserved && cp -r $T/registry/reserved $L/reserved && python3 -I $L/reserved/build_reserved.py >/dev/null && for f in reserved.csv patterns.json SUMMARY.md; do cmp $L/reserved/\$f $T/registry/reserved/\$f || exit 1; done"
st rust-impl          bash -c "cd $T/rust-impl && cargo test --locked --release"
st registry-reproduce bash -c "rm -rf $L/regen && mkdir $L/regen && python3 -I $T/contracts/tools/gen_registry_tests.py $L/regen >/dev/null && cmp $L/regen/registry_shard.test.json $T/contracts/registry_shard.test.json"
st registry           bash -c "cd $T/contracts && $DEBUGGER registry_shard.sil --test-file registry_shard.test.json --run-all"
st payment-reproduce  bash -c "rm -rf $L/payregen && mkdir $L/payregen && python3 -I $T/contracts/tools/gen_payment_tests.py $L/payregen >/dev/null && cmp $L/payregen/payment.test.json $T/contracts/payment.test.json"
st payment            bash -c "cd $T/contracts && $DEBUGGER payment.sil --test-file payment.test.json --run-all"
if ldconfig -p 2>/dev/null | grep -q libclang; then
  st engine           bash -c "SILVERSCRIPT_DIR=${SILVERSCRIPT_DIR:-$T/contracts/.silverscript} bash $T/contracts/tools/run_engine_tests.sh"
else
  echo "SKIP engine (the treasury engine tests build rusty-kaspa's RocksDB, which needs libclang)"
fi
st ceremony           bash -c "rm -rf $L/cer && cp -r $T/tools/ceremony $L/cer && cd $L/cer && cargo build --locked --release -q && bash rehearse-sim.sh $L/cer/target/release/kaspaveil-ceremony $L/cer-sim 0000000000000000000000000000000000000000000000000000000000000000 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
exit $fail
