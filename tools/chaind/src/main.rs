// Kaspaveil chain daemon (Phase 2, testnet-10). Localhost only: the relay/doorman service calls it after it has
// checked tokens, proof of work and the name policy. It holds the operational keys and does every on-chain write:
//   - relay-paid messages from the treasury's spending pot (chained, priced from the node's fee estimate), top-ups;
//   - registry shards: genesis, registerDefault / registerPrepaid / renewPrepaid with the registrar's signature;
//   - payments: one payment-covenant address per order (SC-0018); settling it (keyless) splits 25% Kaspaguy / 75% reservoir;
//   - lapsed names: `reclaim` at the end of grace (hourly job), then first-come claims (settleAuctionPrepaid at the monthly
//     price, or claimReleasedPrepaid), Kaspaguy 2026-10-14;
//   - the testnet faucet.
// Commands:
//   kaspaveil-chaind serve
//   kaspaveil-chaind deploy-pot <kas> [lanes=32] [floor_kas_per_hour=200]   spending pot: lanes under one covenant ID (SC-0019)
//   kaspaveil-chaind deploy-registry <price_kas>      16 shards (one genesis transaction, 16 covenant IDs)
//   kaspaveil-chaind fund-reservoir <month|long|topup> <kas>
//   kaspaveil-chaind address <keyname>
//   kaspaveil-chaind check-contracts        pre-deploy gate: the KASPAVEIL_*_SIL sources match the live chain state
// Env: KASPAVEIL_DATA (state dir), KASPAVEIL_RPC (Borsh wRPC of our own node), KASPAVEIL_HOT (silverscript helper),
// KASPAVEIL_HOT_SIL, KASPAVEIL_RES_SIL, KASPAVEIL_REG_SIL, KASPAVEIL_PAY_SIL (contract sources), KASPAVEIL_LISTEN (default 127.0.0.1:5512),
// KASPAVEIL_FAUCET=1 (testnet only: the /faucet route).
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    Hash,
    constants::{STORAGE_MASS_PARAMETER, TX_VERSION_TOCCATA},
    hashing::{
        covenant_id::covenant_id,
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    mass::{MassCalculator, SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT},
    sign::sign,
    subnets::{SUBNETWORK_ID_NATIVE, SubnetworkId},
    tx::{
        CovenantBinding, PopulatedTransaction, ScriptPublicKey, SignableTransaction, Transaction, TransactionId, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_rpc_core::{RpcUtxosByAddressesEntry, api::rpc::RpcApi};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_address_script, pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const LANE: [u8; 20] = *b"KVL\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const KAS: u64 = 100_000_000;
const COINBASE_MATURITY: u64 = 2_000;
const MONTH_DAA: u64 = 25_920_000;
const LONG_DAA: u64 = 12 * MONTH_DAA;
const SHARD_VALUE: u64 = KAS;
const SHARDS: usize = 16;
const DEPTH: usize = 20;
const POT_MAX_FEE: u64 = 100_000_000;
const GRACE_DAA: u64 = MONTH_DAA;
const PAY_MAX_FEE: u64 = 1_000_000;
const PAY_LATE_DAA: u64 = 2_592_000; // payment.sil LATE_DAA: a payment this old settles on its own (settleLate)

type Res<T> = Result<T, String>;

// ---------- small helpers ----------

fn unhex(s: &str) -> Vec<u8> {
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).expect("hex");
    out
}
fn hx(b: &[u8]) -> String {
    faster_hex::hex_string(b)
}
fn b32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}
fn blake(data: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new().hash_length(32).hash(data).as_bytes().try_into().unwrap()
}
fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}
fn data(p: &str) -> String {
    format!("{}/{p}", env("KASPAVEIL_DATA"))
}
fn ab(b: &[u8]) -> Value {
    json!({"kind": "bytes", "value": b})
}
fn ai(i: u64) -> Value {
    json!({"kind": "int", "value": i as i64})
}
fn aarr(v: &[[u8; 32]]) -> Value {
    json!({"kind": "array", "value": v.iter().map(|b| ab(b)).collect::<Vec<_>>()})
}

fn keypair_from(path: &str) -> secp256k1::Keypair {
    let hex = std::fs::read_to_string(path).expect("read key").trim().to_string();
    secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &unhex(&hex)).expect("valid key")
}
// Operational keys live in <data>/keys/<name>.key (created on first use, mode 600). Testnet only.
fn key(name: &str) -> secp256k1::Keypair {
    let path = data(&format!("keys/{name}.key"));
    if !std::path::Path::new(&path).exists() {
        std::fs::create_dir_all(data("keys")).unwrap();
        let sk: [u8; 32] = rand::random();
        std::fs::write(&path, hx(&sk)).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }
    keypair_from(&path)
}
fn xonly(kp: &secp256k1::Keypair) -> [u8; 32] {
    kp.x_only_public_key().0.serialize()
}
fn p2pk_address(kp: &secp256k1::Keypair) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &xonly(kp))
}
fn p2sh_address(spk: &ScriptPublicKey) -> Address {
    Address::new(Prefix::Testnet, Version::ScriptHash, &spk.script()[2..34])
}
// Script public key as the contracts see it: 2-byte version + script.
fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut v = spk.version().to_be_bytes().to_vec();
    v.extend_from_slice(spk.script());
    v
}
fn schnorr(kp: &secp256k1::Keypair, digest: [u8; 32]) -> Vec<u8> {
    kp.sign_schnorr(secp256k1::Message::from_digest(digest)).as_ref().to_vec()
}

// The silverscript helper (compiles contracts, encodes state and entry calls). Results are memoised: the same
// arguments always give the same bytes.
static HELPER_CACHE: StdMutex<Option<HashMap<String, Vec<u8>>>> = StdMutex::new(None);
fn helper(args: &[String]) -> Vec<u8> {
    let k = args.join(" ");
    if let Some(v) = HELPER_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(&k) {
        return v.clone();
    }
    let out = std::process::Command::new(env("KASPAVEIL_HOT")).args(args).output().expect("run kaspaveil_hot");
    assert!(out.status.success(), "kaspaveil_hot: {}", String::from_utf8_lossy(&out.stderr));
    let v = unhex(String::from_utf8(out.stdout).unwrap().trim());
    HELPER_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(k, v.clone());
    v
}
fn helper_json(sil: &str, req: &Value) -> (Vec<u8>, Option<Vec<u8>>) {
    use std::io::Write;
    let mut child = std::process::Command::new(env("KASPAVEIL_HOT"))
        .args(["json", sil])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run kaspaveil_hot");
    child.stdin.take().unwrap().write_all(req.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "kaspaveil_hot json: {}", String::from_utf8_lossy(&out.stderr));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    (unhex(r["bytecode"].as_str().unwrap()), r["sigscript"].as_str().map(unhex))
}

// ---------- chain access ----------

fn rpc_client() -> KaspaRpcClient {
    KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&env("KASPAVEIL_RPC")), None, Some(NetworkId::with_suffix(NetworkType::Testnet, 10)), None)
        .expect("client")
}
async fn connect() -> KaspaRpcClient {
    let client = rpc_client();
    let opts = ConnectOptions { block_async_connect: true, connect_timeout: Some(Duration::from_secs(10)), strategy: ConnectStrategy::Retry, ..Default::default() };
    client.connect(Some(opts)).await.expect("connect to our testnet-10 node");
    client
}
async fn now_daa(c: &KaspaRpcClient) -> Res<u64> {
    Ok(c.get_server_info().await.map_err(|e| e.to_string())?.virtual_daa_score)
}
fn spendable(u: &RpcUtxosByAddressesEntry, now: u64) -> bool {
    !u.utxo_entry.is_coinbase || u.utxo_entry.block_daa_score + COINBASE_MATURITY <= now
}
async fn utxos(c: &KaspaRpcClient, a: &Address) -> Res<Vec<RpcUtxosByAddressesEntry>> {
    c.get_utxos_by_addresses(vec![a.clone()]).await.map_err(|e| e.to_string())
}

fn masses(tx: &Transaction, entries: &[UtxoEntry]) -> (u64, u64, u64) {
    let calc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    let nc = calc.calc_non_contextual_masses(tx);
    let storage = calc.calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec())).map(|m| m.storage_mass).unwrap_or(u64::MAX / 4);
    (nc.compute_mass, nc.transient_mass, storage)
}
// The fee to pay: the node's priority feerate (never below the 100 sompi/gram floor) times the binding mass, where
// storage mass counts for funding transactions (a small change output can make it the largest).
fn fee_for(tx: &Transaction, entries: &[UtxoEntry], feerate: f64, with_storage: bool) -> u64 {
    // Unsigned P2PK inputs get a placeholder of a signature's size (push + 64 + hash type), so the mass is the signed one.
    let mut t = tx.clone();
    for i in t.inputs.iter_mut().filter(|i| i.signature_script.is_empty()) {
        i.signature_script = vec![0; 66];
    }
    let (compute, transient, storage) = masses(&t, entries);
    let mut m = compute.max(transient / 2);
    if with_storage {
        m = m.max(storage);
    }
    (m as f64 * feerate.max(100.0)).ceil() as u64 + 5_000
}
fn set_storage_mass(tx: &Transaction, entries: &[UtxoEntry]) {
    tx.set_storage_mass(masses(tx, entries).2);
}
fn dry_run(tx: &Transaction, entries: &[UtxoEntry], only: Option<usize>) -> Res<Vec<u64>> {
    let reused = SigHashReusedValuesUnsync::new();
    let cache = Cache::new(100);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov = CovenantsContext::from_tx(&populated).map_err(|e| format!("covenants: {e:?}"))?;
    let mut used = vec![];
    for i in 0..tx.inputs.len() {
        if only.is_some_and(|o| o != i) {
            used.push(0);
            continue;
        }
        let ctx = EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov);
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(&populated, &tx.inputs[i], i, &entries[i], ctx, EngineFlags::default(), u64::MAX.into());
        vm.execute().map_err(|e| format!("input {i}: {e}"))?;
        used.push(vm.used_script_units().0);
    }
    Ok(used)
}
fn budget(units: u64) -> u16 {
    units.div_ceil(SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT).max(1) as u16
}
fn sign_p2pk_input(tx: &mut Transaction, entries: &[UtxoEntry], i: usize, kp: &secp256k1::Keypair) {
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&PopulatedTransaction::new(tx, entries.to_vec()), i, SIG_HASH_ALL, &reused);
    let mut sig = schnorr(kp, hash.as_bytes());
    sig.push(SIG_HASH_ALL.to_u8());
    tx.inputs[i].signature_script = ScriptBuilder::new().add_data(&sig).unwrap().drain();
}

async fn submit(c: &KaspaRpcClient, tx: &Transaction) -> Res<TransactionId> {
    c.submit_transaction(tx.into(), false).await.map_err(|e| e.to_string())
}
// Waits until output `index` of txid is in the UTXO set at `watch` (accepted by the DAG).
async fn wait_accepted(c: &KaspaRpcClient, txid: TransactionId, watch: &Address, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(us) = utxos(c, watch).await
            && us.iter().any(|u| u.outpoint.transaction_id == txid)
        {
            return true;
        }
    }
    false
}

// ---------- the pot (same rules as contracts/treasury_hot.sil) ----------
// SC-0019: the pot is a set of LANES under one covenant ID, each with its own state and a floor of (pot floor / lanes).
// SC-0020: one relay-paid transaction carries up to BATCH messages of 1,536 bytes, concatenated in its payload.

const INTERVAL_DAA: u64 = 36_000;
const N: u64 = 168;
const K: u64 = 5;
const RES_MAX_FEE: u64 = 1_000_000;
const MSG_LEN: usize = 1536;
const BATCH: usize = 5;
// How long a relayed message waits in the mix before it is broadcast, in ms (uniform).
const MIX_MS: std::ops::RangeInclusive<u64> = 500..=4_000;

// One batch out of the mix: the message that is due first, up to BATCH-1 others chosen at random, in random order.
fn mix_take<I: Ord + Copy, T>(pool: &mut Vec<(I, T)>, rng: &mut impl rand::Rng) -> Vec<T> {
    use rand::seq::SliceRandom;
    let i = pool.iter().enumerate().min_by_key(|(_, p)| p.0).map(|(i, _)| i).expect("mix_take on an empty pool");
    let mut batch = vec![pool.swap_remove(i).1];
    pool.shuffle(rng);
    let n = pool.len().min(BATCH - 1);
    batch.extend(pool.drain(..n).map(|p| p.1));
    batch.shuffle(rng);
    batch
}

#[derive(Clone, Debug)]
struct Pot {
    cov: Hash,
    root: [u8; 32],
    floor: u64,
    relay: [u8; 32],
    interval: u64,
    spent: u64,
    smma: u64,
    nonce: u64,
    outpoint: TransactionOutpoint,
    value: u64,
}

impl Pot {
    fn line(&self) -> String {
        format!("{} {} {} {} {} {} {} {} {} {} {}", hx(&self.cov.as_bytes()), hx(&self.root), self.floor, hx(&self.relay), self.interval, self.spent, self.smma,
            self.nonce, hx(&self.outpoint.transaction_id.as_bytes()), self.outpoint.index, self.value)
    }
    fn from_line(l: &str) -> Option<Pot> {
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() != 11 {
            return None;
        }
        Some(Pot {
            cov: Hash::from_bytes(b32(f[0])), root: b32(f[1]), floor: f[2].parse().ok()?, relay: b32(f[3]), interval: f[4].parse().ok()?, spent: f[5].parse().ok()?,
            smma: f[6].parse().ok()?, nonce: f[7].parse().ok()?, outpoint: TransactionOutpoint::new(TransactionId::from_bytes(b32(f[8])), f[9].parse().ok()?), value: f[10].parse().ok()?,
        })
    }
    fn save(&self, path: &str) {
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, self.line()).expect("write pot state");
        std::fs::rename(tmp, path).unwrap();
    }
    fn helper_args(&self, cmd: &str) -> Vec<String> {
        vec![cmd.into(), env("KASPAVEIL_HOT_SIL"), hx(&self.root), self.floor.to_string(), hx(&self.relay), self.interval.to_string(), self.spent.to_string(), self.smma.to_string(), self.nonce.to_string()]
    }
    fn spk(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&helper(&self.helper_args("pot-bytecode")))
    }
    fn address(&self) -> Address {
        p2sh_address(&self.spk())
    }
    fn entry(&self) -> UtxoEntry {
        UtxoEntry::new(self.value, self.spk(), 0, false, Some(self.cov))
    }
    fn output(&self, value: u64) -> TransactionOutput {
        TransactionOutput { value, script_public_key: self.spk(), covenant: Some(CovenantBinding::new(0, self.cov)) }
    }
    fn smma_at(&self, cur: u64) -> u64 {
        if cur <= self.interval {
            return self.smma;
        }
        let s = (self.smma * (N - 1) + self.spent) / N;
        let gap = cur - self.interval - 1;
        if gap >= N { 0 } else { s * (N - gap) / N }
    }
    fn allowance(&self, s: u64) -> u64 {
        (K * s).max(self.floor)
    }
    fn rolled(&self, cur: u64, add: u64) -> Pot {
        let s = self.smma_at(cur);
        let base = if cur == self.interval { self.spent } else { 0 };
        Pot { interval: cur, spent: base + add, smma: s, ..self.clone() }
    }
    fn left(&self, cur: u64) -> u64 {
        let s = self.smma_at(cur);
        let base = if cur == self.interval { self.spent } else { 0 };
        self.allowance(s).saturating_sub(base)
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ResKind {
    Month,
    Long,
    Topup,
}
impl ResKind {
    fn age(self) -> u64 {
        match self {
            ResKind::Month => MONTH_DAA,
            ResKind::Long => LONG_DAA,
            ResKind::Topup => 0,
        }
    }
    fn parse(s: &str) -> Option<ResKind> {
        match s {
            "month" => Some(ResKind::Month),
            "long" => Some(ResKind::Long),
            "topup" => Some(ResKind::Topup),
            _ => None,
        }
    }
}
// Reservoir compile arguments: potCov, sweep age, sweep script (to the Kaspaguy dev address).
fn res_args(cmd: &str, cov: Hash, kind: ResKind) -> Vec<String> {
    let to = spk_bytes(&pay_to_address_script(&p2pk_address(&key("dev"))));
    vec![cmd.into(), env("KASPAVEIL_RES_SIL"), hx(&cov.as_bytes()), kind.age().to_string(), hx(&to)]
}
fn res_spk(cov: Hash, kind: ResKind) -> ScriptPublicKey {
    pay_to_script_hash_script(&helper(&res_args("res-bytecode", cov, kind)))
}

// One lane: its latest (possibly unconfirmed) state, the newest confirmed one, and the submitted-but-unconfirmed spends,
// which are also logged to disk so a restart continues from the real chain tip.
struct Lane {
    idx: usize,
    pot: Pot,
    confirmed: Pot,
    pending: Vec<(TransactionId, Pot, Vec<u8>)>,
    since: Instant,
}
impl Lane {
    fn state_path(i: usize) -> String {
        data(&format!("pot/lane{i}.state"))
    }
    fn log_path(i: usize) -> String {
        data(&format!("pot/lane{i}.pending.log"))
    }
    fn load(i: usize) -> Lane {
        let confirmed = Pot::from_line(std::fs::read_to_string(Lane::state_path(i)).expect("lane state").trim()).expect("lane state format");
        let pending: Vec<_> = std::fs::read_to_string(Lane::log_path(i)).unwrap_or_default().lines().filter_map(Pot::from_line).map(|q| (q.outpoint.transaction_id, q, vec![])).collect();
        let pot = pending.last().map(|x: &(TransactionId, Pot, Vec<u8>)| x.1.clone()).unwrap_or_else(|| confirmed.clone());
        Lane { idx: i, pot, confirmed, pending, since: Instant::now() }
    }
    fn append(&self, p: &Pot) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(Lane::log_path(self.idx)) {
            let _ = writeln!(f, "{}", p.line());
        }
    }
    fn rewrite(&self) {
        let s: String = self.pending.iter().map(|(_, p, _)| p.line() + "\n").collect();
        let tmp = Lane::log_path(self.idx) + ".tmp";
        std::fs::write(&tmp, s).unwrap();
        std::fs::rename(tmp, Lane::log_path(self.idx)).unwrap();
    }
    fn push(&mut self, id: TransactionId, next: Pot, payload: Vec<u8>) {
        self.append(&next);
        if self.pending.is_empty() {
            self.since = Instant::now();
        }
        self.pending.push((id, next.clone(), payload));
        self.pot = next;
    }
}

struct Treasury {
    cov: Hash,
    lanes: Vec<Arc<Mutex<Lane>>>,
    used_res: StdMutex<HashMap<TransactionOutpoint, Instant>>,
    res_lock: Mutex<()>,
    next: std::sync::atomic::AtomicUsize,
    sent: std::sync::atomic::AtomicU64,
    fees: std::sync::atomic::AtomicU64,
}
// data/pot/lanes: "<covenant id> <lanes>"
fn treasury_cov() -> Hash {
    let s = std::fs::read_to_string(data("pot/lanes")).expect("pot not deployed");
    Hash::from_bytes(b32(s.split(' ').next().unwrap()))
}
fn load_treasury() -> Option<Treasury> {
    let s = std::fs::read_to_string(data("pot/lanes")).ok()?;
    let f: Vec<&str> = s.split_whitespace().collect();
    let n: usize = f[1].parse().ok()?;
    let lanes: Vec<_> = (0..n).map(|i| Arc::new(Mutex::new(Lane::load(i)))).collect();
    eprintln!("treasury: {n} lanes loaded");
    Some(Treasury {
        cov: Hash::from_bytes(b32(f[0])), lanes, used_res: StdMutex::new(HashMap::new()), res_lock: Mutex::new(()),
        next: Default::default(), sent: Default::default(), fees: Default::default(),
    })
}
type Job = (Vec<u8>, tokio::sync::oneshot::Sender<Res<(String, usize)>>);

// ---------- registry ----------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Leaf {
    key: u64,
    next_key: u64,
    next_idx: u64,
    owner: String,
    expiry: u64,
    nonce: u64,
    #[serde(default)]
    name: Option<String>,
}
impl Leaf {
    fn hash(&self) -> [u8; 32] {
        let mut m = Vec::with_capacity(72);
        for v in [self.key, self.next_key, self.next_idx] {
            m.extend(v.to_le_bytes());
        }
        m.extend(b32(&self.owner));
        m.extend(self.expiry.to_le_bytes());
        m.extend(self.nonce.to_le_bytes());
        blake(&m)
    }
    fn sentinel() -> Leaf {
        Leaf { key: 0, next_key: 0, next_idx: 0, owner: hx(&[0; 32]), expiry: 0, nonce: 0, name: None }
    }
}

#[derive(Clone)]
struct Tree {
    leaves: Vec<Leaf>,
    nodes: Vec<HashMap<u64, [u8; 32]>>,
    zeros: [[u8; 32]; DEPTH + 1],
}
impl Tree {
    fn new(leaves: Vec<Leaf>) -> Tree {
        let mut zeros = [[0u8; 32]; DEPTH + 1];
        for l in 1..=DEPTH {
            zeros[l] = blake(&[zeros[l - 1], zeros[l - 1]].concat());
        }
        let mut t = Tree { leaves: vec![], nodes: vec![HashMap::new(); DEPTH + 1], zeros };
        for (i, l) in leaves.into_iter().enumerate() {
            t.leaves.push(l.clone());
            t.update(i as u64);
        }
        t
    }
    fn node(&self, level: usize, idx: u64) -> [u8; 32] {
        *self.nodes[level].get(&idx).unwrap_or(&self.zeros[level])
    }
    fn update(&mut self, idx: u64) {
        let mut h = self.leaves[idx as usize].hash();
        let mut i = idx;
        self.nodes[0].insert(i, h);
        for l in 0..DEPTH {
            let sib = self.node(l, i ^ 1);
            h = if i.is_multiple_of(2) { blake(&[h, sib].concat()) } else { blake(&[sib, h].concat()) };
            i /= 2;
            self.nodes[l + 1].insert(i, h);
        }
    }
    fn root(&self) -> [u8; 32] {
        self.node(DEPTH, 0)
    }
    fn path(&self, idx: u64) -> Vec<[u8; 32]> {
        (0..DEPTH).map(|l| self.node(l, (idx >> l) ^ 1)).collect()
    }
    fn find(&self, key: u64) -> Option<usize> {
        self.leaves.iter().position(|l| l.key == key && key != 0)
    }
    // registerDefault / registerPrepaid insertion arguments (after the name-specific ones), and the tree after it.
    fn insert(&self, key: u64, owner: [u8; 32], expiry: u64, name: &str) -> Res<(Vec<Value>, Tree)> {
        if self.find(key).is_some() {
            return Err("name taken".into());
        }
        let low = self.leaves.iter().position(|l| l.key < key && (l.next_key == 0 || key < l.next_key)).ok_or("no low leaf")? as u64;
        let mut t = self.clone();
        let size = t.leaves.len() as u64;
        let lowl = t.leaves[low as usize].clone();
        let low_path = t.path(low);
        t.leaves[low as usize].next_key = key;
        t.leaves[low as usize].next_idx = size;
        t.update(low);
        let new_path = t.path(size);
        t.leaves.push(Leaf { key, next_key: lowl.next_key, next_idx: lowl.next_idx, owner: hx(&owner), expiry, nonce: 0, name: Some(name.into()) });
        t.update(size);
        let args = vec![
            ai(lowl.key), ai(lowl.next_key), ai(lowl.next_idx), ab(&b32(&lowl.owner)), ai(lowl.expiry), ai(lowl.nonce), ai(low),
            aarr(&low_path), aarr(&new_path),
        ];
        Ok((args, t))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardState {
    root: String,
    size: u64,
    registrar: String,
    price_key: String,
    auction_key: String,
    price: u64,
    price_nonce: u64,
    key_nonce: u64,
    prepaid_regs: u64,
    prepaid_months: u64,
    #[serde(default)]
    transfers_open: u64,
}
impl ShardState {
    fn json(&self) -> Value {
        json!({
            "root": ab(&b32(&self.root)), "size": ai(self.size), "registrar": ab(&b32(&self.registrar)), "priceKey": ab(&b32(&self.price_key)),
            "auctionKey": ab(&b32(&self.auction_key)), "price": ai(self.price), "priceNonce": ai(self.price_nonce), "keyNonce": ai(self.key_nonce),
            "prepaidRegs": ai(self.prepaid_regs), "prepaidMonths": ai(self.prepaid_months), "transfersOpen": ai(self.transfers_open)
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Shard {
    id: u64,
    cov: String,
    txid: String,
    index: u32,
    value: u64,
    state: ShardState,
    leaves: Vec<Leaf>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RegistryFile {
    registry_id: String,
    dev: String,
    root_key: String,
    res_month_spk: String,
    res_long_spk: String,
    init_price: u64,
    shards: Vec<Shard>,
}

struct Registry {
    file: RegistryFile,
    trees: Vec<Tree>,
}
impl Registry {
    fn load() -> Option<Registry> {
        let s = std::fs::read_to_string(data("registry.json")).ok()?;
        let file: RegistryFile = serde_json::from_str(&s).expect("registry.json");
        let trees = file.shards.iter().map(|sh| Tree::new(sh.leaves.clone())).collect();
        Some(Registry { file, trees })
    }
    fn save(&mut self) {
        for (sh, t) in self.file.shards.iter_mut().zip(&self.trees) {
            sh.leaves = t.leaves.clone();
        }
        let tmp = data("registry.json.tmp");
        std::fs::write(&tmp, serde_json::to_string(&self.file).unwrap()).unwrap();
        std::fs::rename(tmp, data("registry.json")).unwrap();
    }
    fn ctor(&self, shard: u64) -> Value {
        let f = &self.file;
        let s0 = &f.shards[shard as usize].state;
        json!([
            ab(&self.trees[0].zeros[0]), ab(&b32(&f.registry_id)), ai(shard), ab(&b32(&f.dev)), ab(&unhex(&f.res_month_spk)), ab(&unhex(&f.res_long_spk)),
            ab(&b32(&f.root_key)), ab(&b32(&s0.registrar)), ab(&b32(&s0.price_key)), ab(&b32(&s0.auction_key)), ai(f.init_price)
        ])
    }
    fn domain(&self, label: &str, shard: u64) -> Vec<u8> {
        [b"kasveil/v1/".as_slice(), label.as_bytes(), &b32(&self.file.registry_id), &shard.to_le_bytes()].concat()
    }
}

fn name_key(name: &str) -> u64 {
    let h = blake(name.as_bytes());
    let mut k = [0u8; 8];
    k[..7].copy_from_slice(&h[..7]);
    u64::from_le_bytes(k)
}
fn default_name(owner: &[u8; 32], n: u8) -> String {
    let h = blake(&[owner.as_slice(), &[n]].concat());
    let mut v: u64 = 0;
    for b in &h[..5] {
        v = v * 256 + *b as u64;
    }
    let alpha = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = String::from("kv");
    for i in 0..8 {
        s.push(alpha[((v >> (5 * (7 - i))) & 31) as usize] as char);
    }
    s
}
fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    (3..=20).contains(&b.len()) && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') && b[0] != b'-' && b[b.len() - 1] != b'-'
}

// ---------- the daemon ----------

struct Daemon {
    client: KaspaRpcClient,
    treasury: Option<Arc<Treasury>>,
    batch: Option<tokio::sync::mpsc::Sender<Job>>,
    registry: Mutex<Option<Registry>>,
    fund: Mutex<()>,
    feerate: StdMutex<(f64, Instant)>,
}
type App = Arc<Daemon>;

impl Daemon {
    async fn feerate(&self) -> f64 {
        {
            let f = self.feerate.lock().unwrap();
            if f.1.elapsed() < Duration::from_secs(10) {
                return f.0;
            }
        }
        let r = self.client.get_fee_estimate().await.map(|e| e.priority_bucket.feerate).unwrap_or(100.0);
        *self.feerate.lock().unwrap() = (r, Instant::now());
        r
    }

    // ---- fund wallet (registry fees, faucet, genesis) ----
    async fn fund_utxo(&self, min: u64) -> Res<(TransactionOutpoint, UtxoEntry)> {
        let addr = p2pk_address(&key("fund"));
        let now = now_daa(&self.client).await?;
        let us = utxos(&self.client, &addr).await?;
        let u = us.iter().filter(|u| spendable(u, now) && u.utxo_entry.amount >= min).max_by_key(|u| u.utxo_entry.amount).ok_or("fund wallet has no large enough UTXO")?;
        Ok((u.outpoint.into(), u.utxo_entry.clone().into()))
    }

    // Merges up to 80 small spendable fund UTXOs (mined coinbase outputs) into one, so payments, genesis and
    // registry fees find a large enough coin. Returns how many were merged.
    async fn consolidate(&self) -> Res<usize> {
        let _g = self.fund.lock().await;
        let kp = key("fund");
        let addr = p2pk_address(&kp);
        let now = now_daa(&self.client).await?;
        let mut us: Vec<_> = utxos(&self.client, &addr).await?.into_iter().filter(|u| spendable(u, now)).collect();
        us.sort_by_key(|u| u.utxo_entry.amount);
        us.truncate(80);
        if us.len() < 10 {
            return Ok(0);
        }
        let entries: Vec<UtxoEntry> = us.iter().map(|u| u.utxo_entry.clone().into()).collect();
        let total: u64 = entries.iter().map(|e| e.amount).sum();
        let build = |fee: u64| {
            let ins = us.iter().map(|u| TransactionInput::new_with_compute_budget(u.outpoint.into(), vec![], 0, 10)).collect();
            Transaction::new(TX_VERSION_TOCCATA, ins, vec![TransactionOutput::new(total - fee, pay_to_address_script(&addr))], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
        };
        let fee = fee_for(&build(0), &entries, self.feerate().await, true);
        let tx = build(fee);
        set_storage_mass(&tx, &entries);
        let mut signed = sign(SignableTransaction::with_entries(tx, entries), kp).tx;
        signed.finalize();
        let id = submit(&self.client, &signed).await?;
        if !wait_accepted(&self.client, id, &addr, 60).await {
            return Err(format!("consolidation {id} not accepted"));
        }
        Ok(us.len())
    }

    async fn pay(&self, to: Address, sompi: u64) -> Res<String> {
        let _g = self.fund.lock().await;
        let kp = key("fund");
        let (op, entry) = self.fund_utxo(sompi + KAS).await?;
        let feerate = self.feerate().await;
        let build = |fee: u64| {
            let input = TransactionInput::new_with_compute_budget(op, vec![], 0, 10);
            let outs = vec![TransactionOutput::new(sompi, pay_to_address_script(&to)), TransactionOutput::new(entry.amount - sompi - fee, pay_to_address_script(&p2pk_address(&kp)))];
            Transaction::new(TX_VERSION_TOCCATA, vec![input], outs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
        };
        let fee = fee_for(&build(0), std::slice::from_ref(&entry), feerate, true);
        let tx = build(fee);
        set_storage_mass(&tx, std::slice::from_ref(&entry));
        let mut signed = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
        signed.finalize();
        let id = submit(&self.client, &signed).await?;
        if !wait_accepted(&self.client, id, &to, 60).await {
            return Err(format!("payment {id} not accepted within 60 s"));
        }
        Ok(id.to_string())
    }

    // ---- relay-paid messages: lanes + batches ----
    // Queues one message; the batcher sends it with up to BATCH-1 others in one transaction on a free lane. Returns the
    // transaction ID and the message's index in its payload.
    async fn relay_send(&self, payload: Vec<u8>) -> Res<(String, usize)> {
        if payload.len() != MSG_LEN {
            return Err("a message is exactly 1,536 bytes".into());
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.batch.as_ref().ok_or("pot not deployed")?.send((payload, tx)).await.map_err(|_| "relay stopped".to_string())?;
        rx.await.map_err(|_| "relay dropped the message".to_string())?
    }

    // A free lane (starting from a rotating offset); waits for one only if every lane is busy.
    async fn pick_lane(&self, t: &Treasury, skip: &[usize]) -> Option<tokio::sync::OwnedMutexGuard<Lane>> {
        let n = t.lanes.len();
        let start = t.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for k in 0..n {
            let i = (start + k) % n;
            if skip.contains(&i) {
                continue;
            }
            if let Ok(g) = t.lanes[i].clone().try_lock_owned() {
                return Some(g);
            }
        }
        let i = (0..n).map(|k| (start + k) % n).find(|i| !skip.contains(i))?;
        Some(t.lanes[i].clone().lock_owned().await)
    }

    async fn send_batch(&self, batch: Vec<Job>) {
        let t = self.treasury.clone().unwrap();
        let payload: Vec<u8> = batch.iter().flat_map(|j| j.0.clone()).collect();
        let mut tried = vec![];
        let mut last = String::from("no lane");
        while tried.len() < t.lanes.len() {
            let Some(mut lane) = self.pick_lane(&t, &tried).await else { break };
            tried.push(lane.idx);
            match self.lane_send(&t, &mut lane, &payload).await {
                Ok(id) => {
                    for (i, (_, reply)) in batch.into_iter().enumerate() {
                        let _ = reply.send(Ok((id.clone(), i)));
                    }
                    return;
                }
                Err(e) => {
                    let throttled = e.contains("allowance");
                    last = e;
                    if !throttled {
                        break;
                    }
                }
            }
        }
        for (_, reply) in batch {
            let _ = reply.send(Err(last.clone()));
        }
    }

    async fn lane_send(&self, t: &Treasury, lane: &mut Lane, payload: &[u8]) -> Res<String> {
        let lock = now_daa(&self.client).await? - 10;
        let cur = lock / INTERVAL_DAA;
        let feerate = self.feerate().await;
        if lane.pot.value * 2 <= lane.pot.allowance(lane.pot.smma_at(cur))
            && let Err(e) = self.top_up(t, lane, lock).await
        {
            eprintln!("lane {} top-up: {e}", lane.idx);
        }
        let cap = lane.pot.left(cur).min(POT_MAX_FEE);
        let (tx, next) = build_message(&lane.pot, &key("relay"), payload, lock, feerate, cap)?;
        let fee = lane.pot.value - next.value;
        let id = match submit(&self.client, &tx).await {
            Ok(id) => id,
            Err(e) => {
                eprintln!("lane {} submit failed ({e}); resyncing", lane.idx);
                self.resync(lane).await;
                return Err(format!("submit: {e}"));
            }
        };
        lane.push(id, next, payload.to_vec());
        t.sent.fetch_add((payload.len() / MSG_LEN) as u64, std::sync::atomic::Ordering::Relaxed);
        t.fees.fetch_add(fee, std::sync::atomic::Ordering::Relaxed);
        Ok(id.to_string())
    }

    // Fills a lane up to its allowance from the newest reservoir UTXO no other lane is using.
    async fn top_up(&self, t: &Treasury, lane: &mut Lane, lock: u64) -> Res<()> {
        let _g = t.res_lock.lock().await;
        let pot = lane.pot.clone();
        let cur = lock / INTERVAL_DAA;
        t.used_res.lock().unwrap().retain(|_, at| at.elapsed() < Duration::from_secs(900));
        let mut best: Option<(ResKind, RpcUtxosByAddressesEntry)> = None;
        for kind in [ResKind::Month, ResKind::Long, ResKind::Topup] {
            for u in utxos(&self.client, &p2sh_address(&res_spk(pot.cov, kind))).await? {
                let op: TransactionOutpoint = u.outpoint.into();
                if t.used_res.lock().unwrap().contains_key(&op) {
                    continue;
                }
                if best.as_ref().is_none_or(|b| u.utxo_entry.block_daa_score > b.1.utxo_entry.block_daa_score) {
                    best = Some((kind, u));
                }
            }
        }
        let (kind, u) = best.ok_or("reservoirs are empty")?;
        let rentry: UtxoEntry = u.utxo_entry.clone().into();
        let rspk = res_spk(pot.cov, kind);
        let next = pot.rolled(cur, 0);
        let cap = next.allowance(next.smma);
        let pot_sig = helper(&[pot.helper_args("pot-step"), vec![hx(&[0u8; 65])]].concat());
        let res_sig = helper(&res_args("res-topup", pot.cov, kind));
        let entries = vec![pot.entry(), rentry.clone()];
        let whole = pot.value + rentry.amount <= cap + RES_MAX_FEE;
        let build = |fee: u64, b0: u16, b1: u16| {
            let ins = vec![
                TransactionInput::new_with_compute_budget(pot.outpoint, pot_sig.clone(), 0, b0),
                TransactionInput::new_with_compute_budget(u.outpoint.into(), res_sig.clone(), 0, b1),
            ];
            let outs = if whole {
                vec![next.output(pot.value + rentry.amount - fee)]
            } else {
                vec![next.output(cap), TransactionOutput::new(rentry.amount - (cap - pot.value) - fee, rspk.clone())]
            };
            Transaction::new(TX_VERSION_TOCCATA, ins, outs, lock, SUBNETWORK_ID_NATIVE, 0, vec![])
        };
        let units = dry_run(&build(RES_MAX_FEE, 200, 200), &entries, None)?;
        let (b0, b1) = (budget(units[0]), budget(units[1]));
        let fee = fee_for(&build(0, b0, b1), &entries, self.feerate().await, false).min(RES_MAX_FEE);
        let mut tx = build(fee, b0, b1);
        set_storage_mass(&tx, &entries);
        tx.finalize();
        dry_run(&tx, &entries, None)?;
        let id = submit(&self.client, &tx).await?;
        let after = Pot { outpoint: TransactionOutpoint::new(id, 0), value: tx.outputs[0].value, ..next };
        eprintln!("lane {} top-up {id}: {} -> {} sompi from the {kind:?} reservoir", lane.idx, pot.value, after.value);
        t.used_res.lock().unwrap().insert(u.outpoint.into(), Instant::now());
        lane.push(id, after, vec![]);
        Ok(())
    }

    // Moves a lane's `confirmed` forward: spends leave the mempool oldest first, so a binary search finds the first one
    // still there. If none is left, the newest is confirmed only if its output is in the UTXO set; otherwise the chain was
    // dropped and, after 30 s, it is rebuilt from the confirmed state with the dropped messages resubmitted.
    async fn confirm(&self, lane: &mut Lane) {
        let n = lane.pending.len();
        if n == 0 {
            return;
        }
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.client.get_mempool_entry(lane.pending[mid].0, false, false).await.is_ok() {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        let mut done = lo;
        if lo == n {
            let (id, pot, _) = &lane.pending[n - 1];
            let live = utxos(&self.client, &pot.address()).await.map(|us| us.iter().any(|u| u.outpoint.transaction_id == *id)).unwrap_or(false);
            if !live {
                done = 0;
            }
        }
        if done > 0 {
            lane.confirmed = lane.pending[done - 1].1.clone();
            lane.pending.drain(..done);
            lane.confirmed.save(&Lane::state_path(lane.idx));
            lane.rewrite();
            lane.since = Instant::now();
        } else if lane.since.elapsed() > Duration::from_secs(30) {
            self.resync(lane).await;
        }
    }

    async fn resync(&self, lane: &mut Lane) {
        let dropped: Vec<Vec<u8>> = lane.pending.drain(..).map(|p| p.2).filter(|p| !p.is_empty()).collect();
        lane.rewrite();
        eprintln!("lane {} resync: back to the confirmed state, resubmitting {} transactions", lane.idx, dropped.len());
        lane.pot = lane.confirmed.clone();
        let Ok(n) = now_daa(&self.client).await else { return };
        let lock = n - 10;
        let feerate = self.feerate().await;
        for payload in dropped {
            if let Ok((tx, next)) = build_message(&lane.pot, &key("relay"), &payload, lock, feerate, lane.pot.left(lock / INTERVAL_DAA).min(POT_MAX_FEE))
                && let Ok(id) = submit(&self.client, &tx).await
            {
                lane.push(id, next, payload);
            }
        }
    }

    // ---- registry ----
    // Builds, checks and submits one registry spend: input 0 the shard (entry call), input 1 a fund UTXO paying the fee;
    // output 0 the shard's continuation (new state, same covenant ID), output 1 change. Waits for acceptance.
    // simulate: build against a stand-in shard UTXO and run the real script engine locally, without submitting (for
    // spends that can't happen on the live chain yet, e.g. a lapse 60 days out); `reg` should then be a scratch copy.
    async fn registry_spend(&self, reg: &mut Registry, shard: u64, entry: &str, args: Vec<Value>, next: ShardState, lock: u64, tree: Tree, simulate: bool) -> Res<String> {
        let _g = self.fund.lock().await;
        let sil = env("KASPAVEIL_REG_SIL");
        let sh = reg.file.shards[shard as usize].clone();
        let ctor = reg.ctor(shard);
        let req = json!({"ctor": ctor, "state": sh.state.json(), "entry": entry, "args": args});
        let (cur_code, sigscript) = tokio::task::spawn_blocking({
            let sil = sil.clone();
            move || helper_json(&sil, &req)
        })
        .await
        .map_err(|e| e.to_string())?;
        let sigscript = sigscript.unwrap();
        let req2 = json!({"ctor": reg.ctor(shard), "state": next.json(), "entry": null});
        let (next_code, _) = tokio::task::spawn_blocking(move || helper_json(&sil, &req2)).await.map_err(|e| e.to_string())?;
        let cur_spk = pay_to_script_hash_script(&cur_code);
        let next_spk = pay_to_script_hash_script(&next_code);
        let cov = Hash::from_bytes(b32(&sh.cov));
        // The shard's live UTXO, from the node: proves our copy of the state is the chain's.
        let (sop, sentry): (TransactionOutpoint, UtxoEntry) = if simulate {
            (TransactionOutpoint::new(TransactionId::from_bytes(b32(&sh.txid)), sh.index), UtxoEntry::new(sh.value, cur_spk.clone(), lock.saturating_sub(1_000), false, Some(cov)))
        } else {
            let live = utxos(&self.client, &p2sh_address(&cur_spk)).await?;
            let su = live.iter().find(|u| u.outpoint.transaction_id.to_string() == sh.txid && u.outpoint.index == sh.index).ok_or("shard UTXO not found: state out of sync with the chain")?;
            (su.outpoint.into(), su.utxo_entry.clone().into())
        };
        let kp = key("fund");
        let (fop, fentry) = self.fund_utxo(2 * KAS).await?;
        let entries = vec![sentry.clone(), fentry.clone()];
        let feerate = self.feerate().await;
        let build = |fee: u64, b0: u16| {
            let ins = vec![
                TransactionInput::new_with_compute_budget(sop, sigscript.clone(), 0, b0),
                TransactionInput::new_with_compute_budget(fop, vec![], 0, 10),
            ];
            let outs = vec![
                TransactionOutput { value: sh.value, script_public_key: next_spk.clone(), covenant: Some(CovenantBinding::new(0, cov)) },
                TransactionOutput::new(fentry.amount - fee, pay_to_address_script(&p2pk_address(&kp))),
            ];
            Transaction::new(TX_VERSION_TOCCATA, ins, outs, lock, SUBNETWORK_ID_NATIVE, 0, vec![])
        };
        let units = dry_run(&build(KAS, 2000), &entries, Some(0))?;
        let b0 = budget(units[0]);
        let fee = fee_for(&build(0, b0), &entries, feerate, true);
        let mut tx = build(fee, b0);
        set_storage_mass(&tx, &entries);
        sign_p2pk_input(&mut tx, &entries, 1, &kp);
        tx.finalize();
        dry_run(&tx, &entries, None)?;
        if simulate {
            let s = &mut reg.file.shards[shard as usize];
            s.txid = tx.id().to_string();
            s.index = 0;
            s.state = next;
            reg.trees[shard as usize] = tree;
            return Ok(format!("{entry}: passes the script engine ({} script units, fee {fee})", units[0]));
        }
        let id = submit(&self.client, &tx).await?;
        eprintln!("registry {entry} shard {shard}: {id} fee {fee} ({} script units, budget {b0})", units[0]);
        if !wait_accepted(&self.client, id, &p2sh_address(&next_spk), 60).await {
            return Err(format!("registry transaction {id} not accepted within 60 s"));
        }
        let s = &mut reg.file.shards[shard as usize];
        s.txid = id.to_string();
        s.index = 0;
        s.state = next;
        reg.trees[shard as usize] = tree;
        reg.save();
        Ok(id.to_string())
    }

    async fn register(&self, name: &str, owner: [u8; 32], kind: &str, n: u8, months: u64) -> Res<Value> {
        let mut g = self.registry.lock().await;
        let reg = g.as_mut().ok_or("registry not deployed")?;
        let key = name_key(name);
        let shard = key >> 52;
        let lock = now_daa(&self.client).await? - 10;
        let (label, expiry) = match kind {
            "default" => ("reg-default", 0),
            "prepaid" => ("reg-prepaid", lock + months * MONTH_DAA),
            _ => return Err("kind".into()),
        };
        if kind == "default" && default_name(&owner, n) != name {
            return Err("not this owner's default name".into());
        }
        if kind == "prepaid" && !(1..=12).contains(&months) {
            return Err("months 1-12".into());
        }
        if !valid_name(name) {
            return Err("invalid name".into());
        }
        let (low_args, tree) = reg.trees[shard as usize].insert(key, owner, expiry, name)?;
        let mut msg = [reg.domain(label, shard), name.as_bytes().to_vec(), owner.to_vec()].concat();
        if kind == "prepaid" {
            msg.extend(months.to_le_bytes());
            msg.extend(lock.to_le_bytes());
        }
        let sig = schnorr(&key_registrar(), blake(&msg));
        let mut args = vec![ab(name.as_bytes()), ab(&owner)];
        if kind == "default" {
            args.extend([ai(n as u64), ab(&sig)]);
        } else {
            args.extend([ai(months), ai(lock), ab(&sig)]);
        }
        args.extend(low_args);
        let mut next = reg.file.shards[shard as usize].state.clone();
        next.root = hx(&tree.root());
        next.size += 1;
        if kind == "prepaid" {
            next.prepaid_regs += 1;
            next.prepaid_months += months;
        }
        let entry = if kind == "default" { "registerDefault" } else { "registerPrepaid" };
        let txid = self.registry_spend(reg, shard, entry, args, next, lock, tree, false).await?;
        Ok(json!({"name": name, "shard": shard, "txid": txid, "expiry": expiry}))
    }

    async fn renew_prepaid(&self, name: &str, months: u64) -> Res<Value> {
        let mut g = self.registry.lock().await;
        let reg = g.as_mut().ok_or("registry not deployed")?;
        let lock = now_daa(&self.client).await? - 10;
        self.renew_inner(reg, name, months, lock, false).await
    }

    async fn renew_inner(&self, reg: &mut Registry, name: &str, months: u64, lock: u64, simulate: bool) -> Res<Value> {
        let key = name_key(name);
        let shard = key >> 52;
        let t = &reg.trees[shard as usize];
        let idx = t.find(key).ok_or("no such name")?;
        let l = t.leaves[idx].clone();
        if l.expiry <= 1 || l.owner == hx(&[0; 32]) {
            return Err("not a Plus name".into());
        }
        let msg = [reg.domain("renew-prepaid", shard), l.key.to_le_bytes().to_vec(), l.expiry.to_le_bytes().to_vec(), months.to_le_bytes().to_vec()].concat();
        let sig = schnorr(&key_registrar(), blake(&msg));
        let mut tree = t.clone();
        tree.leaves[idx].expiry = l.expiry + months * MONTH_DAA;
        tree.update(idx as u64);
        let args = vec![
            ai(l.key), ai(l.next_key), ai(l.next_idx), ab(&b32(&l.owner)), ai(l.expiry), ai(l.nonce), ai(idx as u64), aarr(&t.path(idx as u64)), ai(months), ab(&sig),
        ];
        let mut next = reg.file.shards[shard as usize].state.clone();
        next.root = hx(&tree.root());
        next.prepaid_months += months;
        let txid = self.registry_spend(reg, shard, "renewPrepaid", args, next, lock, tree, simulate).await?;
        Ok(json!({"name": name, "txid": txid, "expiry": l.expiry + months * MONTH_DAA}))
    }

    // ---- lapsed names (Kaspaguy 2026-10-14: first come, right after grace, at the monthly price) ----
    fn leaf_args(t: &Tree, idx: usize) -> Vec<Value> {
        let l = &t.leaves[idx];
        vec![ai(l.key), ai(l.next_key), ai(l.next_idx), ab(&b32(&l.owner)), ai(l.expiry), ai(l.nonce), ai(idx as u64), aarr(&t.path(idx as u64))]
    }

    // Anyone may reclaim a Plus name once expiry + 30-day grace has passed; the doorman does it at grace end.
    async fn reclaim_inner(&self, reg: &mut Registry, name: &str, lock: u64, simulate: bool) -> Res<String> {
        let key = name_key(name);
        let shard = key >> 52;
        let t = &reg.trees[shard as usize];
        let idx = t.find(key).ok_or("no such name")?;
        let l = t.leaves[idx].clone();
        if l.owner == hx(&[0; 32]) || l.expiry <= 1 {
            return Err("not an owned Plus name".into());
        }
        if lock < l.expiry + GRACE_DAA {
            return Err("still within its subscription or grace period".into());
        }
        let args = Daemon::leaf_args(t, idx);
        let mut tree = t.clone();
        tree.leaves[idx].owner = hx(&[0; 32]);
        tree.leaves[idx].expiry = l.expiry + GRACE_DAA;
        tree.leaves[idx].nonce = l.nonce + 1;
        tree.update(idx as u64);
        let mut next = reg.file.shards[shard as usize].state.clone();
        next.root = hx(&tree.root());
        self.registry_spend(reg, shard, "reclaim", args, next, lock, tree, simulate).await
    }

    // A lapsed (held) or released name goes to the first claimant who paid: held names through the auction key at the
    // reserve (one month, then renewals for the rest), released names like a new registration.
    async fn claim_inner(&self, reg: &mut Registry, name: &str, owner: [u8; 32], months: u64, lock: u64, simulate: bool) -> Res<Vec<String>> {
        if !(1..=12).contains(&months) {
            return Err("months 1-12".into());
        }
        let key = name_key(name);
        let shard = key >> 52;
        let mut steps = vec![];
        let idx = reg.trees[shard as usize].find(key).ok_or("not registered: register it as a new name")?;
        let l = reg.trees[shard as usize].leaves[idx].clone();
        if l.owner != hx(&[0; 32]) && l.expiry > 1 {
            steps.push(self.reclaim_inner(reg, name, lock, simulate).await?);
        }
        let t = &reg.trees[shard as usize];
        let l = t.leaves[idx].clone();
        if l.owner != hx(&[0; 32]) {
            return Err("free names never lapse".into());
        }
        let mut next = reg.file.shards[shard as usize].state.clone();
        let mut tree = t.clone();
        if l.expiry > 1 {
            let msg = [reg.domain("auction-prepaid", shard), l.key.to_le_bytes().to_vec(), owner.to_vec(), lock.to_le_bytes().to_vec(), l.nonce.to_le_bytes().to_vec()].concat();
            let sig = schnorr(&key_auction(), blake(&msg));
            let mut args = Daemon::leaf_args(t, idx);
            args.extend([ab(&owner), ai(lock), ab(&sig)]);
            tree.leaves[idx].owner = hx(&owner);
            tree.leaves[idx].expiry = lock + MONTH_DAA;
            tree.leaves[idx].nonce = l.nonce + 1;
            tree.leaves[idx].name = Some(name.into());
            tree.update(idx as u64);
            next.root = hx(&tree.root());
            next.prepaid_months += 1;
            steps.push(self.registry_spend(reg, shard, "settleAuctionPrepaid", args, next, lock, tree, simulate).await?);
            if months > 1 {
                steps.push(self.renew_inner(reg, name, months - 1, lock, simulate).await?["txid"].as_str().unwrap_or("").to_string());
            }
        } else {
            let msg = [reg.domain("claim-prepaid", shard), name.as_bytes().to_vec(), owner.to_vec(), months.to_le_bytes().to_vec(), lock.to_le_bytes().to_vec(), l.nonce.to_le_bytes().to_vec()].concat();
            let sig = schnorr(&key_registrar(), blake(&msg));
            let mut args = vec![ab(name.as_bytes()), ab(&owner), ai(months), ai(lock), ab(&sig)];
            args.extend(Daemon::leaf_args(t, idx));
            tree.leaves[idx].owner = hx(&owner);
            tree.leaves[idx].expiry = lock + months * MONTH_DAA;
            tree.leaves[idx].nonce = l.nonce + 1;
            tree.leaves[idx].name = Some(name.into());
            tree.update(idx as u64);
            next.root = hx(&tree.root());
            next.prepaid_regs += 1;
            next.prepaid_months += months;
            steps.push(self.registry_spend(reg, shard, "claimReleasedPrepaid", args, next, lock, tree, simulate).await?);
        }
        Ok(steps)
    }

    async fn claim(&self, name: &str, owner: [u8; 32], months: u64) -> Res<Value> {
        let mut g = self.registry.lock().await;
        let reg = g.as_mut().ok_or("registry not deployed")?;
        let lock = now_daa(&self.client).await? - 10;
        let steps = self.claim_inner(reg, name, owner, months, lock, false).await?;
        Ok(json!({"name": name, "txids": steps}))
    }

    // Test only: a full lapse-and-claim on a scratch copy of the registry, `days_after_expiry` days past the name's expiry,
    // checked by the real script engine and never submitted.
    async fn simulate_lapse(&self, name: &str, owner: [u8; 32], months: u64, days_after_expiry: u64) -> Res<Value> {
        let g = self.registry.lock().await;
        let live = g.as_ref().ok_or("registry not deployed")?;
        let mut reg = Registry { file: live.file.clone(), trees: live.trees.clone() };
        drop(g);
        let key = name_key(name);
        let t = &reg.trees[(key >> 52) as usize];
        let l = t.leaves[t.find(key).ok_or("no such name")?].clone();
        let lock = l.expiry + days_after_expiry * 864_000;
        let steps = self.claim_inner(&mut reg, name, owner, months, lock, true).await?;
        Ok(json!({"name": name, "atDaa": lock, "steps": steps}))
    }

    // Doorman job (spec §8.5): reclaim every Plus name whose grace has ended, so the cut-off is exact and the name is free
    // for the next claimant.
    async fn reclaim_due(&self) {
        let mut g = self.registry.lock().await;
        let Some(reg) = g.as_mut() else { return };
        let Ok(now) = now_daa(&self.client).await else { return };
        let due: Vec<String> = reg.trees.iter().flat_map(|t| t.leaves.iter()).filter(|l| l.owner != hx(&[0; 32]) && l.expiry > 1 && now - 10 >= l.expiry + GRACE_DAA).filter_map(|l| l.name.clone()).collect();
        for name in due {
            match self.reclaim_inner(reg, &name, now - 10, false).await {
                Ok(id) => eprintln!("reclaimed lapsed @{name}: {id}"),
                Err(e) => eprintln!("reclaim @{name}: {e}"),
            }
        }
    }

    // ---- payments (SC-0018): one payment-covenant address per order; settling splits 75% reservoir / 25% Kaspaguy ----
    fn pay_code(&self, id: &str, pot_cov: Hash) -> Res<(Vec<u8>, ResKind, u64)> {
        let rec: Value = serde_json::from_str(&std::fs::read_to_string(deposit_path(id)?).map_err(|_| "no such deposit")?).unwrap();
        let kind = ResKind::parse(rec["reservoir"].as_str().unwrap_or("")).ok_or("bad deposit record")?;
        let min = rec["min"].as_u64().unwrap_or(0);
        let dev = spk_bytes(&pay_to_address_script(&p2pk_address(&key("dev"))));
        let ctor = json!([ab(&blake(id.as_bytes())), ab(&dev), ab(&spk_bytes(&res_spk(pot_cov, kind))), ai(min)]);
        let (code, _) = helper_json(&env("KASPAVEIL_PAY_SIL"), &json!({"ctor": ctor, "state": null, "entry": null}));
        Ok((code, kind, min))
    }
    async fn pot_cov(&self) -> Res<Hash> {
        Ok(self.treasury.as_ref().ok_or("pot not deployed")?.cov)
    }
    async fn deposit_new(&self, kind: ResKind, min: u64) -> Res<Value> {
        std::fs::create_dir_all(data("deposits")).unwrap();
        let id = hx(&rand::random::<[u8; 16]>());
        std::fs::write(deposit_path(&id)?, json!({"reservoir": format!("{kind:?}").to_lowercase(), "min": min}).to_string()).unwrap();
        let (code, _, _) = self.pay_code(&id, self.pot_cov().await?)?;
        // The code's hash, so check-contracts can tell if a new payment.sil would move this order's address.
        std::fs::write(deposit_path(&id)?, json!({"reservoir": format!("{kind:?}").to_lowercase(), "min": min, "code": hx(&blake(&code))}).to_string()).unwrap();
        Ok(json!({"id": id, "address": p2sh_address(&pay_to_script_hash_script(&code)).to_string(), "min": min}))
    }
    async fn deposit_received(&self, id: &str) -> Res<Value> {
        let (code, _, min) = self.pay_code(id, self.pot_cov().await?)?;
        let addr = p2sh_address(&pay_to_script_hash_script(&code));
        let us = utxos(&self.client, &addr).await?;
        let now = now_daa(&self.client).await?;
        let coins: Vec<Value> = us.iter().map(|u| json!({"id": format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index), "sompi": u.utxo_entry.amount, "late": now.saturating_sub(u.utxo_entry.block_daa_score) >= PAY_LATE_DAA})).collect();
        Ok(json!({"address": addr.to_string(), "received": us.iter().map(|u| u.utxo_entry.amount).sum::<u64>(), "min": min, "coins": coins}))
    }
    // Settles an order's payment covenant (keyless), 75% to the reservoir and the rest less the fee to Kaspaguy:
    // with settle() when its payments (at most 8) reach the order amount; otherwise, with settleLate(), only the
    // payments at least PAY_LATE_DAA old (each input then carries that relative lock time).
    async fn deposit_forward(&self, id: &str) -> Res<Value> {
        let pot_cov = self.pot_cov().await?;
        let (code, kind, min) = self.pay_code(id, pot_cov)?;
        let spk = pay_to_script_hash_script(&code);
        let mut us = utxos(&self.client, &p2sh_address(&spk)).await?;
        us.truncate(8);
        let full: u64 = us.iter().map(|u| u.utxo_entry.amount).sum();
        let late = full < min;
        if late {
            let now = now_daa(&self.client).await?;
            us.retain(|u| now.saturating_sub(u.utxo_entry.block_daa_score) >= PAY_LATE_DAA);
        }
        let total: u64 = us.iter().map(|u| u.utxo_entry.amount).sum();
        if total == 0 {
            return Err(format!("received {full} of {min} sompi; nothing 3 days old to settle on its own yet"));
        }
        let (entry, sequence) = if late { ("settleLate", PAY_LATE_DAA) } else { ("settle", 0) };
        let entries: Vec<UtxoEntry> = us.iter().map(|u| u.utxo_entry.clone().into()).collect();
        let req = json!({"ctor": json!([ab(&blake(id.as_bytes())), ab(&spk_bytes(&pay_to_address_script(&p2pk_address(&key("dev"))))), ab(&spk_bytes(&res_spk(pot_cov, kind))), ai(min)]), "state": null, "entry": entry, "args": []});
        let sig = helper_json(&env("KASPAVEIL_PAY_SIL"), &req).1.unwrap();
        let res = total * 75 / 100;
        let rspk = res_spk(pot_cov, kind);
        let dev = pay_to_address_script(&p2pk_address(&key("dev")));
        let build = |fee: u64, b: u16| {
            let ins = us.iter().map(|u| TransactionInput::new_with_compute_budget(u.outpoint.into(), sig.clone(), sequence, b)).collect();
            Transaction::new(TX_VERSION_TOCCATA, ins, vec![TransactionOutput::new(res, rspk.clone()), TransactionOutput::new(total - res - fee, dev.clone())], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
        };
        let units = dry_run(&build(PAY_MAX_FEE, 200), &entries, None)?;
        let b = budget(*units.iter().max().unwrap());
        let fee = fee_for(&build(0, b), &entries, self.feerate().await, true).min(PAY_MAX_FEE);
        let mut tx = build(fee, b);
        set_storage_mass(&tx, &entries);
        tx.finalize();
        dry_run(&tx, &entries, None)?;
        let txid = submit(&self.client, &tx).await?;
        if !wait_accepted(&self.client, txid, &p2sh_address(&rspk), 60).await {
            return Err(format!("settlement {txid} not accepted within 60 s"));
        }
        Ok(json!({"txid": txid.to_string(), "received": total, "reservoir": res, "dev": total - res - fee, "fee": fee, "late": late}))
    }
}

fn key_registrar() -> secp256k1::Keypair {
    key("registrar")
}
fn key_auction() -> secp256k1::Keypair {
    key("auction")
}
fn deposit_path(id: &str) -> Res<String> {
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad deposit id".into());
    }
    Ok(data(&format!("deposits/{id}.json")))
}

// A relay-paid message on top of `pot`. Returns the transaction and the pot after it.
// `cap`: the most this message may pay (what is left of the hour's allowance, at most 1 KAS).
fn build_message(pot: &Pot, relay: &secp256k1::Keypair, payload: &[u8], lock: u64, feerate: f64, cap: u64) -> Res<(Transaction, Pot)> {
    let cur = lock / INTERVAL_DAA;
    let entries = vec![pot.entry()];
    let build = |fee: u64, b: u16| -> (Transaction, Pot) {
        let next = pot.rolled(cur, fee);
        let out = next.output(pot.value - fee);
        let mut tx = Transaction::new(TX_VERSION_TOCCATA, vec![TransactionInput::new_with_compute_budget(pot.outpoint, vec![], 0, b)], vec![out], lock, SubnetworkId::from_bytes(LANE), 0, payload.to_vec());
        let reused = SigHashReusedValuesUnsync::new();
        let hash = calc_schnorr_signature_hash(&PopulatedTransaction::new(&tx, entries.clone()), 0, SIG_HASH_ALL, &reused);
        let mut sig = schnorr(relay, hash.as_bytes());
        sig.push(SIG_HASH_ALL.to_u8());
        tx.inputs[0].signature_script = helper(&[pot.helper_args("pot-step"), vec![hx(&sig)]].concat());
        tx.finalize();
        (tx, Pot { value: pot.value - fee, ..next })
    };
    if pot.value < 1_000_000 {
        return Err("pot lane empty".into());
    }
    if payload.is_empty() || !payload.len().is_multiple_of(MSG_LEN) || payload.len() > BATCH * MSG_LEN {
        return Err("payload must be 1 to 5 messages of 1,536 bytes".into());
    }
    let probe = 1_000_000.min(cap.max(1));
    let units = dry_run(&build(probe, 200).0, &entries, None).map(|u| budget(u[0])).unwrap_or(30);
    let fee = fee_for(&build(probe, units).0, &entries, feerate, false);
    if fee > cap {
        return Err("the treasury's allowance for this hour is used up; messages resume within the hour".into());
    }
    let (tx, mut next) = build(fee, units);
    set_storage_mass(&tx, &entries);
    dry_run(&tx, &entries, None)?;
    next.outpoint = TransactionOutpoint::new(tx.id(), 0);
    Ok((tx, next))
}

// ---------- HTTP (127.0.0.1 only) ----------

type HttpRes = Result<Json<Value>, (StatusCode, String)>;
fn bad(e: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e)
}

#[derive(Deserialize)]
struct RelayReq {
    payload: String,
}
async fn h_relay(State(app): State<App>, Json(r): Json<RelayReq>) -> HttpRes {
    let p = unhex(&r.payload);
    app.relay_send(p).await.map(|(id, i)| Json(json!({"txid": id, "index": i}))).map_err(bad)
}

#[derive(Deserialize)]
struct RegReq {
    name: String,
    owner: String,
    #[serde(default)]
    n: u8,
    #[serde(default)]
    months: u64,
}
async fn h_reg_default(State(app): State<App>, Json(r): Json<RegReq>) -> HttpRes {
    app.register(&r.name, b32(&r.owner), "default", r.n, 0).await.map(Json).map_err(bad)
}
async fn h_reg_prepaid(State(app): State<App>, Json(r): Json<RegReq>) -> HttpRes {
    app.register(&r.name, b32(&r.owner), "prepaid", 0, r.months).await.map(Json).map_err(bad)
}
async fn h_renew(State(app): State<App>, Json(r): Json<RegReq>) -> HttpRes {
    app.renew_prepaid(&r.name, r.months).await.map(Json).map_err(bad)
}

fn leaf_json(t: &Tree, i: usize, shard: u64) -> Value {
    let l = &t.leaves[i];
    json!({"shard": shard, "idx": i, "key": l.key.to_string(), "nextKey": l.next_key.to_string(), "nextIdx": l.next_idx, "owner": l.owner,
           "expiry": l.expiry, "nonce": l.nonce, "name": l.name, "path": t.path(i as u64).iter().map(|p| hx(p)).collect::<Vec<_>>()})
}
async fn h_meta(State(app): State<App>) -> HttpRes {
    let g = app.registry.lock().await;
    let reg = g.as_ref().ok_or(bad("registry not deployed".into()))?;
    Ok(Json(json!({
        "registryId": reg.file.registry_id, "dev": reg.file.dev, "rootKey": reg.file.root_key,
        "shards": reg.file.shards.iter().map(|s| json!({"id": s.id, "cov": s.cov, "txid": s.txid, "state": s.state})).collect::<Vec<_>>()
    })))
}
// Registry bucket (spec §6.3): every entry whose name hashes to this first byte, with its Merkle path.
async fn h_bucket(State(app): State<App>, Path(b): Path<u8>) -> HttpRes {
    let g = app.registry.lock().await;
    let reg = g.as_ref().ok_or(bad("registry not deployed".into()))?;
    let mut out = vec![];
    for (s, t) in reg.trees.iter().enumerate() {
        for (i, l) in t.leaves.iter().enumerate() {
            if l.key != 0 && (l.key & 0xff) as u8 == b {
                out.push(leaf_json(t, i, s as u64));
            }
        }
    }
    Ok(Json(json!({"bucket": b, "roots": reg.trees.iter().map(|t| hx(&t.root())).collect::<Vec<_>>(), "entries": out})))
}
async fn h_name(State(app): State<App>, Path(name): Path<String>) -> HttpRes {
    let g = app.registry.lock().await;
    let reg = g.as_ref().ok_or(bad("registry not deployed".into()))?;
    let k = name_key(&name);
    let s = k >> 52;
    let t = &reg.trees[s as usize];
    Ok(Json(match t.find(k) {
        Some(i) => json!({"taken": true, "entry": leaf_json(t, i, s)}),
        None => json!({"taken": false}),
    }))
}
async fn h_owner_names(State(app): State<App>, Path(owner): Path<String>) -> HttpRes {
    let g = app.registry.lock().await;
    let reg = g.as_ref().ok_or(bad("registry not deployed".into()))?;
    let mut out = vec![];
    for (s, t) in reg.trees.iter().enumerate() {
        for (i, l) in t.leaves.iter().enumerate() {
            if l.owner == owner && l.key != 0 {
                out.push(leaf_json(t, i, s as u64));
            }
        }
    }
    Ok(Json(json!({"entries": out})))
}

#[derive(Deserialize)]
struct DepReq {
    reservoir: String,
    min: u64,
}
async fn h_deposit_new(State(app): State<App>, Json(r): Json<DepReq>) -> HttpRes {
    let kind = ResKind::parse(&r.reservoir).ok_or(bad("reservoir".into()))?;
    if kind == ResKind::Topup && r.min < 20 * KAS {
        return Err(bad("top-ups are at least 20 KAS".into()));
    }
    app.deposit_new(kind, r.min).await.map(Json).map_err(bad)
}
async fn h_deposit_get(State(app): State<App>, Path(id): Path<String>) -> HttpRes {
    app.deposit_received(&id).await.map(Json).map_err(bad)
}
async fn h_deposit_forward(State(app): State<App>, Path(id): Path<String>) -> HttpRes {
    app.deposit_forward(&id).await.map(Json).map_err(bad)
}
async fn h_claim(State(app): State<App>, Json(r): Json<RegReq>) -> HttpRes {
    app.claim(&r.name, b32(&r.owner), r.months).await.map(Json).map_err(bad)
}
#[derive(Deserialize)]
struct SimReq {
    name: String,
    owner: String,
    months: u64,
    days: u64,
}
async fn h_simulate_lapse(State(app): State<App>, Json(r): Json<SimReq>) -> HttpRes {
    app.simulate_lapse(&r.name, b32(&r.owner), r.months, r.days).await.map(Json).map_err(bad)
}
#[derive(Deserialize)]
struct FaucetReq {
    address: String,
    sompi: u64,
}
async fn h_faucet(State(app): State<App>, Json(r): Json<FaucetReq>) -> HttpRes {
    let a = Address::try_from(r.address.as_str()).map_err(|e| bad(e.to_string()))?;
    if r.sompi > 1_000 * KAS {
        return Err(bad("faucet limit 1,000 tKAS".into()));
    }
    app.pay(a, r.sompi).await.map(|id| Json(json!({"txid": id}))).map_err(bad)
}

async fn h_status(State(app): State<App>) -> HttpRes {
    let now = now_daa(&app.client).await.map_err(bad)?;
    let cur = now / INTERVAL_DAA;
    let mut out = json!({"daa": now, "feerate": app.feerate().await});
    let fund = utxos(&app.client, &p2pk_address(&key("fund"))).await.map_err(bad)?;
    out["fund"] = json!({"address": p2pk_address(&key("fund")).to_string(), "sompi": fund.iter().map(|u| u.utxo_entry.amount).sum::<u64>()});
    if let Some(t) = app.treasury.as_ref() {
        let mut res = json!({});
        for (n, k) in [("month", ResKind::Month), ("long", ResKind::Long), ("topup", ResKind::Topup)] {
            let a = p2sh_address(&res_spk(t.cov, k));
            let us = utxos(&app.client, &a).await.map_err(bad)?;
            res[n] = json!({"address": a.to_string(), "sompi": us.iter().map(|u| u.utxo_entry.amount).sum::<u64>(), "utxos": us.len()});
        }
        let (mut value, mut allowance, mut left, mut pending, mut busy) = (0u64, 0u64, 0u64, 0usize, 0usize);
        for l in &t.lanes {
            match l.try_lock() {
                Ok(g) => {
                    value += g.pot.value;
                    allowance += g.pot.allowance(g.pot.smma_at(cur));
                    left += g.pot.left(cur);
                    pending += g.pending.len();
                }
                Err(_) => busy += 1,
            }
        }
        out["pot"] = json!({"cov": t.cov.to_string(), "lanes": t.lanes.len(), "busyLanes": busy, "value": value, "allowance": allowance, "leftThisHour": left,
            "pending": pending, "messagesSinceStart": t.sent.load(std::sync::atomic::Ordering::Relaxed), "feesSinceStart": t.fees.load(std::sync::atomic::Ordering::Relaxed)});
        out["reservoirs"] = res;
    }
    if let Some(reg) = app.registry.lock().await.as_ref() {
        out["registry"] = json!({"names": reg.trees.iter().map(|t| t.leaves.len() - 1).sum::<usize>(), "price": reg.file.shards[0].state.price});
    }
    Ok(Json(out))
}

async fn serve() {
    let client = connect().await;
    let treasury = load_treasury().map(Arc::new);
    let (btx, mut brx) = tokio::sync::mpsc::channel::<Job>(20_000);
    let app = Arc::new(Daemon {
        client, treasury: treasury.clone(), batch: treasury.as_ref().map(|_| btx), registry: Mutex::new(Registry::load()), fund: Mutex::new(()),
        feerate: StdMutex::new((100.0, Instant::now() - Duration::from_secs(60))),
    });
    // The mix (PROTOCOL_SPEC §1): each message waits a random MIX_MS, then leaves in one transaction on a free lane with
    // up to BATCH-1 others picked at random from those waiting, in random order, so neither on-chain order nor timing
    // mirrors the order and times in which messages were submitted.
    let bd = app.clone();
    tokio::spawn(async move {
        use rand::Rng;
        let mut pool: Vec<(tokio::time::Instant, Job)> = vec![];
        loop {
            let due = pool.iter().map(|p| p.0).min();
            tokio::select! {
                j = brx.recv() => match j {
                    Some(j) => pool.push((tokio::time::Instant::now() + Duration::from_millis(rand::thread_rng().gen_range(MIX_MS)), j)),
                    None => break,
                },
                _ = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)), if due.is_some() => {
                    let batch = mix_take(&mut pool, &mut rand::thread_rng());
                    let d = bd.clone();
                    tokio::spawn(async move { d.send_batch(batch).await });
                }
            }
        }
    });
    let cg = app.clone();
    tokio::spawn(async move {
        loop {
            match cg.consolidate().await {
                Ok(n) if n > 0 => eprintln!("consolidated {n} fund UTXOs"),
                Err(e) => eprintln!("consolidate: {e}"),
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    let rg = app.clone();
    tokio::spawn(async move {
        loop {
            rg.reclaim_due().await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    if let Some(t) = treasury.clone() {
        let bg = app.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                for l in &t.lanes {
                    if let Ok(mut g) = l.try_lock() {
                        bg.confirm(&mut g).await;
                    }
                }
            }
        });
    }
    let router = Router::new()
        .route("/relay", post(h_relay))
        .route("/registry/default", post(h_reg_default))
        .route("/registry/prepaid", post(h_reg_prepaid))
        .route("/registry/renew", post(h_renew))
        .route("/registry/claim", post(h_claim))
        .route("/registry/simulate-lapse", post(h_simulate_lapse))
        .route("/registry/meta", get(h_meta))
        .route("/registry/bucket/:b", get(h_bucket))
        .route("/registry/name/:name", get(h_name))
        .route("/registry/owner/:owner", get(h_owner_names))
        .route("/deposit", post(h_deposit_new))
        .route("/deposit/:id", get(h_deposit_get))
        .route("/deposit/:id/forward", post(h_deposit_forward))
        .route("/status", get(h_status));
    // Testnet only: pays from the fund wallet to any address. Never set KASPAVEIL_FAUCET on mainnet.
    let router = if std::env::var("KASPAVEIL_FAUCET").as_deref() == Ok("1") { router.route("/faucet", post(h_faucet)) } else { router };
    let router = router.with_state(app);
    let listen = std::env::var("KASPAVEIL_LISTEN").unwrap_or("127.0.0.1:5512".into());
    let l = tokio::net::TcpListener::bind(&listen).await.expect("bind");
    eprintln!("kaspaveil-chaind listening on {listen}");
    axum::serve(l, router).await.unwrap();
}

// ---------- deployment commands ----------

// Pre-deploy gate: the contract sources named in the environment (KASPAVEIL_*_SIL) must compile to the addresses the
// live state is at. A changed source moves every address derived from it (registry shards, pot lanes, reservoirs,
// open payment addresses), and chaind would then look for its coins where there are none. Exits non-zero on a mismatch.
async fn check_contracts() -> bool {
    let client = connect().await;
    let mut ok = true;
    let mut report = |good: bool, what: String| {
        println!("{} {what}", if good { "ok  " } else { "FAIL" });
        ok &= good;
    };
    let live = |us: &[RpcUtxosByAddressesEntry], op: &TransactionOutpoint| us.iter().any(|u| TransactionOutpoint::from(u.outpoint) == *op);
    if let Some(reg) = Registry::load() {
        for sh in &reg.file.shards {
            let (code, _) = helper_json(&env("KASPAVEIL_REG_SIL"), &json!({"ctor": reg.ctor(sh.id), "state": sh.state.json(), "entry": null}));
            let addr = p2sh_address(&pay_to_script_hash_script(&code));
            let op = TransactionOutpoint::new(TransactionId::from_bytes(b32(&sh.txid)), sh.index);
            let us = utxos(&client, &addr).await.unwrap_or_default();
            report(live(&us, &op), format!("registry shard {:2}: its live coin is at the address this source gives", sh.id));
        }
    } else {
        println!("skip registry (not deployed)");
    }
    if let Some(t) = load_treasury() {
        let mut lanes_ok = 0;
        for l in &t.lanes {
            let lane = l.lock().await;
            let mut found = false;
            for p in std::iter::once(&lane.confirmed).chain(lane.pending.iter().map(|x| &x.1)) {
                if live(&utxos(&client, &p.address()).await.unwrap_or_default(), &p.outpoint) {
                    found = true;
                    break;
                }
            }
            lanes_ok += found as usize;
        }
        report(lanes_ok == t.lanes.len(), format!("treasury pot: {lanes_ok}/{} lanes' live coins are at the addresses this source gives", t.lanes.len()));
        if let Some(reg) = Registry::load() {
            report(
                reg.file.res_month_spk == hx(&spk_bytes(&res_spk(t.cov, ResKind::Month))) && reg.file.res_long_spk == hx(&spk_bytes(&res_spk(t.cov, ResKind::Long))),
                "reservoirs: this source gives the scripts the registry pays to".into(),
            );
        }
        let recent = std::time::SystemTime::now() - Duration::from_secs(32 * 86_400);
        let (mut same, mut moved, mut unknown) = (0, 0, 0);
        for e in std::fs::read_dir(data("deposits")).into_iter().flatten().flatten() {
            if e.metadata().and_then(|m| m.modified()).map(|m| m < recent).unwrap_or(true) {
                continue;
            }
            let id = e.file_name().to_string_lossy().trim_end_matches(".json").to_string();
            let rec: Value = serde_json::from_str(&std::fs::read_to_string(e.path()).unwrap_or_default()).unwrap_or_default();
            let Some(was) = rec["code"].as_str() else {
                unknown += 1;
                continue;
            };
            let d = Daemon { client: rpc_client(), treasury: None, batch: None, registry: Mutex::new(None), fund: Mutex::new(()), feerate: StdMutex::new((100.0, Instant::now())) };
            match d.pay_code(&id, t.cov) {
                Ok((code, _, _)) if hx(&blake(&code)) == was => same += 1,
                _ => moved += 1,
            }
        }
        report(moved == 0, format!("payment addresses of the last 32 days: {same} unchanged, {moved} would move, {unknown} made before codes were recorded"));
    } else {
        println!("skip treasury (not deployed)");
    }
    ok
}

// The pot (SC-0019): `lanes` lane UTXOs created by one genesis transaction under one covenant ID, `kas` KAS in all, an
// hourly floor of `floor_kas` KAS for the whole pot (each lane gets floor_kas / lanes).
async fn deploy_pot(kas: u64, lanes: usize, floor_kas: u64) {
    assert!(!std::path::Path::new(&data("pot/lanes")).exists(), "a pot is deployed already (data/pot/lanes)");
    std::fs::create_dir_all(data("pot")).unwrap();
    let client = connect().await;
    let kp = key("fund");
    let addr = p2pk_address(&kp);
    let now = now_daa(&client).await.unwrap();
    let us = utxos(&client, &addr).await.unwrap();
    let best = us.iter().filter(|u| spendable(u, now)).max_by_key(|u| u.utxo_entry.amount).expect("no spendable funds in the fund wallet");
    let entry: UtxoEntry = best.utxo_entry.clone().into();
    let outpoint: TransactionOutpoint = best.outpoint.into();
    let per = kas * KAS / lanes as u64;
    let mut pot = Pot {
        cov: Hash::from_bytes([0; 32]), root: xonly(&key("root")), floor: floor_kas * KAS / lanes as u64, relay: xonly(&key("relay")), interval: now / INTERVAL_DAA,
        spent: 0, smma: 0, nonce: 0, outpoint, value: per,
    };
    let unbound: Vec<TransactionOutput> = (0..lanes).map(|_| TransactionOutput::new(per, pot.spk())).collect();
    pot.cov = covenant_id(outpoint, unbound.iter().enumerate().map(|(i, o)| (i as u32, o)).collect::<Vec<_>>().into_iter());
    let build = |fee: u64| {
        let mut outs: Vec<TransactionOutput> = (0..lanes).map(|_| pot.output(per)).collect();
        outs.push(TransactionOutput::new(entry.amount - per * lanes as u64 - fee, pay_to_address_script(&addr)));
        Transaction::new(TX_VERSION_TOCCATA, vec![TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 10)], outs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    };
    let fee = fee_for(&build(0), std::slice::from_ref(&entry), 200.0, true);
    let tx = build(fee);
    set_storage_mass(&tx, std::slice::from_ref(&entry));
    println!("genesis masses (compute, transient, storage): {:?}", masses(&tx, std::slice::from_ref(&entry)));
    let mut signed = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
    signed.finalize();
    let id = submit(&client, &signed).await.expect("submit");
    println!("pot genesis {id}: covenant ID {}, {lanes} lanes of {per} sompi, floor {} sompi per lane per hour", pot.cov, pot.floor);
    assert!(wait_accepted(&client, id, &pot.address(), 120).await, "not accepted");
    for i in 0..lanes {
        Pot { outpoint: TransactionOutpoint::new(id, i as u32), ..pot.clone() }.save(&Lane::state_path(i));
    }
    std::fs::write(data("pot/lanes"), format!("{} {lanes}", pot.cov)).unwrap();
    for k in [ResKind::Month, ResKind::Long, ResKind::Topup] {
        println!("reservoir {k:?}: {}", p2sh_address(&res_spk(pot.cov, k)));
    }
}

async fn fund_reservoir(kind: ResKind, kas: u64) {
    let cov = treasury_cov();
    let client = connect().await;
    let d = Daemon { client, treasury: None, batch: None, registry: Mutex::new(None), fund: Mutex::new(()), feerate: StdMutex::new((200.0, Instant::now())) };
    let id = d.pay(p2sh_address(&res_spk(cov, kind)), kas * KAS).await.expect("pay");
    println!("reservoir {kind:?} funded: {id}");
}

// 16 shards, one genesis transaction each (a single transaction with 16 small outputs exceeds the storage-mass limit).
// A split transaction makes 16 fund UTXOs (`reuse` names an earlier split); shard i is output 0 of the transaction
// spending split output i, with covenant ID = covenant_id(split outpoint i, [(0, shard output)]).
async fn deploy_registry(price_kas: u64, reuse: Option<String>) {
    assert!(!std::path::Path::new(&data("registry.json")).exists(), "registry.json exists already");
    let pot_cov = treasury_cov();
    let client = connect().await;
    let kp = key("fund");
    let addr = p2pk_address(&kp);
    let feerate = 200.0;
    let piece = SHARD_VALUE + KAS;
    let sid = match reuse {
        Some(t) => TransactionId::from_bytes(b32(&t)),
        None => {
            let now = now_daa(&client).await.unwrap();
            let us = utxos(&client, &addr).await.unwrap();
            let best = us.iter().filter(|u| spendable(u, now)).max_by_key(|u| u.utxo_entry.amount).expect("no funds");
            let entry: UtxoEntry = best.utxo_entry.clone().into();
            let build = |fee: u64| {
                let mut outs: Vec<_> = (0..SHARDS).map(|_| TransactionOutput::new(piece, pay_to_address_script(&addr))).collect();
                outs.push(TransactionOutput::new(entry.amount - piece * SHARDS as u64 - fee, pay_to_address_script(&addr)));
                Transaction::new(TX_VERSION_TOCCATA, vec![TransactionInput::new_with_compute_budget(best.outpoint.into(), vec![], 0, 10)], outs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
            };
            let fee = fee_for(&build(0), std::slice::from_ref(&entry), feerate, true);
            let tx = build(fee);
            set_storage_mass(&tx, std::slice::from_ref(&entry));
            let mut split = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
            split.finalize();
            let sid = submit(&client, &split).await.expect("split");
            println!("split {sid}");
            assert!(wait_accepted(&client, sid, &addr, 120).await);
            sid
        }
    };
    let registrar = xonly(&key("registrar"));
    let file = RegistryFile {
        registry_id: hx(&rand::random::<[u8; 32]>()),
        dev: hx(&xonly(&key("dev"))),
        root_key: hx(&xonly(&key("root"))),
        res_month_spk: hx(&spk_bytes(&res_spk(pot_cov, ResKind::Month))),
        res_long_spk: hx(&spk_bytes(&res_spk(pot_cov, ResKind::Long))),
        init_price: price_kas * KAS,
        shards: vec![],
    };
    let tree = Tree::new(vec![Leaf::sentinel()]);
    let state0 = ShardState {
        root: hx(&tree.root()), size: 1, registrar: hx(&registrar), price_key: hx(&xonly(&key("price"))), auction_key: hx(&xonly(&key("auction"))),
        price: price_kas * KAS, price_nonce: 0, key_nonce: 0, prepaid_regs: 0, prepaid_months: 0, transfers_open: 0,
    };
    let mut reg = Registry { trees: vec![tree.clone(); SHARDS], file };
    for i in 0..SHARDS {
        reg.file.shards.push(Shard { id: i as u64, cov: String::new(), txid: String::new(), index: 0, value: SHARD_VALUE, state: state0.clone(), leaves: vec![Leaf::sentinel()] });
    }
    for i in 0..SHARDS {
        let op = TransactionOutpoint::new(sid, i as u32);
        let entry = UtxoEntry::new(piece, pay_to_address_script(&addr), 0, false, None);
        let (code, _) = helper_json(&env("KASPAVEIL_REG_SIL"), &json!({"ctor": reg.ctor(i as u64), "state": state0.json(), "entry": null}));
        let spk = pay_to_script_hash_script(&code);
        let cov = covenant_id(op, [(0u32, &TransactionOutput::new(SHARD_VALUE, spk.clone()))].into_iter());
        let build = |fee: u64| {
            let outs = vec![
                TransactionOutput { value: SHARD_VALUE, script_public_key: spk.clone(), covenant: Some(CovenantBinding::new(0, cov)) },
                TransactionOutput::new(piece - SHARD_VALUE - fee, pay_to_address_script(&addr)),
            ];
            Transaction::new(TX_VERSION_TOCCATA, vec![TransactionInput::new_with_compute_budget(op, vec![], 0, 10)], outs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
        };
        let fee = fee_for(&build(0), std::slice::from_ref(&entry), feerate, true);
        let tx = build(fee);
        set_storage_mass(&tx, std::slice::from_ref(&entry));
        let mut g = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
        g.finalize();
        let gid = submit(&client, &g).await.unwrap_or_else(|e| panic!("genesis {i}: {e}"));
        assert!(wait_accepted(&client, gid, &p2sh_address(&spk), 120).await, "genesis {i} not accepted");
        println!("shard {i:2}: covenant ID {cov}, genesis {gid}, fee {fee}");
        reg.file.shards[i].cov = cov.to_string();
        reg.file.shards[i].txid = gid.to_string();
    }
    reg.save();
    println!("registry {} saved", reg.file.registry_id);
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("serve") => serve().await,
        Some("deploy-pot") => deploy_pot(a[2].parse().expect("KAS"), a.get(3).map(|x| x.parse().expect("lanes")).unwrap_or(32), a.get(4).map(|x| x.parse().expect("floor KAS/hour")).unwrap_or(200)).await,
        Some("deploy-registry") => deploy_registry(a[2].parse().expect("price KAS"), a.get(3).cloned()).await,
        Some("fund-reservoir") => fund_reservoir(ResKind::parse(&a[2]).expect("month|long|topup"), a[3].parse().expect("KAS")).await,
        Some("address") => println!("{}", p2pk_address(&key(&a[2]))),
        Some("check-contracts") => {
            if !check_contracts().await {
                eprintln!("CONTRACT SOURCES DO NOT MATCH THE LIVE CHAIN: chaind would lose its coins. Do not deploy.");
                std::process::exit(1);
            }
        }
        Some("consolidate") => {
            let d = Daemon { client: connect().await, treasury: None, batch: None, registry: Mutex::new(None), fund: Mutex::new(()), feerate: StdMutex::new((200.0, Instant::now())) };
            for _ in 0..a.get(2).and_then(|n| n.parse().ok()).unwrap_or(1) {
                println!("merged {:?}", d.consolidate().await);
            }
        }
        _ => eprintln!("usage: see the source header"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mix_sends_the_due_message_with_random_others_in_random_order() {
        let mut rng = rand::thread_rng();
        let (mut firsts, mut orders) = (std::collections::HashSet::new(), std::collections::HashSet::new());
        for _ in 0..200 {
            let mut pool: Vec<(u32, u32)> = (0..12).map(|k| (100 + k, k)).collect();
            pool.push((1, 99)); // due first
            let b = mix_take(&mut pool, &mut rng);
            assert_eq!(b.len(), BATCH);
            assert!(b.contains(&99), "the message that is due always leaves");
            assert_eq!(pool.len(), 13 - BATCH);
            let mut all: Vec<u32> = b.iter().copied().chain(pool.iter().map(|p| p.1)).collect();
            all.sort();
            assert_eq!(all, (0..12).chain([99]).collect::<Vec<_>>(), "nothing lost or duplicated");
            firsts.insert(b[0]);
            orders.insert(b.clone());
        }
        assert!(firsts.len() > 3 && orders.len() > 100, "position in the transaction and company are random");
        let mut small: Vec<(u32, u32)> = vec![(5, 1), (3, 2)];
        assert_eq!(mix_take(&mut small, &mut rng).len(), 2);
        assert!(small.is_empty());
    }
}
