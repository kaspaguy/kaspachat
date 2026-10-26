// Kaspaveil testnet checks (testnet-10 only). Usage:
//   kaspaveil-lanecheck keygen <keyfile>              creates a throwaway testnet key, prints its address
//   kaspaveil-lanecheck pub <keyfile>                 prints the key's x-only public key
//   kaspaveil-lanecheck balance <keyfile>             lists the key's UTXOs
//   kaspaveil-lanecheck send <keyfile> <payload.hex>  sends one self-paid v1 lane transaction and waits for acceptance
// Treasury (spending pot + reservoir). The pot's state lives in <pot.state>, updated after every accepted spend.
//   kaspaveil-lanecheck pot-genesis <fundkey> <relaykey> <rootkey|rootPubHex> <kas> <pot.state>   creates the pot (new covenant ID)
//   kaspaveil-lanecheck res-fund <fundkey> <kas> <pot.state>                           pays KAS into the reservoir
//   kaspaveil-lanecheck pot-topup <pot.state>                                          tops the pot up from the newest reservoir UTXO
//   kaspaveil-lanecheck res-sweep <pot.state> [early]                                  sweeps the oldest reservoir UTXO to the sweep address
//       (early: submits without waiting for the sweep age; consensus must reject it)
//   kaspaveil-lanecheck pot-relay <relaykey> <payload.hex> <pot.state> <mode> [fee]    pays one message fee from the pot
//       mode: ok | withdraw | wrong-lane | unbound | uncounted | wrong-key | timestamp | final-seq
//   kaspaveil-lanecheck pot-burst <relaykey> <payload.hex> <pot.state> <n>             n chained messages, back to back
//   kaspaveil-lanecheck pot-replace <rootkey|-> <newrelaykey> <pot.state>              root replaces the relay key
//       (rootkey "-": the ceremony's signature in KASPAVEIL_REPLACE_SIG, 64-byte hex)
//   kaspaveil-lanecheck pot-local <relaykey> <payload.hex> <pot.state>                 every relay mode, offline, on the local engine
//   kaspaveil-lanecheck pot-tx-vector <relaykey> <payload.hex> <pot.state>             a pot-paid transaction as a JSON test vector (offline)
// Needs KASPAVEIL_HOT (the silverscript kaspaveil_hot helper), KASPAVEIL_HOT_SIL (treasury_hot.sil), KASPAVEIL_RES_SIL (reservoir.sil),
// KASPAVEIL_RES_SWEEP_AGE (the reservoir's sweep age in DAA; mainnet one-month value 25920000) and KASPAVEIL_RES_SWEEP_ADDR (where sweeps go).
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
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_address_script, pay_to_script_hash_script,
};
use kaspa_wrpc_client::{
    KaspaRpcClient, Resolver, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use std::time::{Duration, Instant};

const LANE: [u8; 20] = *b"KVL\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const PAYLOAD_LEN: usize = 1536;
const KAS: u64 = 100_000_000;
// Default 0.02 KAS; override with KASPAVEIL_FEE (sompi) to probe the exact minimum.
fn fee() -> u64 {
    std::env::var("KASPAVEIL_FEE").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000_000)
}

fn keypair(path: &str) -> secp256k1::Keypair {
    let hex = std::fs::read_to_string(path).expect("read key").trim().to_string();
    let mut sk = [0u8; 32];
    faster_hex::hex_decode(hex.as_bytes(), &mut sk).expect("key hex");
    secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &sk).expect("valid key")
}

fn xonly(kp: &secp256k1::Keypair) -> [u8; 32] {
    kp.x_only_public_key().0.serialize()
}

fn address(kp: &secp256k1::Keypair) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &xonly(kp))
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") => {
            let sk: [u8; 32] = rand::random();
            let path = &a[2];
            std::fs::write(path, faster_hex::hex_string(&sk)).expect("write key");
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
            println!("{}", address(&secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &sk).unwrap()));
        }
        Some("pub") => println!("{}", faster_hex::hex_string(&xonly(&keypair(&a[2])))),
        Some("balance") => balance(&a[2]).await,
        Some("send") => send(&a[2], &a[3]).await,
        Some("pot-genesis") => pot_genesis(&a[2], &a[3], &a[4], a[5].parse().expect("KAS"), &a[6]).await,
        Some("res-fund") => res_fund(&a[2], a[3].parse().expect("KAS"), &a[4]).await,
        Some("pot-topup") => pot_topup(&a[2]).await,
        Some("res-sweep") => res_sweep(&a[2], a.get(3).map(String::as_str) == Some("early")).await,
        Some("pot-relay") => pot_relay(&a[2], &a[3], &a[4], &a[5], a.get(6).map(|f| f.parse().expect("fee"))).await,
        Some("pot-burst") => pot_burst(&a[2], &a[3], &a[4], a[5].parse().expect("n")).await,
        Some("pot-replace") => pot_replace(&a[2], &a[3], &a[4]).await,
        Some("pot-local") => pot_local(&a[2], &a[3], &a[4]),
        Some("pot-tx-vector") => pot_tx_vector(&a[2], &a[3], &a[4]),
        _ => eprintln!("usage: see the source header"),
    }
}

async fn send(key_path: &str, payload_path: &str) {
    let kp = keypair(key_path);
    let addr = address(&kp);
    let hex = std::fs::read_to_string(payload_path).expect("read payload").trim().to_string();
    let mut payload = vec![0u8; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut payload).expect("payload hex");
    assert_eq!(payload.len(), PAYLOAD_LEN, "Kaspaveil payloads are exactly 1,536 bytes");

    let network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let client = rpc_client(network);
    let opts = ConnectOptions { block_async_connect: true, connect_timeout: Some(Duration::from_secs(10)), strategy: ConnectStrategy::Fallback, ..Default::default() };
    client.connect(Some(opts)).await.expect("connect to a public testnet-10 node");
    let info = client.get_server_info().await.expect("server info");
    println!("node {} network {} synced {} utxoindex {}", info.server_version, info.network_id, info.is_synced, info.has_utxo_index);

    let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("utxos");
    let best = utxos.iter().filter(|u| spendable(u, info.virtual_daa_score)).max_by_key(|u| u.utxo_entry.amount).expect("no spendable funds at the test address yet");
    let amount = best.utxo_entry.amount;
    println!("spending {} sompi from {}", amount, addr);

    let entry: UtxoEntry = best.utxo_entry.clone().into();
    let outpoint: TransactionOutpoint = best.outpoint.into();
    let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 10);
    let change = TransactionOutput::new(amount - fee(), pay_to_address_script(&addr));
    let tx = Transaction::new(TX_VERSION_TOCCATA, vec![input], vec![change], 0, SubnetworkId::from_bytes(LANE), 0, payload.clone());

    let calc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    let storage = calc.calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![entry.clone()])).expect("storage mass").storage_mass;
    tx.set_storage_mass(storage);
    let mut signed = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
    signed.finalize();
    let nc = calc.calc_non_contextual_masses(&signed);
    println!("masses: compute {} transient {} storage {}; fee {} sompi", nc.compute_mass, nc.transient_mass, storage, fee());

    let low = client.get_block_dag_info().await.expect("dag info").sink;
    let txid = match client.submit_transaction((&signed).into(), false).await {
        Ok(id) => id,
        Err(e) => {
            println!("REJECTED by the node: {e}");
            return;
        }
    };
    println!("submitted {txid}");

    for _ in 0..60 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("utxos");
        if let Some(u) = utxos.iter().find(|u| u.outpoint.transaction_id == txid) {
            println!("ACCEPTED: change output confirmed at DAA score {}", u.utxo_entry.block_daa_score);
            // Read the transaction back out of the node's blocks and compare it byte for byte.
            let blocks = client.get_blocks(Some(low), true, true).await.expect("blocks").blocks;
            for block in &blocks {
                for t in &block.transactions {
                    let id = t.verbose_data.as_ref().map(|v| v.transaction_id);
                    if id == Some(txid) {
                        println!(
                            "FOUND in block {} (DAA {}): version {} lane {} gas {} payload {} bytes, identical to sent: {}",
                            block.header.hash, block.header.daa_score, t.version, t.subnetwork_id, t.gas, t.payload.len(),
                            t.payload == payload
                        );
                        return;
                    }
                }
            }
            println!("accepted, but not found in the {} blocks scanned", blocks.len());
            return;
        }
    }
    println!("not seen as accepted within 120 s");
}

// ---------- shared ----------

fn read_hex(path: &str) -> Vec<u8> {
    unhex(std::fs::read_to_string(path).expect("read hex file").trim())
}

fn unhex(s: &str) -> Vec<u8> {
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).expect("hex");
    out
}

// KASPAVEIL_RPC (e.g. ws://127.0.0.1:17210, a Borsh wRPC URL) uses that node; otherwise a public testnet-10 node.
fn rpc_client(network: NetworkId) -> KaspaRpcClient {
    match std::env::var("KASPAVEIL_RPC") {
        Ok(url) => KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&url), None, Some(network), None).expect("client"),
        Err(_) => KaspaRpcClient::new(WrpcEncoding::Borsh, None, Some(Resolver::default()), Some(network), None).expect("client"),
    }
}

// Coinbase outputs can't be spent until they are COINBASE_MATURITY DAA scores old (1,000 at 10 blocks a second; 2,000 for margin).
const COINBASE_MATURITY: u64 = 2_000;
fn spendable(u: &kaspa_rpc_core::RpcUtxosByAddressesEntry, now: u64) -> bool {
    !u.utxo_entry.is_coinbase || u.utxo_entry.block_daa_score + COINBASE_MATURITY <= now
}

async fn connect() -> KaspaRpcClient {
    let network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let client = rpc_client(network);
    let opts = ConnectOptions { block_async_connect: true, connect_timeout: Some(Duration::from_secs(10)), strategy: ConnectStrategy::Fallback, ..Default::default() };
    client.connect(Some(opts)).await.expect("connect to a public testnet-10 node");
    let info = client.get_server_info().await.expect("server info");
    println!("node {} network {} synced {} virtual DAA {}", info.server_version, info.network_id, info.is_synced, info.virtual_daa_score);
    client
}

async fn now_daa(client: &KaspaRpcClient) -> u64 {
    client.get_server_info().await.expect("info").virtual_daa_score
}

// Minimum relay fee (rusty-kaspa mempool rule): 100 sompi per gram of the larger of compute mass and normalized
// transient mass (x0.5). Storage mass has its own block limit and doesn't enter the fee.
fn min_fee(tx: &Transaction) -> (u64, String) {
    let nc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER).calc_non_contextual_masses(tx);
    let binding = nc.compute_mass.max(nc.transient_mass / 2);
    (binding * 100, format!("size {} B, compute {} transient {}", nc.transient_mass / 4, nc.compute_mass, nc.transient_mass))
}

// Funding transactions (pot genesis, reservoir deposits) pay FUNDING_FEERATE sompi per gram of their largest mass,
// storage mass included: a small coin split into a 2 KAS output has a storage mass far above its size, and a fee set
// from size alone sits unmined whenever testnet traffic pays more than the 100 sompi/gram floor.
const FUNDING_FEERATE: u64 = 200;
fn funding_fee(tx: &Transaction, entries: &[UtxoEntry]) -> u64 {
    let calc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    let nc = calc.calc_non_contextual_masses(tx);
    let storage = calc.calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec())).expect("storage mass").storage_mass;
    FUNDING_FEERATE * nc.compute_mass.max(nc.transient_mass / 2).max(storage) + 10_000
}

fn set_storage_mass(tx: &Transaction, entries: &[UtxoEntry]) {
    let calc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    let storage = calc.calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec())).expect("storage mass").storage_mass;
    tx.set_storage_mass(storage);
}

async fn submit_and_wait(client: &KaspaRpcClient, tx: &Transaction, watch: Address) -> bool {
    let txid = match client.submit_transaction(tx.into(), false).await {
        Ok(id) => id,
        Err(e) if e.to_string().contains("already spent by transaction") => match client.submit_transaction_replacement(tx.into()).await {
            Ok(r) => {
                println!("replaced a stuck mempool transaction for the same coin by fee");
                r.transaction_id
            }
            Err(e) => {
                println!("REJECTED by the node: {e}");
                return false;
            }
        },
        Err(e) => {
            println!("REJECTED by the node: {e}");
            return false;
        }
    };
    println!("submitted {txid}");
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let utxos = client.get_utxos_by_addresses(vec![watch.clone()]).await.expect("utxos");
        if let Some(u) = utxos.iter().find(|u| u.outpoint.transaction_id == txid) {
            println!("ACCEPTED: output {} sompi confirmed at DAA score {}", u.utxo_entry.amount, u.utxo_entry.block_daa_score);
            return true;
        }
    }
    println!("not seen as accepted within 120 s");
    false
}

fn p2sh_address(spk: &ScriptPublicKey) -> Address {
    Address::new(Prefix::Testnet, Version::ScriptHash, &spk.script()[2..34])
}

fn helper(args: &[String]) -> Vec<u8> {
    let bin = std::env::var("KASPAVEIL_HOT").expect("KASPAVEIL_HOT");
    let out = std::process::Command::new(bin).args(args).output().expect("run kaspaveil_hot");
    assert!(out.status.success(), "kaspaveil_hot: {}", String::from_utf8_lossy(&out.stderr));
    unhex(String::from_utf8(out.stdout).unwrap().trim())
}

// Runs the real script engine on every input, with the covenant context consensus builds. Returns each input's script units.
fn dry_run(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Vec<u64>, String> {
    let reused = SigHashReusedValuesUnsync::new();
    let cache = Cache::new(100);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov = CovenantsContext::from_tx(&populated).map_err(|e| format!("covenants: {e:?}"))?;
    let mut used = vec![];
    for i in 0..tx.inputs.len() {
        let ctx = EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov);
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated, &tx.inputs[i], i, &entries[i], ctx, EngineFlags::default(), u64::MAX.into(),
        );
        vm.execute().map_err(|e| format!("input {i}: {e}"))?;
        used.push(vm.used_script_units().0);
    }
    Ok(used)
}

fn budget(units: u64) -> u16 {
    units.div_ceil(SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT) as u16
}

// ---------- the pot's state and the throttle model (same rules as contracts/treasury_hot.sil) ----------

const INTERVAL_DAA: u64 = 36_000;
const N: u64 = 168;
const K: u64 = 5;
const FLOOR: u64 = 20 * KAS;
const RES_MAX_FEE: u64 = 1_000_000;

#[derive(Clone, Debug)]
struct Pot {
    cov: Hash,
    root: [u8; 32],
    relay: [u8; 32],
    interval: u64,
    spent: u64,
    smma: u64,
    nonce: u64,
    outpoint: TransactionOutpoint,
    value: u64,
}

impl Pot {
    fn load(path: &str) -> Pot {
        let s = std::fs::read_to_string(path).expect("read pot state");
        let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(&format!("{k} "))).unwrap_or_else(|| panic!("{k} missing")).to_string();
        let b32 = |k: &str| -> [u8; 32] { unhex(&get(k)).try_into().unwrap() };
        Pot {
            cov: Hash::from_bytes(b32("cov")),
            root: b32("root"),
            relay: b32("relay"),
            interval: get("interval").parse().unwrap(),
            spent: get("spent").parse().unwrap(),
            smma: get("smma").parse().unwrap(),
            nonce: get("nonce").parse().unwrap(),
            outpoint: TransactionOutpoint::new(TransactionId::from_bytes(b32("txid")), get("index").parse().unwrap()),
            value: get("value").parse().unwrap(),
        }
    }
    fn save(&self, path: &str) {
        let h = faster_hex::hex_string;
        let s = format!(
            "cov {}\nroot {}\nrelay {}\ninterval {}\nspent {}\nsmma {}\nnonce {}\ntxid {}\nindex {}\nvalue {}\n",
            h(&self.cov.as_bytes()), h(&self.root), h(&self.relay), self.interval, self.spent, self.smma, self.nonce,
            h(&self.outpoint.transaction_id.as_bytes()), self.outpoint.index, self.value
        );
        std::fs::write(path, s).expect("write pot state");
    }
    fn state_args(&self) -> Vec<String> {
        let h = faster_hex::hex_string;
        vec![h(&self.root), h(&self.relay), self.interval.to_string(), self.spent.to_string(), self.smma.to_string(), self.nonce.to_string()]
    }
    fn helper_args(&self, cmd: &str) -> Vec<String> {
        let mut v = vec![cmd.to_string(), std::env::var("KASPAVEIL_HOT_SIL").expect("KASPAVEIL_HOT_SIL")];
        v.extend(self.state_args());
        v
    }
    fn code(&self) -> Vec<u8> {
        helper(&self.helper_args("pot-bytecode"))
    }
    fn spk(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.code())
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
    fn allowance(s: u64) -> u64 {
        (K * s).max(FLOOR)
    }
    // The state after a message paying `fee` (spent_counted = false models the "uncounted" attack).
    fn after_message(&self, cur: u64, fee: u64, counted: bool) -> Pot {
        let s = self.smma_at(cur);
        let base = if cur == self.interval { self.spent } else { 0 };
        Pot { interval: cur, spent: base + if counted { fee } else { 0 }, smma: s, ..self.clone() }
    }
    fn after_topup(&self, cur: u64) -> Pot {
        let s = self.smma_at(cur);
        let base = if cur == self.interval { self.spent } else { 0 };
        Pot { interval: cur, spent: base, smma: s, ..self.clone() }
    }
    fn describe(&self, cur: u64) -> String {
        let s = self.smma_at(cur);
        let base = if cur == self.interval { self.spent } else { 0 };
        format!("pot {} holds {} sompi; interval {} spent {} of allowance {} (SMMA {}); relay key {}…; nonce {}",
            self.address(), self.value, cur, base, Pot::allowance(s), s, &faster_hex::hex_string(&self.relay)[..8], self.nonce)
    }
}

// The reservoir's compile arguments after the .sil path: potCov, sweep age, sweep script (2-byte version + script).
fn res_args(cmd: &str, cov: Hash) -> Vec<String> {
    let age: u64 = std::env::var("KASPAVEIL_RES_SWEEP_AGE").expect("KASPAVEIL_RES_SWEEP_AGE").parse().expect("sweep age");
    let mut to = sweep_spk().version().to_be_bytes().to_vec();
    to.extend_from_slice(sweep_spk().script());
    vec![cmd.into(), std::env::var("KASPAVEIL_RES_SIL").expect("KASPAVEIL_RES_SIL"), faster_hex::hex_string(&cov.as_bytes()), age.to_string(), faster_hex::hex_string(&to)]
}

fn sweep_spk() -> ScriptPublicKey {
    pay_to_address_script(&Address::try_from(std::env::var("KASPAVEIL_RES_SWEEP_ADDR").expect("KASPAVEIL_RES_SWEEP_ADDR").as_str()).expect("sweep address"))
}

fn res_code(cov: Hash) -> Vec<u8> {
    helper(&res_args("res-bytecode", cov))
}

fn res_spk(cov: Hash) -> ScriptPublicKey {
    pay_to_script_hash_script(&res_code(cov))
}

// ---------- commands ----------

async fn balance(key_path: &str) {
    let addr = address(&keypair(key_path));
    let client = connect().await;
    let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("utxos");
    let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    println!("{addr}: {} UTXOs, {} sompi ({:.4} KAS)", utxos.len(), total, total as f64 / KAS as f64);
}

// Pot genesis: output 0 is the pot with its initial state, bound to a new covenant ID computed from the funding
// outpoint and that output; output 1 is change. The funding key signs; the pot script doesn't run at genesis.
async fn pot_genesis(fund_path: &str, relay_path: &str, root_path: &str, kas: u64, state_path: &str) {
    let kp = keypair(fund_path);
    let addr = address(&kp);
    let client = connect().await;
    let now = now_daa(&client).await;
    let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("utxos");
    let best = utxos.iter().filter(|u| spendable(u, now)).max_by_key(|u| u.utxo_entry.amount).expect("no spendable funds at the funding address");
    let entry: UtxoEntry = best.utxo_entry.clone().into();
    let outpoint: TransactionOutpoint = best.outpoint.into();
    let mut pot = Pot {
        cov: Hash::from_bytes([0; 32]),
        root: if std::path::Path::new(root_path).exists() { xonly(&keypair(root_path)) } else { unhex(root_path).try_into().expect("root: key file or 32-byte hex public key") },
        relay: xonly(&keypair(relay_path)),
        interval: now / INTERVAL_DAA,
        spent: 0,
        smma: 0,
        nonce: 0,
        outpoint,
        value: kas * KAS,
    };
    let unbound = TransactionOutput::new(pot.value, pot.spk());
    pot.cov = covenant_id(outpoint, [(0u32, &unbound)].into_iter());
    let build = |fee: u64| {
        let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 10);
        let outs = vec![pot.output(pot.value), TransactionOutput::new(entry.amount - pot.value - fee, pay_to_address_script(&addr))];
        Transaction::new(TX_VERSION_TOCCATA, vec![input], outs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    };
    let (_, masses) = min_fee(&build(0));
    let fee = funding_fee(&build(0), std::slice::from_ref(&entry));
    let tx = build(fee);
    set_storage_mass(&tx, std::slice::from_ref(&entry));
    let mut signed = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
    signed.finalize();
    println!("pot genesis: covenant ID {}; {masses}; fee {fee}", pot.cov);
    if submit_and_wait(&client, &signed, pot.address()).await {
        pot.outpoint = TransactionOutpoint::new(signed.id(), 0);
        pot.save(state_path);
        println!("{}", pot.describe(pot.interval));
        println!("reservoir address for this pot: {}", p2sh_address(&res_spk(pot.cov)));
    }
}

async fn res_fund(fund_path: &str, kas: u64, state_path: &str) {
    let kp = keypair(fund_path);
    let addr = address(&kp);
    let pot = Pot::load(state_path);
    let spk = res_spk(pot.cov);
    let client = connect().await;
    let now = now_daa(&client).await;
    let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("utxos");
    let best = utxos.iter().filter(|u| spendable(u, now)).max_by_key(|u| u.utxo_entry.amount).expect("no spendable funds");
    let entry: UtxoEntry = best.utxo_entry.clone().into();
    let build = |fee: u64| {
        let input = TransactionInput::new_with_compute_budget(best.outpoint.into(), vec![], 0, 10);
        let outs = vec![TransactionOutput::new(kas * KAS, spk.clone()), TransactionOutput::new(entry.amount - kas * KAS - fee, pay_to_address_script(&addr))];
        Transaction::new(TX_VERSION_TOCCATA, vec![input], outs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    };
    let fee = funding_fee(&build(0), std::slice::from_ref(&entry));
    let tx = build(fee);
    set_storage_mass(&tx, std::slice::from_ref(&entry));
    let mut signed = sign(SignableTransaction::with_entries(tx, vec![entry]), kp).tx;
    signed.finalize();
    println!("paying {kas} KAS into the reservoir {}", p2sh_address(&spk));
    submit_and_wait(&client, &signed, p2sh_address(&spk)).await;
}

// Top-up: inputs [pot, one reservoir UTXO]; outputs [pot filled to the allowance, reservoir change] or [pot + whole UTXO].
async fn pot_topup(state_path: &str) {
    let pot = Pot::load(state_path);
    let client = connect().await;
    let lock = now_daa(&client).await - 10;
    let cur = lock / INTERVAL_DAA;
    println!("{}", pot.describe(cur));
    let rspk = res_spk(pot.cov);
    let raddr = p2sh_address(&rspk);
    let rutxos = client.get_utxos_by_addresses(vec![raddr.clone()]).await.expect("utxos");
    // Newest first (SC-0015): older deposits are left to outlive their credits and be swept.
    let r = rutxos.iter().max_by_key(|u| u.utxo_entry.block_daa_score).expect("reservoir is empty");
    let rentry: UtxoEntry = r.utxo_entry.clone().into();
    let next = pot.after_topup(cur);
    let cap = Pot::allowance(next.smma);
    let pot_sig = helper(&[pot.helper_args("pot-step"), vec![faster_hex::hex_string(&[0u8; 65])]].concat());
    let res_sig = helper(&res_args("res-topup", pot.cov));
    let entries = vec![pot.entry(), rentry.clone()];
    let whole = pot.value + rentry.amount <= cap + RES_MAX_FEE;
    let build = |fee: u64, b0: u16, b1: u16| {
        let ins = vec![
            TransactionInput::new_with_compute_budget(pot.outpoint, pot_sig.clone(), 0, b0),
            TransactionInput::new_with_compute_budget(r.outpoint.into(), res_sig.clone(), 0, b1),
        ];
        let outs = if whole {
            vec![next.output(pot.value + rentry.amount - fee)]
        } else {
            vec![next.output(cap), TransactionOutput::new(rentry.amount - (cap - pot.value) - fee, rspk.clone())]
        };
        Transaction::new(TX_VERSION_TOCCATA, ins, outs, lock, SUBNETWORK_ID_NATIVE, 0, vec![])
    };
    let units = dry_run(&build(RES_MAX_FEE, 200, 200), &entries).expect("top-up must pass the local engine");
    let (b0, b1) = (budget(units[0]), budget(units[1]));
    let (floor, masses) = min_fee(&build(0, b0, b1));
    let fee = floor + 5_000;
    let tx = build(fee, b0, b1);
    set_storage_mass(&tx, &entries);
    let mut tx = tx;
    tx.finalize();
    println!("top-up from reservoir UTXO of {} sompi ({}); budgets {b0}/{b1}; {masses}; fee {fee}; local engine {:?}",
        rentry.amount, if whole { "whole" } else { "fill to the allowance, change back" }, dry_run(&tx, &entries).map(|_| "PASS"));
    let new_value = tx.outputs[0].value;
    if submit_and_wait(&client, &tx, next.address()).await {
        Pot { outpoint: TransactionOutpoint::new(tx.id(), 0), value: new_value, ..next }.save(state_path);
    }
}

// Sweep: one reservoir UTXO, whole, to the sweep address, with the input sequence set to the sweep age (the relative
// DAA lock consensus enforces). Without `early` it waits until the UTXO is old enough; with it, it submits at once.
async fn res_sweep(state_path: &str, early: bool) {
    let pot = Pot::load(state_path);
    let client = connect().await;
    let age: u64 = std::env::var("KASPAVEIL_RES_SWEEP_AGE").expect("KASPAVEIL_RES_SWEEP_AGE").parse().expect("sweep age");
    let rspk = res_spk(pot.cov);
    let rutxos = client.get_utxos_by_addresses(vec![p2sh_address(&rspk)]).await.expect("utxos");
    let r = rutxos.iter().min_by_key(|u| u.utxo_entry.block_daa_score).expect("reservoir is empty");
    let entry: UtxoEntry = r.utxo_entry.clone().into();
    let sig = helper(&res_args("res-sweep", pot.cov));
    let to = sweep_spk();
    let build = |fee: u64, b: u16| {
        let ins = vec![TransactionInput::new_with_compute_budget(r.outpoint.into(), sig.clone(), age, b)];
        Transaction::new(TX_VERSION_TOCCATA, ins, vec![TransactionOutput::new(entry.amount - fee, to.clone())], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    };
    let units = dry_run(&build(RES_MAX_FEE, 200), std::slice::from_ref(&entry)).expect("sweep must pass the local engine");
    let b = budget(units[0]);
    let (floor, masses) = min_fee(&build(0, b));
    let tx = build(floor + 5_000, b);
    set_storage_mass(&tx, std::slice::from_ref(&entry));
    let mut tx = tx;
    tx.finalize();
    let ripe = entry.block_daa_score + age;
    let now = now_daa(&client).await;
    println!("sweep of reservoir UTXO {} sompi created at DAA {}; sweepable from DAA {ripe}; now {now}; {masses}; fee {}", entry.amount, entry.block_daa_score, floor + 5_000);
    if !early {
        while now_daa(&client).await < ripe + 10 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    let watch = Address::new(Prefix::Testnet, Version::PubKey, &to.script()[1..33]);
    submit_and_wait(&client, &tx, watch).await;
}

const MODES: [&str; 8] = ["ok", "withdraw", "wrong-lane", "unbound", "uncounted", "wrong-key", "timestamp", "final-seq"];

// A relay-paid message for `mode`, fee `fee` (0 = the minimum + 5,000 sompi). Returns (tx, entries, next state, local verdict).
fn build_message(pot: &Pot, relay: &secp256k1::Keypair, payload: &[u8], lock: u64, mode: &str, fee: Option<u64>) -> (Transaction, Vec<UtxoEntry>, Pot, Result<Vec<u64>, String>) {
    let lock = if mode == "timestamp" { 1_790_000_000_000 } else { lock };
    let cur = lock / INTERVAL_DAA;
    let signer = if mode == "wrong-key" { secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[66; 32]).unwrap() } else { *relay };
    let lane = if mode == "wrong-lane" { SUBNETWORK_ID_NATIVE } else { SubnetworkId::from_bytes(LANE) };
    let sequence = if mode == "final-seq" { u64::MAX } else { 0 };
    let entries = vec![pot.entry()];
    let build = |fee: u64, b: u16| -> (Transaction, Pot) {
        let next = pot.after_message(cur, fee, mode != "uncounted");
        let out = match mode {
            "withdraw" => TransactionOutput::new(pot.value - fee, pay_to_address_script(&address(relay))),
            "unbound" => TransactionOutput::new(pot.value - fee, next.spk()),
            _ => next.output(pot.value - fee),
        };
        let mut tx = Transaction::new(TX_VERSION_TOCCATA, vec![TransactionInput::new_with_compute_budget(pot.outpoint, vec![], sequence, b)], vec![out], lock, lane, 0, payload.to_vec());
        let reused = SigHashReusedValuesUnsync::new();
        let hash = calc_schnorr_signature_hash(&PopulatedTransaction::new(&tx, entries.clone()), 0, SIG_HASH_ALL, &reused);
        let mut sig = signer.sign_schnorr(secp256k1::Message::from_digest(hash.as_bytes())).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        tx.inputs[0].signature_script = helper(&[pot.helper_args("pot-step"), vec![faster_hex::hex_string(&sig)]].concat());
        tx.finalize();
        (tx, next)
    };
    // Size the compute budget and the fee on the honest version of the transaction.
    let (probe, _) = build(1_000_000, 200);
    let units = dry_run(&probe, &entries).map(|u| budget(u[0])).unwrap_or(40);
    let (floor, masses) = min_fee(&build(1_000_000, units).0);
    let fee = fee.unwrap_or(floor + 5_000);
    let (tx, next) = build(fee, units);
    set_storage_mass(&tx, &entries);
    let verdict = dry_run(&tx, &entries);
    println!("[{mode}] interval {cur} budget {units}; {masses}; minimum fee {floor}, fee {fee}; local engine: {}",
        match &verdict { Ok(u) => format!("PASS ({} script units)", u[0]), Err(e) => format!("FAIL ({e})") });
    (tx, entries, next, verdict)
}

fn pot_local(relay_path: &str, payload_path: &str, state_path: &str) {
    let pot = Pot::load(state_path);
    let payload = read_hex(payload_path);
    let lock = pot.interval * INTERVAL_DAA + 1_000;
    for mode in MODES {
        let _ = build_message(&pot, &keypair(relay_path), &payload, lock, mode, None);
    }
}

async fn pot_relay(relay_path: &str, payload_path: &str, state_path: &str, mode: &str, fee: Option<u64>) {
    let pot = Pot::load(state_path);
    let payload = read_hex(payload_path);
    assert_eq!(payload.len(), PAYLOAD_LEN);
    let client = connect().await;
    let lock = now_daa(&client).await - 10;
    println!("{}", pot.describe(lock / INTERVAL_DAA));
    let (tx, _, next, _) = build_message(&pot, &keypair(relay_path), &payload, lock, mode, fee);
    let watch = match mode {
        "withdraw" => address(&keypair(relay_path)),
        _ => next.address(),
    };
    let low = client.get_block_dag_info().await.expect("dag info").sink;
    let paid = pot.value - tx.outputs[0].value;
    if submit_and_wait(&client, &tx, watch).await {
        if matches!(mode, "ok") {
            Pot { outpoint: TransactionOutpoint::new(tx.id(), 0), value: tx.outputs[0].value, ..next }.save(state_path);
        }
        println!("fee paid {paid} sompi ({:.6} KAS)", paid as f64 / KAS as f64);
        let id = tx.id();
        for block in client.get_blocks(Some(low), true, true).await.expect("blocks").blocks {
            if let Some(t) = block.transactions.iter().find(|t| t.verbose_data.as_ref().map(|v| v.transaction_id) == Some(id)) {
                println!("FOUND in block {}: lane {} payload {} bytes, identical: {}", block.header.hash, t.subnetwork_id, t.payload.len(), t.payload == payload);
                break;
            }
        }
    }
}

// n messages, each spending the previous one's unconfirmed pot output, submitted back to back.
async fn pot_burst(relay_path: &str, payload_path: &str, state_path: &str, n: usize) {
    let mut pot = Pot::load(state_path);
    let payload = read_hex(payload_path);
    let relay = keypair(relay_path);
    let client = connect().await;
    let lock = now_daa(&client).await - 10;
    let mut txs = vec![];
    for _ in 0..n {
        let (tx, _, next, verdict) = build_message(&pot, &relay, &payload, lock, "ok", None);
        verdict.expect("each chained message must pass the local engine");
        pot = Pot { outpoint: TransactionOutpoint::new(tx.id(), 0), value: tx.outputs[0].value, ..next };
        txs.push(tx);
    }
    let start = Instant::now();
    let mut accepted = 0;
    for (i, tx) in txs.iter().enumerate() {
        match client.submit_transaction(tx.into(), false).await {
            Ok(_) => accepted += 1,
            Err(e) => {
                println!("message {} of {n} REJECTED: {e}", i + 1);
                break;
            }
        }
    }
    println!("{accepted} of {n} chained messages accepted into the mempool in {:.2} s", start.elapsed().as_secs_f64());
    if accepted < n {
        println!("burst stopped part-way; the pot state file was not updated");
        return;
    }
    let last = &txs[n - 1];
    let addr = pot.address();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let utxos = client.get_utxos_by_addresses(vec![addr.clone()]).await.expect("utxos");
        if utxos.iter().any(|u| u.outpoint.transaction_id == last.id()) {
            println!("all {accepted} confirmed within {:.1} s of the first submission", start.elapsed().as_secs_f64());
            pot.save(state_path);
            return;
        }
    }
    println!("last message not confirmed within 60 s");
}

async fn pot_replace(root_path: &str, new_relay_path: &str, state_path: &str) {
    let pot = Pot::load(state_path);
    let new_relay = xonly(&keypair(new_relay_path));
    let mut m = b"kasveil/v1/relay-replace".to_vec();
    m.extend(pot.cov.as_bytes());
    m.extend(new_relay);
    m.extend(pot.nonce.to_le_bytes());
    let digest: [u8; 32] = blake2b_simd::Params::new().hash_length(32).hash(&m).as_bytes().try_into().unwrap();
    println!("replacement digest (what the root signs): {}", faster_hex::hex_string(&digest));
    let sig = if root_path == "-" {
        unhex(std::env::var("KASPAVEIL_REPLACE_SIG").expect("KASPAVEIL_REPLACE_SIG").trim())
    } else {
        keypair(root_path).sign_schnorr(secp256k1::Message::from_digest(digest)).as_ref().to_vec()
    };
    let next = Pot { relay: new_relay, nonce: pot.nonce + 1, ..pot.clone() };
    let ss = helper(&[pot.helper_args("pot-replace"), vec![faster_hex::hex_string(&new_relay), faster_hex::hex_string(&sig)]].concat());
    let entries = vec![pot.entry()];
    let build = |fee: u64, b: u16| {
        let mut tx = Transaction::new(TX_VERSION_TOCCATA, vec![TransactionInput::new_with_compute_budget(pot.outpoint, ss.clone(), 0, b)],
            vec![next.output(pot.value - fee)], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        tx.finalize();
        tx
    };
    let units = dry_run(&build(1_000_000, 200), &entries).map(|u| budget(u[0])).unwrap_or(40);
    let (floor, masses) = min_fee(&build(0, units));
    let tx = build(floor + 5_000, units);
    set_storage_mass(&tx, &entries);
    let verdict = dry_run(&tx, &entries);
    println!("replace relay key → {}…; {masses}; fee {}; local engine: {}", &faster_hex::hex_string(&new_relay)[..8], floor + 5_000,
        match &verdict { Ok(_) => "PASS".to_string(), Err(e) => format!("FAIL ({e})") });
    let client = connect().await;
    if submit_and_wait(&client, &tx, next.address()).await && verdict.is_ok() {
        Pot { outpoint: TransactionOutpoint::new(tx.id(), 0), value: tx.outputs[0].value, ..next }.save(state_path);
    }
}

// A fixed pot-paid transaction for the published test vectors: every field, the Kaspa transaction ID and the
// masses behind the minimum fee, all computed by rusty-kaspa's own code. Checked on the engine first. The pot
// state comes from <pot.state> (its outpoint, value and interval are used as given; lock time = interval start + 5,000).
fn pot_tx_vector(relay_path: &str, payload_path: &str, state_path: &str) {
    let pot = Pot::load(state_path);
    let payload = read_hex(payload_path);
    let lock = pot.interval * INTERVAL_DAA + 5_000;
    let (tx, entries, _, verdict) = build_message(&pot, &keypair(relay_path), &payload, lock, "ok", None);
    assert!(verdict.is_ok(), "vector transaction must pass the script engine");
    let calc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    let nc = calc.calc_non_contextual_masses(&tx);
    let storage = calc.calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone())).unwrap().storage_mass;
    let h = |b: &[u8]| faster_hex::hex_string(b);
    let (input, out, entry) = (&tx.inputs[0], &tx.outputs[0], &entries[0]);
    let cov = out.covenant.as_ref().expect("bound");
    println!(
        "{{\"version\":{},\"subnetwork_id\":\"{}\",\"gas\":{},\"lock_time\":{},\"inputs\":[{{\"previous_txid\":\"{}\",\"previous_index\":{},\"sequence\":{},\"compute_budget\":{},\"signature_script\":\"{}\",\"utxo_amount\":{},\"utxo_script_public_key\":\"{}\",\"utxo_script_version\":{},\"utxo_daa_score\":{},\"utxo_covenant_id\":\"{}\"}}],\"outputs\":[{{\"value\":{},\"script_public_key\":\"{}\",\"script_version\":{},\"covenant\":{{\"authorizing_input\":{},\"covenant_id\":\"{}\"}}}}],\"payload\":\"{}\",\"transaction_id\":\"{}\",\"estimated_serialized_size\":{},\"compute_mass\":{},\"transient_mass\":{},\"storage_mass\":{},\"fee\":{}}}",
        tx.version, tx.subnetwork_id, tx.gas, tx.lock_time, input.previous_outpoint.transaction_id, input.previous_outpoint.index, input.sequence,
        input.compute_commit.compute_budget().unwrap(), h(&input.signature_script), entry.amount, h(entry.script_public_key.script()),
        entry.script_public_key.version(), entry.block_daa_score, pot.cov, out.value, h(out.script_public_key.script()), out.script_public_key.version(),
        cov.authorizing_input, cov.covenant_id, h(&tx.payload), tx.id(), nc.transient_mass / 4, nc.compute_mass, nc.transient_mass, storage, entry.amount - out.value
    );
}
