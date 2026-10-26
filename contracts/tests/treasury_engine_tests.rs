// Kaspaveil treasury tests against the real rusty-kaspa script engine (real Schnorr signatures, real v1
// transactions with lane, payload, lock time and covenant bindings). Run with contracts/tools/run_engine_tests.sh.
//
// The spending pot (treasury_hot.sil) is one covenant with state: relay key, interval, spent, SMMA, key nonce.
// Each test builds the pot UTXO with a given state and the continuation output with the state the rules
// require, computed here by an independent model of the throttle (`Model`).
mod common;

use common::{bytecode, compile_contract, encode_entry_sig_script, push_redeem_script};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script};
use silverscript_abi::ArtifactValue;
use silverscript_lang::compiler::CompileOptions;

const HOT_SRC: &str = include_str!("kaspaveil/treasury_hot.sil");
const RES_SRC: &str = include_str!("kaspaveil/reservoir.sil");
const LANE: [u8; 20] = *b"KVL\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const KAS: u64 = 100_000_000;
const MAX_FEE: u64 = KAS;
const ADMIN_FEE: u64 = 1_000_000;
const RES_MAX_FEE: u64 = 1_000_000;
const INTERVAL_DAA: u64 = 36_000;
const N: u64 = 168;
const PER_DAY: u64 = 24; // intervals per day
const K: u64 = 5;
const FLOOR: u64 = 20 * KAS;
const MIN_TOPUP: u64 = KAS;
const MSG_FEE: u64 = 530_000; // about what a relay-paid 1,536-byte message costs with this pot
const I0: u64 = 13_200; // current interval in these tests (mainnet DAA ≈ 475M)
const POT_COV: [u8; 32] = [0xc0; 32];
const OTHER_COV: [u8; 32] = [0xc1; 32];

fn keypair(seed: u8) -> secp256k1::Keypair {
    secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[seed; 32]).unwrap()
}

fn xonly(kp: &secp256k1::Keypair) -> Vec<u8> {
    kp.x_only_public_key().0.serialize().to_vec()
}

fn attacker() -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(xonly(&keypair(66)));
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

// ---------- independent model of the throttle ----------

#[derive(Clone, Copy, Debug, PartialEq)]
struct PotState {
    relay: [u8; 32],
    interval: u64,
    spent: u64,
    smma: u64,
    nonce: u64,
}

struct Model;
impl Model {
    fn smma_at(st: &PotState, cur: u64) -> u64 {
        if cur <= st.interval {
            return st.smma; // cur < interval only in a rejection test
        }
        let s = (st.smma * (N - 1) + st.spent) / N;
        let gap = cur - st.interval - 1;
        if gap >= N { 0 } else { s * (N - gap) / N }
    }
    fn allowance(s: u64) -> u64 {
        (K * s).max(FLOOR)
    }
    fn after_message(st: &PotState, cur: u64, fee: u64) -> PotState {
        let s = Self::smma_at(st, cur);
        let base = if cur == st.interval { st.spent } else { 0 };
        PotState { interval: cur, spent: base + fee, smma: s, ..*st }
    }
    fn after_topup(st: &PotState, cur: u64) -> PotState {
        let s = Self::smma_at(st, cur);
        let base = if cur == st.interval { st.spent } else { 0 };
        PotState { interval: cur, spent: base, smma: s, ..*st }
    }
}

// ---------- building and running transactions ----------

struct Pot {
    root: Vec<u8>,
    cache: std::cell::RefCell<std::collections::HashMap<(u64, u64, u64, u64, [u8; 32]), silverscript_abi::SilAbiArtifact>>,
}

impl Pot {
    fn artifact(&self, st: &PotState) -> silverscript_abi::SilAbiArtifact {
        let key = (st.interval, st.spent, st.smma, st.nonce, st.relay);
        if let Some(a) = self.cache.borrow().get(&key) {
            return a.clone();
        }
        let args = [
            ArtifactValue::from(self.root.clone()),
            ArtifactValue::from(FLOOR as i64),
            ArtifactValue::from(st.relay.to_vec()),
            ArtifactValue::from(st.interval as i64),
            ArtifactValue::from(st.spent as i64),
            ArtifactValue::from(st.smma as i64),
            ArtifactValue::from(st.nonce as i64),
        ];
        let a = compile_contract(HOT_SRC, &args, CompileOptions::default()).expect("pot compiles");
        self.cache.borrow_mut().insert(key, a.clone());
        a
    }
    fn spk(&self, st: &PotState) -> ScriptPublicKey {
        pay_to_script_hash_script(&bytecode(&self.artifact(st)))
    }
    fn out(&self, value: u64, st: &PotState) -> TransactionOutput {
        self.out_cov(value, st, POT_COV)
    }
    fn out_cov(&self, value: u64, st: &PotState, cov: [u8; 32]) -> TransactionOutput {
        TransactionOutput { value, script_public_key: self.spk(st), covenant: Some(CovenantBinding::new(0, Hash::from_bytes(cov))) }
    }
    fn utxo(&self, value: u64, st: &PotState, cov: [u8; 32]) -> UtxoEntry {
        UtxoEntry::new(value, self.spk(st), st.interval * INTERVAL_DAA, false, Some(Hash::from_bytes(cov)))
    }
}

fn pot(root: &secp256k1::Keypair) -> Pot {
    Pot { root: xonly(root), cache: Default::default() }
}

fn fresh(relay: &secp256k1::Keypair) -> PotState {
    PotState { relay: xonly(relay).try_into().unwrap(), interval: I0, spent: 0, smma: 0, nonce: 0 }
}

fn input(n: u8, sequence: u64) -> TransactionInput {
    TransactionInput::new(TransactionOutpoint { transaction_id: TransactionId::from_bytes([n; 32]), index: 0 }, vec![], sequence, 0)
}

fn plain(value: u64, spk: ScriptPublicKey) -> TransactionOutput {
    TransactionOutput { value, script_public_key: spk, covenant: None }
}

// Runs every input's script on the real engine, with the covenant context consensus would build.
fn run(tx: &Transaction, utxos: &[UtxoEntry]) -> Result<(), String> {
    let populated = PopulatedTransaction::new(tx, utxos.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("covenants: {e:?}"))?;
    let reused = SigHashReusedValuesUnsync::new();
    let cache = Cache::new(100);
    for i in 0..tx.inputs.len() {
        let entry = populated.utxo(i).unwrap();
        let mut vm = TxScriptEngine::from_transaction_input(
            &populated,
            &tx.inputs[i],
            i,
            entry,
            EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov_ctx),
            EngineFlags { covenants_enabled: true, ..Default::default() },
        );
        vm.execute().map_err(|e| format!("input {i}: {e}"))?;
    }
    Ok(())
}

fn reject(name: &str, r: Result<(), String>) {
    match r {
        Ok(()) => panic!("must reject: {name}"),
        Err(e) => println!("rejected as it should be: {name}: {e}"),
    }
}

fn sign_input0(tx: &Transaction, utxos: &[UtxoEntry], kp: &secp256k1::Keypair) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&PopulatedTransaction::new(tx, utxos.to_vec()), 0, SIG_HASH_ALL, &reused);
    let mut sig = kp.sign_schnorr(secp256k1::Message::from_digest(hash.as_bytes())).as_ref().to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    sig
}

struct Msg<'a> {
    signer: &'a secp256k1::Keypair,
    lock_time: u64,
    sequence: u64,
    outs: Vec<TransactionOutput>,
    lane: [u8; 20],
    payload_len: usize,
    in_cov: [u8; 32],
}

// A relay-paid message spending a pot UTXO with state `st`.
fn message(p: &Pot, st: &PotState, value: u64, m: Msg) -> (Transaction, Vec<UtxoEntry>) {
    let utxos = vec![p.utxo(value, st, m.in_cov)];
    let mut tx = Transaction::new(1, vec![input(7, m.sequence)], m.outs, m.lock_time, SubnetworkId::from_bytes(m.lane), 0, vec![0xab; m.payload_len]);
    let sig = sign_input0(&tx, &utxos, m.signer);
    let art = p.artifact(st);
    let mut ss = encode_entry_sig_script(&art, "step", &[sig.into()]).unwrap();
    ss.extend(push_redeem_script(&bytecode(&art)));
    tx.inputs[0].signature_script = ss;
    (tx, utxos)
}

fn daa(interval: u64) -> u64 {
    interval * INTERVAL_DAA + 5_000
}

// The correct message: pays `fee`, continuation carries exactly the model's next state.
fn ok_msg<'a>(p: &Pot, st: &PotState, value: u64, fee: u64, cur: u64, signer: &'a secp256k1::Keypair) -> Msg<'a> {
    let next = Model::after_message(st, cur, fee);
    Msg { signer, lock_time: daa(cur), sequence: 0, outs: vec![p.out(value - fee, &next)], lane: LANE, payload_len: 1536, in_cov: POT_COV }
}

fn pays(p: &Pot, st: &PotState, value: u64, fee: u64, cur: u64, signer: &secp256k1::Keypair) -> Result<(), String> {
    let (tx, u) = message(p, st, value, ok_msg(p, st, value, fee, cur, signer));
    run(&tx, &u)
}

#[test]
fn pot_pays_message_fees_within_the_allowance() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let st = fresh(&relay);
    let v = 20 * KAS;
    pays(&p, &st, v, MSG_FEE, I0, &relay).expect("one message");
    pays(&p, &st, v, MAX_FEE, I0, &relay).expect("fee exactly at the 1 KAS cap");
    let (tx, u) = message(&p, &st, v, Msg { payload_len: 4096, ..ok_msg(&p, &st, v, MSG_FEE, I0, &relay) });
    run(&tx, &u).expect("a future 4 KB message size still works");
    let (tx, u) = message(&p, &st, v, Msg { payload_len: 256, ..ok_msg(&p, &st, v, MSG_FEE, I0, &relay) });
    run(&tx, &u).expect("a future 256-byte message size still works");
    // Spending up to exactly the allowance (the floor, for a fresh pot) passes; one sompi more doesn't.
    let nearly = PotState { spent: FLOOR - MSG_FEE, ..st };
    pays(&p, &nearly, v, MSG_FEE, I0, &relay).expect("interval total exactly at the allowance");
    assert!(pays(&p, &nearly, v, MSG_FEE + 1, I0, &relay).is_err(), "one sompi over the allowance");
}

// SC-0019: lanes share the covenant ID but every spend moves exactly one lane.
#[test]
fn pot_lanes_stay_separate() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let st = fresh(&relay);
    let v = 20 * KAS;
    let next = Model::after_message(&st, I0, MSG_FEE);
    let art = p.artifact(&st);
    let sign_step = |tx: &mut Transaction, u: &[UtxoEntry], i: usize| {
        let reused = SigHashReusedValuesUnsync::new();
        let hash = calc_schnorr_signature_hash(&PopulatedTransaction::new(tx, u.to_vec()), i, SIG_HASH_ALL, &reused);
        let mut sig = relay.sign_schnorr(secp256k1::Message::from_digest(hash.as_bytes())).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        let mut ss = encode_entry_sig_script(&art, "step", &[sig.into()]).unwrap();
        ss.extend(push_redeem_script(&bytecode(&art)));
        tx.inputs[i].signature_script = ss;
    };
    // Merge: two lanes in, one lane out.
    let u = vec![p.utxo(v, &st, POT_COV), p.utxo(v, &st, POT_COV)];
    let mut tx = Transaction::new(1, vec![input(7, 0), input(8, 0)], vec![p.out(2 * v - MSG_FEE, &next)], daa(I0), SubnetworkId::from_bytes(LANE), 0, vec![0xab; 1536]);
    sign_step(&mut tx, &u, 0);
    sign_step(&mut tx, &u, 1);
    reject("two lanes merged into one", run(&tx, &u));
    // Split: one lane in, two bound outputs (a thief doubling the lanes, and so the allowance).
    let u = vec![p.utxo(v, &st, POT_COV)];
    let mut tx = Transaction::new(1, vec![input(7, 0)], vec![p.out(v / 2, &next), p.out(v / 2 - MSG_FEE, &next)], daa(I0), SubnetworkId::from_bytes(LANE), 0, vec![0xab; 1536]);
    sign_step(&mut tx, &u, 0);
    reject("one lane split into two", run(&tx, &u));
    // A lane on its own still pays.
    pays(&p, &st, v, MSG_FEE, I0, &relay).expect("one lane pays as before");
}

#[test]
fn pot_rejects_every_way_out() {
    let (root, relay, other) = (keypair(9), keypair(1), keypair(2));
    let p = pot(&root);
    let st = fresh(&relay);
    let v = 20 * KAS;
    let next = Model::after_message(&st, I0, MSG_FEE);
    let base = || ok_msg(&p, &st, v, MSG_FEE, I0, &relay);
    let unbound = TransactionOutput { covenant: None, ..p.out(v - MSG_FEE, &next) };
    let two_pot_inputs = {
        let (mut tx, mut u) = message(&p, &st, v, base());
        tx.inputs.push(input(8, 0));
        u.push(p.utxo(v, &st, POT_COV));
        (tx, u)
    };
    let cases: Vec<(&str, (Transaction, Vec<UtxoEntry>))> = vec![
        ("fee 1 sompi over the cap", message(&p, &st, v, Msg { outs: vec![p.out(v - MAX_FEE - 1, &Model::after_message(&st, I0, MAX_FEE + 1))], ..base() })),
        ("send to another address", message(&p, &st, v, Msg { outs: vec![plain(v - MSG_FEE, attacker())], ..base() })),
        ("continuation without the covenant binding", message(&p, &st, v, Msg { outs: vec![unbound], ..base() })),
        ("extra output skimming 1 sompi", message(&p, &st, v, Msg { outs: vec![p.out(v - MSG_FEE - 1, &next), plain(1, attacker())], ..base() })),
        ("not on the Kaspaveil lane", message(&p, &st, v, Msg { lane: [0; 20], ..base() })),
        ("payload below 256 bytes", message(&p, &st, v, Msg { payload_len: 255, ..base() })),
        ("payload above 8 KB", message(&p, &st, v, Msg { payload_len: 8193, ..base() })),
        ("signed by a key that isn't the relay key", message(&p, &st, v, Msg { signer: &other, ..base() })),
        ("fee not counted in the interval", message(&p, &st, v, Msg { outs: vec![p.out(v - MSG_FEE, &st)], ..base() })),
        ("SMMA inflated in the continuation", message(&p, &st, v, Msg { outs: vec![p.out(v - MSG_FEE, &PotState { smma: 100 * KAS, ..next })], ..base() })),
        ("relay key swapped in the continuation", message(&p, &st, v, Msg { outs: vec![p.out(v - MSG_FEE, &PotState { relay: [5; 32], ..next })], ..base() })),
        ("interval moved backwards", message(&p, &PotState { interval: I0 + 1, ..st }, v, ok_msg(&p, &PotState { interval: I0 + 1, ..st }, v, MSG_FEE, I0, &relay))),
        ("timestamp lock time (would freeze the pot in the far future)", message(&p, &st, v, Msg { lock_time: 1_790_000_000_000, outs: vec![p.out(v - MSG_FEE, &Model::after_message(&st, 1_790_000_000_000 / INTERVAL_DAA, MSG_FEE))], ..base() })),
        ("lock time switched off (final input sequence)", message(&p, &st, v, Msg { sequence: u64::MAX, ..base() })),
        ("two pot inputs", two_pot_inputs),
    ];
    for (name, (tx, u)) in cases {
        reject(name, run(&tx, &u));
    }
}

#[test]
fn interval_roll_updates_the_smma() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let v = 50 * KAS;
    let st = PotState { interval: I0, spent: 12 * KAS, smma: 8 * KAS, ..fresh(&relay) };
    // Next interval: one SMMA step with last interval's 12 KAS, the counter restarts at this fee.
    let next = Model::after_message(&st, I0 + 1, MSG_FEE);
    assert_eq!(next.smma, (8 * KAS * (N - 1) + 12 * KAS) / N);
    assert_eq!(next.spent, MSG_FEE);
    pays(&p, &st, v, MSG_FEE, I0 + 1, &relay).expect("roll to the next interval");
    // Three intervals later: one step, then two empty intervals of linear decay.
    let later = Model::after_message(&st, I0 + 3, MSG_FEE);
    assert_eq!(later.smma, (8 * KAS * (N - 1) + 12 * KAS) / N * (N - 2) / N);
    pays(&p, &st, v, MSG_FEE, I0 + 3, &relay).expect("roll across empty intervals");
    // After a week of silence the average is zero and the floor applies.
    assert_eq!(Model::after_message(&st, I0 + 1 + N, MSG_FEE).smma, 0);
    pays(&p, &st, v, MSG_FEE, I0 + 1 + N, &relay).expect("roll after a quiet week");
    // Claiming the old counters in the new interval is refused.
    let (tx, u) = message(&p, &st, v, Msg { outs: vec![p.out(v - MSG_FEE, &PotState { interval: I0 + 1, spent: 12 * KAS + MSG_FEE, smma: 8 * KAS, ..st })], ..ok_msg(&p, &st, v, MSG_FEE, I0 + 1, &relay) });
    assert!(run(&tx, &u).is_err(), "must reset the counter and update the SMMA");
}

#[test]
fn a_real_burst_of_five_times_normal_goes_through_at_once() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let v = 100 * KAS;
    // Normal use: 10 KAS per interval. A burst to 5× = 50 KAS in one interval passes; a sompi more doesn't.
    let st = PotState { interval: I0, spent: 50 * KAS - MSG_FEE, smma: 10 * KAS, ..fresh(&relay) };
    assert_eq!(Model::allowance(st.smma), 50 * KAS);
    pays(&p, &st, v, MSG_FEE, I0, &relay).expect("burst to 5× the average");
    assert!(pays(&p, &st, v, MSG_FEE + 1, I0, &relay).is_err(), "beyond 5× waits for the next interval");
}

// A thief with the relay key spends everything the throttle allows, every interval, for two days, starting
// from a pot whose normal use is 8 KAS per interval. Every transaction runs on the engine; each interval ends
// with one more attempt that must fail. The limit grows by the model's factor only: about 1.76× a day.
#[test]
fn a_relay_key_thief_can_only_raise_the_limit_slowly() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let normal = 8 * KAS;
    let mut st = PotState { interval: I0, spent: normal, smma: normal, ..fresh(&relay) };
    let mut value = 10_000 * KAS;
    let first_cap = Model::allowance(Model::smma_at(&st, I0 + 1));
    let mut burned_day = [0u64; 2];
    for k in 1..=2 * PER_DAY {
        let cur = I0 + k;
        let cap = Model::allowance(Model::smma_at(&st, cur));
        let mut left = cap;
        while left > 0 {
            let fee = left.min(MAX_FEE);
            pays(&p, &st, value, fee, cur, &relay).unwrap_or_else(|e| panic!("interval {k}: thief's spend within the allowance: {e}"));
            st = Model::after_message(&st, cur, fee);
            value -= fee;
            left -= fee;
        }
        assert_eq!(st.spent, cap);
        assert!(pays(&p, &st, value, 1, cur, &relay).is_err(), "interval {k}: nothing beyond the allowance");
        burned_day[((k - 1) / PER_DAY) as usize] += cap;
    }
    let last_cap = Model::allowance(Model::smma_at(&st, I0 + 2 * PER_DAY + 1));
    let per_day = ((last_cap as f64) / (first_cap as f64)).sqrt();
    println!("thief: allowance {} → {} KAS over two days ({per_day:.2}× a day); burned {} KAS on day 1, {} KAS on day 2 (normal: {} KAS a day)",
        first_cap / KAS, last_cap / KAS, burned_day[0] / KAS, burned_day[1] / KAS, PER_DAY * normal / KAS);
    assert!(per_day < 1.8, "the limit must grow at most ~1.76× a day");
    assert!(burned_day[0] < 8 * PER_DAY * normal, "a day of theft costs well under 8 normal days");
}

// ---------- reservoir top-ups ----------

const SWEEP_1M: u64 = 25_920_000; // a one-month payment: credits expire when the month renews (30 days)
const SWEEP_LONG: u64 = 311_040_000; // a 2-12 month prepayment: 12 months (360 days)

fn kaspaguy() -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(xonly(&keypair(30)));
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

// Same encoding as OpTxOutputSpk: 2-byte big-endian version, then the script.
fn spk_arg(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut v = spk.version().to_be_bytes().to_vec();
    v.extend_from_slice(spk.script());
    v
}

fn reservoir_with(sweep_age: u64, sweep_to: &ScriptPublicKey) -> (silverscript_abi::SilAbiArtifact, ScriptPublicKey) {
    let args = [ArtifactValue::from(POT_COV.to_vec()), ArtifactValue::from(sweep_age as i64), ArtifactValue::from(spk_arg(sweep_to))];
    let compiled = compile_contract(RES_SRC, &args, CompileOptions::default()).expect("reservoir compiles");
    let spk = pay_to_script_hash_script(&bytecode(&compiled));
    (compiled, spk)
}

// The reservoir for one-month payments; top-ups work the same in every variant.
fn reservoir() -> (silverscript_abi::SilAbiArtifact, ScriptPublicKey) {
    reservoir_with(SWEEP_1M, &kaspaguy())
}

struct TopUp {
    pot_value: u64,
    res_value: u64,
    outs: Vec<TransactionOutput>,
    pot_cov: [u8; 32],
    lock_time: u64,
}

fn topup_tx(p: &Pot, st: &PotState, t: TopUp) -> (Transaction, Vec<UtxoEntry>) {
    let (res, res_spk) = reservoir();
    let utxos = vec![p.utxo(t.pot_value, st, t.pot_cov), UtxoEntry::new(t.res_value, res_spk, 0, false, None)];
    let mut tx = Transaction::new(1, vec![input(7, 0), input(9, 0)], t.outs, t.lock_time, SubnetworkId::from_bytes([0; 20]), 0, vec![]);
    let art = p.artifact(st);
    let mut ss = encode_entry_sig_script(&art, "step", &[vec![0u8; 65].into()]).unwrap();
    ss.extend(push_redeem_script(&bytecode(&art)));
    tx.inputs[0].signature_script = ss;
    let mut rs = encode_entry_sig_script(&res, "topUp", &[]).unwrap();
    rs.extend(push_redeem_script(&bytecode(&res)));
    tx.inputs[1].signature_script = rs;
    (tx, utxos)
}

#[test]
fn reservoir_tops_the_pot_up_to_one_interval_s_allowance() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let st = PotState { spent: 3 * KAS, ..fresh(&relay) };
    let next = Model::after_topup(&st, I0);
    let (_, res_spk) = reservoir();
    let before = 4 * KAS;
    // A 75 KAS deposit fills the pot to the 20 KAS allowance; the rest goes back to the reservoir.
    let (tx, u) = topup_tx(&p, &st, TopUp {
        pot_value: before, res_value: 75 * KAS, pot_cov: POT_COV, lock_time: daa(I0),
        outs: vec![p.out(FLOOR, &next), plain(75 * KAS - (FLOOR - before) - RES_MAX_FEE, res_spk.clone())],
    });
    run(&tx, &u).expect("fill to the allowance, change back to the reservoir");
    // A 15 KAS deposit (a free user's top-up share) fits whole.
    let (tx, u) = topup_tx(&p, &st, TopUp { pot_value: before, res_value: 15 * KAS, pot_cov: POT_COV, lock_time: daa(I0), outs: vec![p.out(before + 15 * KAS - RES_MAX_FEE, &next)] });
    run(&tx, &u).expect("a small deposit goes in whole");
    // A top-up in a new interval rolls the counters like a message does.
    let rolled = Model::after_topup(&st, I0 + 1);
    let cap = Model::allowance(rolled.smma);
    let (tx, u) = topup_tx(&p, &st, TopUp { pot_value: before, res_value: 75 * KAS, pot_cov: POT_COV, lock_time: daa(I0 + 1), outs: vec![p.out(cap, &rolled), plain(75 * KAS - (cap - before) - RES_MAX_FEE, res_spk.clone())] });
    run(&tx, &u).expect("top-up in a new interval");
}

#[test]
fn top_ups_reject_every_way_out() {
    let (root, relay) = (keypair(9), keypair(1));
    let p = pot(&root);
    let st = fresh(&relay);
    let next = Model::after_topup(&st, I0);
    let (_, res_spk) = reservoir();
    let r = 75 * KAS;
    let t = |pot_value: u64, outs: Vec<TransactionOutput>| TopUp { pot_value, res_value: r, outs, pot_cov: POT_COV, lock_time: daa(I0) };
    let cases: Vec<(&str, TopUp)> = vec![
        ("pot more than half full", t(FLOOR / 2 + 1, vec![p.out(FLOOR, &next), plain(r - (FLOOR / 2 - 1) - RES_MAX_FEE, res_spk.clone())])),
        ("pot above one interval's allowance", t(4 * KAS, vec![p.out(FLOOR + 1, &next), plain(r - (FLOOR + 1 - 4 * KAS) - RES_MAX_FEE, res_spk.clone())])),
        ("partial fill with change (dribbling)", t(4 * KAS, vec![p.out(5 * KAS, &next), plain(r - KAS - RES_MAX_FEE, res_spk.clone())])),
        ("whole deposit adding under 1 KAS", TopUp { res_value: MIN_TOPUP, ..t(4 * KAS, vec![p.out(4 * KAS + MIN_TOPUP - RES_MAX_FEE, &next)]) }),
        ("reservoir change to another address", t(4 * KAS, vec![p.out(FLOOR, &next), plain(r - (FLOOR - 4 * KAS) - RES_MAX_FEE, attacker())])),
        ("top-up fee over the reservoir's cap", t(4 * KAS, vec![p.out(FLOOR, &next), plain(r - (FLOOR - 4 * KAS) - RES_MAX_FEE - 1, res_spk.clone())])),
        ("taking from the pot", t(4 * KAS, vec![p.out(3 * KAS, &next), plain(r + KAS - RES_MAX_FEE, res_spk.clone())])),
        ("reservoir into a copy of the pot (same code, another covenant ID)", TopUp { pot_cov: OTHER_COV, ..t(4 * KAS, vec![p.out_cov(FLOOR, &next, OTHER_COV), plain(r - (FLOOR - 4 * KAS) - RES_MAX_FEE, res_spk.clone())]) }),
        ("pot counters changed in a top-up", t(4 * KAS, vec![p.out(FLOOR, &PotState { spent: 0, smma: 50 * KAS, ..next }), plain(r - (FLOOR - 4 * KAS) - RES_MAX_FEE, res_spk.clone())])),
    ];
    for (name, top) in cases {
        let (tx, u) = topup_tx(&p, &st, top);
        reject(name, run(&tx, &u));
    }
    // The reservoir on its own can't move anywhere.
    let (res, res_spk2) = reservoir();
    let utxo = UtxoEntry::new(r, res_spk2, 0, false, None);
    let mut tx = Transaction::new(1, vec![input(9, 0)], vec![plain(r - RES_MAX_FEE, attacker())], 0, SubnetworkId::from_bytes([0; 20]), 0, vec![]);
    let mut rs = encode_entry_sig_script(&res, "topUp", &[]).unwrap();
    rs.extend(push_redeem_script(&bytecode(&res)));
    tx.inputs[0].signature_script = rs;
    assert!(run(&tx, &[utxo]).is_err(), "must reject: reservoir spent alone");
}

// ---------- unused funds: swept whole to Kaspaguy once outlived (SC-0015) ----------

// One reservoir UTXO of `value`, spent by sweep() with input sequence `age` (the relative DAA lock consensus enforces).
fn sweep_tx(res: &(silverscript_abi::SilAbiArtifact, ScriptPublicKey), value: u64, age: u64, inputs: usize, outs: Vec<TransactionOutput>) -> (Transaction, Vec<UtxoEntry>) {
    let ins: Vec<TransactionInput> = (0..inputs).map(|i| input(20 + i as u8, age)).collect();
    let utxos = vec![UtxoEntry::new(value, res.1.clone(), 0, false, None); inputs];
    let mut tx = Transaction::new(1, ins, outs, 0, SubnetworkId::from_bytes([0; 20]), 0, vec![]);
    let mut rs = encode_entry_sig_script(&res.0, "sweep", &[]).unwrap();
    rs.extend(push_redeem_script(&bytecode(&res.0)));
    for i in 0..inputs {
        tx.inputs[i].signature_script = rs.clone();
    }
    (tx, utxos)
}

#[test]
fn unused_funds_sweep_to_kaspaguy_once_their_window_has_passed() {
    let v = 75 * KAS;
    for (name, age) in [("one-month reservoir", SWEEP_1M), ("prepayment reservoir", SWEEP_LONG)] {
        let res = reservoir_with(age, &kaspaguy());
        let (tx, u) = sweep_tx(&res, v, age, 1, vec![plain(v - RES_MAX_FEE, kaspaguy())]);
        run(&tx, &u).unwrap_or_else(|e| panic!("{name}: sweep at its age must pass: {e}"));
        let (tx, u) = sweep_tx(&res, v, age + 1_000_000, 1, vec![plain(v - 1_000, kaspaguy())]);
        run(&tx, &u).unwrap_or_else(|e| panic!("{name}: sweep after its age must pass: {e}"));
        let (tx, u) = sweep_tx(&res, v, age - 1, 1, vec![plain(v - RES_MAX_FEE, kaspaguy())]);
        reject(&format!("{name}: one DAA too early"), run(&tx, &u));
    }
}

#[test]
fn sweeps_reject_every_way_out() {
    let v = 75 * KAS;
    let res = reservoir();
    let cases: Vec<(&str, Vec<TransactionOutput>, usize)> = vec![
        ("swept to another address", vec![plain(v - RES_MAX_FEE, attacker())], 1),
        ("fee over the cap", vec![plain(v - RES_MAX_FEE - 1, kaspaguy())], 1),
        ("part to Kaspaguy, part elsewhere", vec![plain(v / 2, kaspaguy()), plain(v / 2 - RES_MAX_FEE, attacker())], 1),
        ("two deposits into one output (each must pay its own whole value)", vec![plain(v - RES_MAX_FEE, kaspaguy())], 2),
    ];
    for (name, outs, inputs) in cases {
        let (tx, u) = sweep_tx(&res, v, SWEEP_1M, inputs, outs);
        reject(name, run(&tx, &u));
    }
    // A reservoir built with sweep age 0 (top-up money) never sweeps, however old.
    let never = reservoir_with(0, &kaspaguy());
    let (tx, u) = sweep_tx(&never, v, SWEEP_LONG * 10, 1, vec![plain(v - RES_MAX_FEE, kaspaguy())]);
    reject("sweep from a never-sweep reservoir", run(&tx, &u));
    // The sweep address is fixed at compile time: a reservoir compiled for Kaspaguy pays only Kaspaguy.
    let (tx, u) = sweep_tx(&reservoir_with(SWEEP_1M, &attacker()), v, SWEEP_1M, 1, vec![plain(v - RES_MAX_FEE, kaspaguy())]);
    reject("output to Kaspaguy from a reservoir compiled for another address", run(&tx, &u));
}

// ---------- relay-key replacement (root key) ----------

fn replace_digest(cov: [u8; 32], new_relay: &[u8], nonce: u64) -> [u8; 32] {
    let mut m = b"kasveil/v1/relay-replace".to_vec();
    m.extend(cov);
    m.extend(new_relay);
    m.extend(nonce.to_le_bytes());
    blake2b_simd::Params::new().hash_length(32).hash(&m).as_bytes().try_into().unwrap()
}

fn replace_tx(p: &Pot, st: &PotState, value: u64, new_relay: &[u8], sig: Vec<u8>, out: TransactionOutput) -> (Transaction, Vec<UtxoEntry>) {
    let utxos = vec![p.utxo(value, st, POT_COV)];
    let mut tx = Transaction::new(1, vec![input(7, 0)], vec![out], 0, SubnetworkId::from_bytes([0; 20]), 0, vec![]);
    let art = p.artifact(st);
    let mut ss = encode_entry_sig_script(&art, "replaceRelay", &[ArtifactValue::from(new_relay.to_vec()), sig.into()]).unwrap();
    ss.extend(push_redeem_script(&bytecode(&art)));
    tx.inputs[0].signature_script = ss;
    (tx, utxos)
}

#[test]
fn the_root_key_replaces_a_stolen_relay_key() {
    let (root, stolen, fresh_key, not_root) = (keypair(9), keypair(1), keypair(3), keypair(10));
    let p = pot(&root);
    let st = PotState { spent: 5 * KAS, smma: 6 * KAS, ..fresh(&stolen) };
    let v = 20 * KAS;
    let nk = xonly(&fresh_key);
    let sign = |kp: &secp256k1::Keypair, cov: [u8; 32], nonce: u64| kp.sign_schnorr(secp256k1::Message::from_digest(replace_digest(cov, &nk, nonce))).as_ref().to_vec();
    let replaced = PotState { relay: nk.clone().try_into().unwrap(), nonce: 1, ..st };
    let (tx, u) = replace_tx(&p, &st, v, &nk, sign(&root, POT_COV, 0), p.out(v - ADMIN_FEE, &replaced));
    run(&tx, &u).expect("root replaces the relay key");
    // From then on the stolen key is refused and the new one pays.
    assert!(pays(&p, &replaced, v, MSG_FEE, I0, &stolen).is_err(), "the replaced key can't pay any more");
    pays(&p, &replaced, v, MSG_FEE, I0, &fresh_key).expect("the new relay key pays");
    let cases = vec![
        ("replaying the used signature", replace_tx(&p, &replaced, v, &nk, sign(&root, POT_COV, 0), p.out(v - ADMIN_FEE, &PotState { nonce: 2, ..replaced }))),
        ("signed by a key that isn't the root", replace_tx(&p, &st, v, &nk, sign(&not_root, POT_COV, 0), p.out(v - ADMIN_FEE, &replaced))),
        ("signature for another pot", replace_tx(&p, &st, v, &nk, sign(&root, OTHER_COV, 0), p.out(v - ADMIN_FEE, &replaced))),
        ("taking more than 0.01 KAS", replace_tx(&p, &st, v, &nk, sign(&root, POT_COV, 0), p.out(v - ADMIN_FEE - 1, &replaced))),
        ("also resetting the throttle", replace_tx(&p, &st, v, &nk, sign(&root, POT_COV, 0), p.out(v - ADMIN_FEE, &PotState { spent: 0, ..replaced }))),
        ("paying out elsewhere", replace_tx(&p, &st, v, &nk, sign(&root, POT_COV, 0), plain(v - ADMIN_FEE, attacker()))),
    ];
    for (name, (tx, u)) in cases {
        reject(name, run(&tx, &u));
    }
}
