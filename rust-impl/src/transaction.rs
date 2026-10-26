//! WIRE_FORMAT §5: the Kaspa transaction carrying a payload.
//!
//! The Kaspaveil rules (version, lane, gas, payload, relay shape) come from the spec. The
//! transaction ID, estimated serialized size and masses follow Kaspa consensus, which the spec
//! cites normatively (rusty-kaspa v2.1.0, commit 01b532e8…): `consensus/core/src/hashing/tx.rs`,
//! `consensus/core/src/mass/mod.rs`, `mining/src/mempool/check_transaction_standard.rs`.
//! They are re-implemented here from those files (see NOTES.md).

use crate::PAYLOAD_LEN;

pub const TX_VERSION_TOCCATA: u16 = 1;
pub const KASPAVEIL_LANE: [u8; 20] = [0x4b, 0x56, 0x4c, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const SOMPI_PER_KAS: u64 = 100_000_000;
pub const MAX_RELAY_FEE: u64 = SOMPI_PER_KAS;
pub const EPOCH_DAA: u64 = 25_920_000;
/// Kaspa: lock times at or above this are timestamps, not DAA scores.
pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

const MASS_PER_TX_BYTE: u64 = 1;
const MASS_PER_SPK_BYTE: u64 = 10;
const GRAMS_PER_COMPUTE_BUDGET_UNIT: u64 = 100;
const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;
const STORAGE_MASS_PARAMETER: u64 = SOMPI_PER_KAS * 10_000;
/// Mempool minimum relay fee, sompi per 1,000 grams.
const MIN_RELAY_FEE_PER_KG: u64 = 100_000;

#[derive(Clone, Debug)]
pub struct Input {
    pub previous_txid: [u8; 32],
    pub previous_index: u32,
    pub sequence: u64,
    pub compute_budget: u16,
    pub signature_script: Vec<u8>,
    pub utxo_amount: u64,
    pub utxo_script_public_key: Vec<u8>,
    pub utxo_script_version: u16,
    pub utxo_daa_score: u64,
    /// The spent UTXO's covenant ID, if it has one (the treasury spending pot does).
    pub utxo_covenant_id: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct Output {
    pub value: u64,
    pub script_public_key: Vec<u8>,
    pub script_version: u16,
    /// Covenant binding: (authorizing input, covenant ID).
    pub covenant: Option<(u16, [u8; 32])>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: u16,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: Vec<u8>,
}

fn keyed_blake3(domain: &[u8]) -> blake3::Hasher {
    let mut key = [0u8; 32];
    key[..domain.len()].copy_from_slice(domain);
    blake3::Hasher::new_keyed(&key)
}

fn var_bytes(v: &mut Vec<u8>, b: &[u8]) {
    v.extend_from_slice(&(b.len() as u64).to_le_bytes());
    v.extend_from_slice(b);
}

impl Transaction {
    /// A Kaspaveil message transaction (fields common to both sending modes).
    pub fn kaspaveil(inputs: Vec<Input>, outputs: Vec<Output>, lock_time: u64, payload: Vec<u8>) -> Self {
        Transaction { version: TX_VERSION_TOCCATA, inputs, outputs, lock_time, subnetwork_id: KASPAVEIL_LANE, gas: 0, payload }
    }

    /// What an indexer checks: version, lane and payload length.
    pub fn is_kaspaveil(&self) -> bool {
        self.version == TX_VERSION_TOCCATA && self.subnetwork_id == KASPAVEIL_LANE && self.payload.len() == PAYLOAD_LEN
    }

    pub fn fee(&self) -> Option<u64> {
        let ins: u64 = self.inputs.iter().map(|i| i.utxo_amount).sum();
        let outs: u64 = self.outputs.iter().map(|o| o.value).sum();
        ins.checked_sub(outs)
    }

    /// Relay-paid shape of the retired certificate-based hot wallet (kept for the vectors that
    /// carry it, SC-0012): one input, one output back to the same script with no covenant
    /// binding, fee ≤ 1 KAS, lock_time in [epoch start, current DAA score], gas 0.
    pub fn check_relay_paid(&self, cert_epoch: u64, current_daa: u64) -> bool {
        self.is_kaspaveil()
            && self.gas == 0
            && self.inputs.len() == 1
            && self.outputs.len() == 1
            && self.outputs[0].script_public_key == self.inputs[0].utxo_script_public_key
            && self.outputs[0].script_version == self.inputs[0].utxo_script_version
            && self.fee().is_some_and(|f| f <= MAX_RELAY_FEE)
            && self.lock_time >= cert_epoch * EPOCH_DAA
            && self.lock_time <= current_daa
    }

    /// Relay-paid shape (§5, SC-0012): one input, the treasury spending pot (it has a covenant
    /// ID); one output bound to that same covenant ID by input 0 (the pot with its new state, so
    /// its script differs from the input's); fee ≤ 1 KAS; a DAA-score lock time ≤ the current DAA
    /// score that consensus enforces (input sequence not final); gas 0. The pot's own rules (relay
    /// signature, throttle, state) are checked by its script, not here.
    pub fn check_pot_paid(&self, current_daa: u64) -> bool {
        self.is_kaspaveil()
            && self.gas == 0
            && self.inputs.len() == 1
            && self.outputs.len() == 1
            && self.inputs[0].utxo_covenant_id.is_some()
            && self.outputs[0].covenant == self.inputs[0].utxo_covenant_id.map(|id| (0, id))
            && self.fee().is_some_and(|f| f <= MAX_RELAY_FEE)
            && self.lock_time < LOCK_TIME_THRESHOLD
            && self.lock_time <= current_daa
            && self.inputs[0].sequence != u64::MAX
    }

    /// v1 `rest` preimage: payload, signature scripts and mass commitment excluded; each output
    /// ends with a covenant flag byte (0: none; 1: then authorizing input u16 LE and the ID).
    fn rest_preimage(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&(self.inputs.len() as u64).to_le_bytes());
        for i in &self.inputs {
            v.extend_from_slice(&i.previous_txid);
            v.extend_from_slice(&i.previous_index.to_le_bytes());
            var_bytes(&mut v, &[]);
            v.extend_from_slice(&i.sequence.to_le_bytes());
        }
        v.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        for o in &self.outputs {
            v.extend_from_slice(&o.value.to_le_bytes());
            v.extend_from_slice(&o.script_version.to_le_bytes());
            var_bytes(&mut v, &o.script_public_key);
            match o.covenant {
                None => v.push(0),
                Some((auth, id)) => {
                    v.push(1);
                    v.extend_from_slice(&auth.to_le_bytes());
                    v.extend_from_slice(&id);
                }
            }
        }
        v.extend_from_slice(&self.lock_time.to_le_bytes());
        v.extend_from_slice(&self.subnetwork_id);
        v.extend_from_slice(&self.gas.to_le_bytes());
        var_bytes(&mut v, &[]);
        v
    }

    pub fn id(&self) -> [u8; 32] {
        assert!(self.version >= 1, "only v1 transactions are built here");
        let payload_digest = {
            let mut h = keyed_blake3(b"PayloadDigest");
            h.update(&self.payload);
            *h.finalize().as_bytes()
        };
        let rest_digest = {
            let mut h = keyed_blake3(b"TransactionRest");
            h.update(&self.rest_preimage());
            *h.finalize().as_bytes()
        };
        let mut h = keyed_blake3(b"TransactionV1Id");
        h.update(&payload_digest);
        h.update(&rest_digest);
        *h.finalize().as_bytes()
    }

    pub fn estimated_serialized_size(&self) -> u64 {
        let mut size = 2 + 8;
        for i in &self.inputs {
            size += 32 + 4 + 8 + i.signature_script.len() as u64 + 8 + if self.version >= 1 { 2 } else { 0 };
        }
        size += 8;
        for o in &self.outputs {
            size += 8 + 2 + 8 + o.script_public_key.len() as u64 + if o.covenant.is_some() { 2 + 32 } else { 0 };
        }
        size + 8 + 20 + 8 + 32 + 8 + self.payload.len() as u64
    }

    pub fn compute_mass(&self) -> u64 {
        let size = self.estimated_serialized_size();
        let spk: u64 = self.outputs.iter().map(|o| 2 + o.script_public_key.len() as u64).sum();
        let budget: u64 = self.inputs.iter().map(|i| i.compute_budget as u64).sum();
        size * MASS_PER_TX_BYTE + spk * MASS_PER_SPK_BYTE + budget * GRAMS_PER_COMPUTE_BUDGET_UNIT
    }

    pub fn transient_mass(&self) -> u64 {
        self.estimated_serialized_size() * TRANSIENT_BYTE_TO_MASS_FACTOR
    }

    /// KIP-9 storage mass; a covenant ID adds 32 bytes to a UTXO's storage size.
    pub fn storage_mass(&self) -> u64 {
        let plurality = |spk_len: usize, cov: bool| (63 + spk_len + if cov { 32 } else { 0 }).div_ceil(100) as u64;
        let outs: Vec<(u64, u64)> = self.outputs.iter().map(|o| (plurality(o.script_public_key.len(), o.covenant.is_some()), o.value)).collect();
        let ins: Vec<(u64, u64)> =
            self.inputs.iter().map(|i| (plurality(i.utxo_script_public_key.len(), i.utxo_covenant_id.is_some()), i.utxo_amount)).collect();
        let c = STORAGE_MASS_PARAMETER;
        let outs_plurality: u64 = outs.iter().map(|o| o.0).sum();
        let harmonic_outs: u64 = outs.iter().map(|(p, a)| c * p * p / a).sum();
        let ins_plurality: u64 = ins.iter().map(|i| i.0).sum();
        let relaxed = outs_plurality == 1 || (ins.len() <= 2 && (ins_plurality == 1 || (outs_plurality == 2 && ins_plurality == 2)));
        if relaxed {
            let harmonic_ins = ins.iter().map(|(p, a)| c * p * p / a).fold(0u64, |t, x| t.saturating_add(x));
            return harmonic_outs.saturating_sub(harmonic_ins);
        }
        let sum_ins: u64 = ins.iter().map(|i| i.1).sum();
        let mean_ins = (sum_ins / ins_plurality).max(1);
        harmonic_outs.saturating_sub(ins_plurality.saturating_mul(c / mean_ins))
    }

    /// Minimum relay fee: 100 sompi × max(compute mass, ⌈transient mass × 0.5⌉); storage mass
    /// doesn't enter it.
    pub fn min_fee(&self) -> u64 {
        let normalized_transient = self.transient_mass().div_ceil(2);
        let mass = self.compute_mass().max(normalized_transient);
        let fee = mass.saturating_mul(MIN_RELAY_FEE_PER_KG) / 1000;
        if fee == 0 {
            MIN_RELAY_FEE_PER_KG
        } else {
            fee
        }
    }
}
