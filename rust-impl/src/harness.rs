//! Test-vector harness support (the vector file's `format` block): session-state JSON and
//! injected named randomness. Not wire format.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::primitives::{to32, Key32};
use crate::random::RandomSource;
use crate::session::{IncomingChain, PqOffer, PqSecret, Session, SkippedKey};

pub fn hex_of(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap_or_else(|| panic!("expected hex string, got {v}"))).expect("valid hex")
}

pub fn key_of(v: &Value) -> Key32 {
    let b = hex_of(v);
    assert_eq!(b.len(), 32, "expected 32 bytes");
    to32(&b)
}

fn opt_key(v: &Value) -> Option<Key32> {
    if v.is_null() {
        None
    } else {
        Some(key_of(v))
    }
}

fn u32_of(v: &Value) -> u32 {
    v.as_u64().expect("number") as u32
}

fn u32_list(v: &Value) -> Vec<u32> {
    v.as_array().expect("array").iter().map(u32_of).collect()
}

fn h(b: &[u8]) -> Value {
    Value::String(hex::encode(b))
}

fn opt_h(b: &Option<Key32>) -> Value {
    b.as_ref().map(|k| h(k)).unwrap_or(Value::Null)
}

pub fn session_from_json(v: &Value) -> Session {
    let pq_offer = if v["pq_offer"].is_null() {
        None
    } else {
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&hex_of(&v["pq_offer"]["mlkem_keygen_seed"]));
        Some(PqOffer { epoch: u32_of(&v["pq_offer"]["epoch"]), mlkem_keygen_seed: seed })
    };
    let pq_secret = if v["pq_secret"].is_null() {
        None
    } else {
        let s = &v["pq_secret"];
        Some(PqSecret { epoch: u32_of(&s["epoch"]), shared_secret: key_of(&s["shared_secret"]), mix_on_send: s["mix_on_send"].as_bool().unwrap() })
    };
    let previous_in = if v["previous_in"].is_null() {
        None
    } else {
        let p = &v["previous_in"];
        Some(IncomingChain { tag_key_in: key_of(&p["tag_key_in"]), tag_in: u32_of(&p["tag_in"]), seen_in: u32_list(&p["seen_in"]) })
    };
    Session {
        ad: hex_of(&v["ad"]),
        initiator: v["initiator"].as_bool().unwrap(),
        root_key: key_of(&v["root_key"]),
        our_ratchet_sk: key_of(&v["our_ratchet_sk"]),
        our_ratchet_pub: key_of(&v["our_ratchet_pub"]),
        their_ratchet_pub: key_of(&v["their_ratchet_pub"]),
        sending_chain_key: opt_key(&v["sending_chain_key"]),
        receiving_chain_key: opt_key(&v["receiving_chain_key"]),
        ns: u32_of(&v["ns"]),
        nr: u32_of(&v["nr"]),
        pn: u32_of(&v["pn"]),
        tag_key_out: key_of(&v["tag_key_out"]),
        tag_key_in: key_of(&v["tag_key_in"]),
        tag_out: u32_of(&v["tag_out"]),
        tag_in: u32_of(&v["tag_in"]),
        seen_in: u32_list(&v["seen_in"]),
        skipped: v["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| SkippedKey {
                their_ratchet_pub: key_of(&s["their_ratchet_pub"]),
                n: u32_of(&s["n"]),
                message_key: key_of(&s["message_key"]),
                stored_at: 0,
            })
            .collect(),
        pq_epoch: u32_of(&v["pq_epoch"]),
        pq_offer,
        pq_secret,
        tag_key_in_next: opt_key(&v["tag_key_in_next"]),
        previous_in,
        kem_messages: 0,
        kem_since: 0,
        receive_only: false,
    }
}

pub fn session_to_json(s: &Session) -> Value {
    json!({
        "ad": h(&s.ad),
        "initiator": s.initiator,
        "root_key": h(&s.root_key),
        "our_ratchet_sk": h(&s.our_ratchet_sk),
        "our_ratchet_pub": h(&s.our_ratchet_pub),
        "their_ratchet_pub": h(&s.their_ratchet_pub),
        "sending_chain_key": opt_h(&s.sending_chain_key),
        "receiving_chain_key": opt_h(&s.receiving_chain_key),
        "ns": s.ns, "nr": s.nr, "pn": s.pn,
        "tag_key_out": h(&s.tag_key_out),
        "tag_key_in": h(&s.tag_key_in),
        "tag_out": s.tag_out,
        "tag_in": s.tag_in,
        "seen_in": s.seen_in,
        "skipped": s.skipped.iter().map(|k| json!({"their_ratchet_pub": h(&k.their_ratchet_pub), "n": k.n, "message_key": h(&k.message_key)})).collect::<Vec<_>>(),
        "pq_epoch": s.pq_epoch,
        "pq_offer": s.pq_offer.as_ref().map(|o| json!({"epoch": o.epoch, "mlkem_keygen_seed": h(&o.mlkem_keygen_seed)})).unwrap_or(Value::Null),
        "pq_secret": s.pq_secret.as_ref().map(|p| json!({"epoch": p.epoch, "shared_secret": h(&p.shared_secret), "mix_on_send": p.mix_on_send})).unwrap_or(Value::Null),
        "tag_key_in_next": opt_h(&s.tag_key_in_next),
        "previous_in": s.previous_in.as_ref().map(|p| json!({"tag_key_in": h(&p.tag_key_in), "tag_in": p.tag_in, "seen_in": p.seen_in})).unwrap_or(Value::Null),
    })
}

/// Named random values from a step's `rand` object. Asking for a value the step didn't give
/// panics; [`Injected::unused`] lists values the step gave but the code never consumed.
pub struct Injected {
    values: BTreeMap<String, Vec<u8>>,
    used: Vec<String>,
}

impl Injected {
    pub fn new(rand: &Value) -> Self {
        let values = rand.as_object().unwrap_or(&Map::new()).iter().map(|(k, v)| (k.clone(), hex_of(v))).collect();
        Injected { values, used: vec![] }
    }

    pub fn empty() -> Self {
        Injected { values: BTreeMap::new(), used: vec![] }
    }

    fn take(&mut self, name: &str) -> Vec<u8> {
        let v = self.values.get(name).unwrap_or_else(|| panic!("the vector did not provide random value `{name}`")).clone();
        assert!(!self.used.iter().any(|u| u == name), "random value `{name}` consumed twice");
        self.used.push(name.to_string());
        v
    }

    pub fn unused(&self) -> Vec<String> {
        self.values.keys().filter(|k| !self.used.contains(k)).cloned().collect()
    }

    pub fn consumed(&self) -> &[String] {
        &self.used
    }
}

impl RandomSource for Injected {
    fn ratchet_x25519_sk(&mut self) -> Key32 {
        to32(&self.take("ratchet_x25519_sk"))
    }
    fn random_field(&mut self) -> Key32 {
        to32(&self.take("random_field"))
    }
    fn mlkem_encaps_m(&mut self) -> Key32 {
        to32(&self.take("mlkem_encaps_m"))
    }
    fn mlkem_keygen_seed(&mut self) -> [u8; 64] {
        let mut s = [0u8; 64];
        s.copy_from_slice(&self.take("mlkem_keygen_seed"));
        s
    }
    fn ephemeral_x25519_sk(&mut self) -> Key32 {
        to32(&self.take("ephemeral_x25519_sk"))
    }
    fn schnorr_aux(&mut self) -> Key32 {
        to32(&self.take("schnorr_aux"))
    }
}
