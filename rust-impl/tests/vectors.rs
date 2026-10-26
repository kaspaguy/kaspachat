//! Runs every vector of `../protocol/vectors/v1.json` and asserts byte-exact equality.
//! One test per vector id; `every_vector_has_a_test` checks the list against the file.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use kaspaveil_wire::buckets::{cover_first_contact, default_name, inbox_bucket, message_bucket, registry_bucket, with_bucket};
use kaspaveil_wire::bundle::{bundle_tag, parse_publication, publication_payload, Bundle};
use kaspaveil_wire::first_contact::{self, crossing_keeps_sent, keeps_current, open_first_contact, receive_first_contact, SeenFirstContacts, Recipient, RegistryEntry, Sender};
use kaspaveil_wire::groups::{GroupReceiver, GroupState, GroupText, Member, StateEvent, TextOutcome};
use kaspaveil_wire::harness::{hex_of, key_of, session_from_json, session_to_json, Injected};
use kaspaveil_wire::keys::{identity_from_mnemonic, prekey, Prekey};
use kaspaveil_wire::primitives::{x25519_pub, Key32};
use kaspaveil_wire::random::RandomSource;
use kaspaveil_wire::session::{seed64, Session};
use kaspaveil_wire::settings::{self, Prefs};
use kaspaveil_wire::transaction::{Input, Output, Transaction};
use serde_json::Value;

const VECTOR_IDS: &[&str] = &[
    "keys-alice",
    "keys-bob",
    "keys-prekey-bob-1",
    "keys-prekey-bob-2",
    "bundle-bob-1",
    "bundle-reject-tampered",
    "bundle-reject-wrong-owner",
    "bundle-accept",
    "bundle-payload",
    "buckets-message",
    "buckets-registry",
    "buckets-inbox",
    "buckets-with-bucket",
    "first-contact-alice-to-bob",
    "first-contact-bob-opens",
    "first-contact-reject-not-for-me",
    "first-contact-reject-registry-mismatch",
    "ratchet-conversation",
    "kem-step-full",
    "group-state-encode",
    "group-state-over-session",
    "group-text-encode",
    "group-text-over-session",
    "group-receive-rules",
    "ratchet-out-of-order",
    "ratchet-reject-tampered",
    "kem-step-crossing-offers",
    "ratchet-skipped-key-state",
    "kem-step-offer-pending",
    "kem-step-malformed-offer",
    "ratchet-receiver-edge-cases",
    "ratchet-reject-low-order-ratchet-key",
    "first-contact-reject-low-order",
    "group-state-duplicate-identity-key",
    "cover-first-contact",
    "first-contact-crossing",
    "registry-default-names",
    "settings-encode",
    "settings-reject",
    "settings-effective",
    "ratchet-late-from-older-ratchet-key",
    "kem-step-responder-keeps-offer-on-malformed",
    "bundle-reject-bad-mlkem-key",
    "first-contact-recontact",
    "first-contact-replay",
    "settings-encode-v2",
    "settings-encode-group",
    "settings-reject-v2",
    "transaction-relay-paid-pot",
];

fn file() -> &'static Value {
    static F: OnceLock<Value> = OnceLock::new();
    F.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../protocol/vectors/v1.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("read ../protocol/vectors/v1.json")).expect("valid JSON")
    })
}

fn vector(id: &str) -> &'static Value {
    file()["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap_or_else(|| panic!("vector {id} not in file"))
}

/// Byte comparison that prints expected and actual side by side (16 bytes per row, rows that
/// differ marked), so a failure shows exactly where the bytes diverge.
fn assert_bytes(label: &str, expected: &[u8], actual: &[u8]) {
    if expected == actual {
        return;
    }
    let mut msg = format!("\n{label}: MISMATCH (expected {} bytes, actual {} bytes)\n", expected.len(), actual.len());
    let first = expected.iter().zip(actual).position(|(a, b)| a != b).unwrap_or(expected.len().min(actual.len()));
    msg += &format!("first difference at byte offset {first}\n");
    msg += &format!("{:>6}  {:<32}  {:<32}\n", "offset", "expected", "actual");
    let rows = expected.len().max(actual.len()).div_ceil(16);
    let mut shown = 0;
    for r in 0..rows {
        let e = expected.get(r * 16..((r + 1) * 16).min(expected.len())).unwrap_or(&[]);
        let a = actual.get(r * 16..((r + 1) * 16).min(actual.len())).unwrap_or(&[]);
        if e != a || (r * 16 + 16 > first && r * 16 <= first + 32) {
            msg += &format!("{:>6}  {:<32}  {:<32}{}\n", r * 16, hex::encode(e), hex::encode(a), if e != a { "  <-" } else { "" });
            shown += 1;
            if shown > 40 {
                msg += "... (truncated)\n";
                break;
            }
        }
    }
    panic!("{msg}");
}

fn assert_hex(label: &str, expected: &Value, actual: &[u8]) {
    assert_bytes(label, &hex_of(expected), actual);
}

fn assert_eq_val(label: &str, expected: &Value, actual: &Value) {
    if expected != actual {
        panic!("\n{label}: MISMATCH\n  expected: {expected}\n  actual:   {actual}\n");
    }
}

/// Field-by-field session comparison (hex fields shown side by side).
fn assert_session(label: &str, expected: &Value, actual: &Session) {
    let a = session_to_json(actual);
    let exp = expected.as_object().unwrap();
    let act = a.as_object().unwrap();
    let mut diffs = String::new();
    for k in exp.keys().chain(act.keys().filter(|k| !exp.contains_key(*k))) {
        let (e, x) = (exp.get(k).unwrap_or(&Value::Null), act.get(k).unwrap_or(&Value::Null));
        if e != x {
            diffs += &format!("  {k}:\n    expected: {e}\n    actual:   {x}\n");
        }
    }
    if !diffs.is_empty() {
        panic!("\n{label}: session state MISMATCH\n{diffs}");
    }
}

fn check_all_consumed(label: &str, rng: &Injected) {
    let unused = rng.unused();
    assert!(unused.is_empty(), "{label}: random values given but never consumed: {unused:?}");
}

// -------------------------------------------------------------------------------- keys

fn keys_vector(id: &str) {
    let v = vector(id);
    assert_eq!(v["input"]["passphrase"], "", "the passphrase is always empty");
    let ident = identity_from_mnemonic(v["input"]["mnemonic"].as_str().unwrap()).expect("valid phrase");
    let e = &v["expected"];
    assert_hex("seed", &e["seed"], &ident.seed);
    assert_hex("owner_sk", &e["owner_sk"], &ident.owner_sk);
    assert_hex("owner_pub", &e["owner_pub"], &ident.owner_pub);
    assert_hex("id_x25519_sk", &e["id_x25519_sk"], &ident.id_x25519_sk);
    assert_hex("id_x25519_pub", &e["id_x25519_pub"], &ident.id_x25519_pub);
}

#[test]
fn keys_alice() {
    keys_vector("keys-alice");
}

#[test]
fn keys_bob() {
    keys_vector("keys-bob");
}

fn prekey_vector(id: &str) {
    let v = vector(id);
    let seed = hex_of(&v["input"]["seed"]);
    let pk = prekey(&seed, v["input"]["spk_id"].as_u64().unwrap() as u32);
    let e = &v["expected"];
    assert_hex("spk_x25519_sk", &e["spk_x25519_sk"], &pk.x25519_sk);
    assert_hex("spk_x25519_pub", &e["spk_x25519_pub"], &pk.x25519_pub);
    assert_hex("mlkem_keygen_seed", &e["mlkem_keygen_seed"], &pk.mlkem_seed);
    assert_hex("spk_mlkem_pub", &e["spk_mlkem_pub"], &pk.mlkem_pub);
    assert_hex("spk_mlkem_sk", &e["spk_mlkem_sk"], &pk.mlkem_sk);
}

#[test]
fn keys_prekey_bob_1() {
    prekey_vector("keys-prekey-bob-1");
}

#[test]
fn keys_prekey_bob_2() {
    prekey_vector("keys-prekey-bob-2");
}

#[test]
fn mnemonic_rejects_wrong_length_and_checksum() {
    let v = vector("keys-alice");
    let phrase = v["input"]["mnemonic"].as_str().unwrap();
    let words: Vec<&str> = phrase.split(' ').collect();
    assert!(identity_from_mnemonic(&words[..12].join(" ")).is_err());
    let mut bad = words.clone();
    bad[23] = if bad[23] == "zoo" { "wrong" } else { "zoo" };
    assert!(identity_from_mnemonic(&bad.join(" ")).is_err());
    // A valid 12-word phrase (BIP-39 test vector) is refused too: exactly 24 words.
    assert!(identity_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_err());
}

// -------------------------------------------------------------------------------- bundles

#[test]
fn bundle_bob_1() {
    let v = vector("bundle-bob-1");
    let i = &v["input"];
    assert!(i["devices"].as_array().unwrap().is_empty());
    let b = Bundle::create(
        &key_of(&i["owner_sk"]),
        key_of(&i["owner_pub"]),
        key_of(&i["id_x25519_pub"]),
        i["spk_id"].as_u64().unwrap() as u32,
        key_of(&i["spk_x25519_pub"]),
        hex_of(&i["spk_mlkem_pub"]),
        i["created"].as_u64().unwrap(),
        vec![],
        &key_of(&i["rand"]["schnorr_aux"]),
    )
    .unwrap();
    let e = &v["expected"];
    let unsigned = b.unsigned_bytes();
    assert_hex("unsigned", &e["unsigned"], &unsigned);
    assert_hex("signed_digest", &e["signed_digest"], &Bundle::digest(&unsigned));
    assert_hex("signature", &e["signature"], &b.signature);
    assert_hex("bundle", &e["bundle"], &b.to_bytes());
    assert_eq!(b.to_bytes().len(), 1358);
}

#[test]
fn bundle_reject_tampered() {
    let v = vector("bundle-reject-tampered");
    assert_eq!(v["expected"]["result"], "reject");
    assert!(Bundle::accept(&hex_of(&v["input"]["bundle"]), &key_of(&v["input"]["expected_owner_pub"])).is_err());
}

#[test]
fn bundle_reject_wrong_owner() {
    let v = vector("bundle-reject-wrong-owner");
    assert_eq!(v["expected"]["result"], "reject");
    assert!(Bundle::accept(&hex_of(&v["input"]["bundle"]), &key_of(&v["input"]["expected_owner_pub"])).is_err());
}

#[test]
fn bundle_reject_bad_mlkem_key() {
    let v = vector("bundle-reject-bad-mlkem-key");
    assert_eq!(v["expected"]["result"], "reject");
    assert_eq!(
        Bundle::accept(&hex_of(&v["input"]["bundle"]), &key_of(&v["input"]["expected_owner_pub"])).unwrap_err(),
        kaspaveil_wire::Error::MlKemKey
    );
}

#[test]
fn bundle_accept() {
    let v = vector("bundle-accept");
    assert_eq!(v["expected"]["result"], "accept");
    let b = Bundle::accept(&hex_of(&v["input"]["bundle"]), &key_of(&v["input"]["expected_owner_pub"])).expect("accepted");
    assert_eq!(b.spk_id as u64, v["expected"]["spk_id"].as_u64().unwrap());
    assert_eq!(b.created, v["expected"]["created"].as_u64().unwrap());
    assert!(v["expected"]["devices"].as_array().unwrap().is_empty() && b.devices.is_empty());
}

#[test]
fn bundle_payload() {
    let v = vector("bundle-payload");
    let bundle = hex_of(&v["input"]["bundle"]);
    assert_hex("bundle_tag", &v["expected"]["bundle_tag"], &bundle_tag(&key_of(&v["input"]["owner_pub"])));
    let p = publication_payload(&bundle).unwrap();
    assert_hex("payload", &v["expected"]["payload"], &p);
    let parsed = parse_publication(&p).expect("valid publication");
    assert_eq!(parsed.to_bytes(), bundle);
    // A publication filed under someone else's tag, or with a bad marker, is ignored.
    let mut wrong_tag = p.clone();
    wrong_tag[1] ^= 1;
    assert!(parse_publication(&wrong_tag).is_err());
    let mut wrong_marker = p.clone();
    wrong_marker[20] ^= 1;
    assert!(parse_publication(&wrong_marker).is_err());
}

// -------------------------------------------------------------------------------- buckets

#[test]
fn buckets_message() {
    let v = vector("buckets-message");
    let got: Vec<u64> = v["input"]["tags"].as_array().unwrap().iter().map(|t| message_bucket(&hex_of(t)) as u64).collect();
    assert_eq_val("buckets", &v["expected"]["buckets"], &serde_json::json!(got));
}

#[test]
fn buckets_registry() {
    let v = vector("buckets-registry");
    let got: Vec<u64> = v["input"]["names"].as_array().unwrap().iter().map(|n| registry_bucket(n.as_str().unwrap()) as u64).collect();
    assert_eq_val("buckets", &v["expected"]["buckets"], &serde_json::json!(got));
}

#[test]
fn buckets_inbox() {
    let v = vector("buckets-inbox");
    let got: Vec<u64> = v["input"]["id_x25519_pubs"].as_array().unwrap().iter().map(|k| inbox_bucket(&key_of(k)) as u64).collect();
    assert_eq_val("buckets", &v["expected"]["buckets"], &serde_json::json!(got));
}

#[test]
fn buckets_with_bucket() {
    let v = vector("buckets-with-bucket");
    let tag: [u8; 16] = hex_of(&v["input"]["tag"]).try_into().unwrap();
    assert_hex("tag", &v["expected"]["tag"], &with_bucket(&tag, v["input"]["bucket"].as_u64().unwrap() as u16));
}

#[test]
fn cover_first_contact_vector() {
    let v = vector("cover-first-contact");
    let r = &v["input"]["rand"];
    let tag: [u8; 16] = hex_of(&r["random_tag"]).try_into().unwrap();
    let p = cover_first_contact(v["input"]["bucket"].as_u64().unwrap() as u16, &tag, &key_of(&r["ephemeral_x25519_sk"]), &hex_of(&r["random_rest"]));
    assert_hex("payload", &v["expected"]["payload"], &p);
    assert_eq!(message_bucket(&p[1..17]) as u64, v["input"]["bucket"].as_u64().unwrap());
}

#[test]
fn registry_default_names() {
    let v = vector("registry-default-names");
    let got: Vec<Vec<String>> =
        v["input"]["owner_pubs"].as_array().unwrap().iter().map(|o| (0..3).map(|n| default_name(&key_of(o), n)).collect()).collect();
    assert_eq_val("names", &v["expected"]["names"], &serde_json::json!(got));
}

// -------------------------------------------------------------------------------- first contact

fn recipient_prekeys(r: &Value) -> Vec<Prekey> {
    r["prekeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| Prekey::from_parts(p["spk_id"].as_u64().unwrap() as u32, key_of(&p["x25519_sk"]), seed64(&hex_of(&p["mlkem_keygen_seed"]))))
        .collect()
}

fn registry_of(v: &Value) -> BTreeMap<String, RegistryEntry> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, e)| (k.clone(), RegistryEntry { owner_pub: key_of(&e["owner_pub"]), id_x25519_pub: key_of(&e["id_x25519_pub"]) }))
        .collect()
}

fn open_vector(v: &Value) -> (Result<first_contact::Opened, kaspaveil_wire::Error>, Injected) {
    let r = &v["input"]["recipient"];
    let prekeys = recipient_prekeys(r);
    let me = Recipient { id_x25519_sk: key_of(&r["id_x25519_sk"]), id_x25519_pub: key_of(&r["id_x25519_pub"]), prekeys: &prekeys };
    assert_eq!(x25519_pub(&me.id_x25519_sk), me.id_x25519_pub);
    let reg = registry_of(&v["input"]["registry"]);
    let lookup = |name: &str| reg.get(name).cloned();
    let mut rng = Injected::new(&v["input"]["rand"]);
    let res = open_first_contact(&me, &lookup, &hex_of(&v["input"]["payload"]), &mut rng);
    (res, rng)
}

#[test]
fn first_contact_alice_to_bob() {
    let v = vector("first-contact-alice-to-bob");
    let a = &v["input"]["alice"];
    let alice = Sender {
        owner_pub: key_of(&a["owner_pub"]),
        id_x25519_sk: key_of(&a["id_x25519_sk"]),
        id_x25519_pub: key_of(&a["id_x25519_pub"]),
        name: a["name"].as_str().unwrap(),
    };
    let (bob, _) = Bundle::parse_prefix(&hex_of(&v["input"]["bob_bundle"])).unwrap();
    assert!(bob.verify_signature());
    let mut rng = Injected::new(&v["input"]["rand"]);
    let out = first_contact::send(&alice, &bob, 0x01, v["input"]["text"].as_str().unwrap().as_bytes(), &mut rng).unwrap();
    check_all_consumed("first contact", &rng);
    let e = &v["expected"];
    assert_hex("dh1", &e["dh1"], &out.dh1);
    assert_hex("dh2", &e["dh2"], &out.dh2);
    assert_hex("dh3", &e["dh3"], &out.dh3);
    assert_hex("mlkem_ciphertext", &e["mlkem_ciphertext"], &out.mlkem_ciphertext);
    assert_hex("mlkem_shared_secret", &e["mlkem_shared_secret"], &out.mlkem_shared_secret);
    assert_hex("sk", &e["sk"], &out.sk);
    assert_hex("tag", &e["tag"], &out.tag);
    assert_eq!(out.inbox_bucket as u64, e["inbox_bucket"].as_u64().unwrap());
    assert_hex("payload", &e["payload"], &out.payload);
    assert_session("alice session", &e["session"], &out.session);
}

#[test]
fn first_contact_bob_opens() {
    let v = vector("first-contact-bob-opens");
    let (res, rng) = open_vector(v);
    let o = res.expect("first contact opens");
    check_all_consumed("open", &rng);
    let e = &v["expected"];
    assert_eq!(o.from, e["from"].as_str().unwrap());
    assert_eq!(o.kind as u64, e["kind"].as_u64().unwrap());
    assert_bytes("text", e["text"].as_str().unwrap().as_bytes(), &o.content);
    assert_session("bob session", &e["session"], &o.session);
}

#[test]
fn first_contact_reject_not_for_me() {
    let v = vector("first-contact-reject-not-for-me");
    assert_eq!(v["expected"]["result"], "reject");
    assert!(open_vector(v).0.is_err());
}

#[test]
fn first_contact_reject_registry_mismatch() {
    let v = vector("first-contact-reject-registry-mismatch");
    assert_eq!(v["expected"]["result"], "reject");
    assert!(open_vector(v).0.is_err());
}

#[test]
fn first_contact_reject_low_order() {
    let v = vector("first-contact-reject-low-order");
    assert_eq!(v["expected"]["result"], "reject");
    assert_eq!(open_vector(v).0.unwrap_err(), kaspaveil_wire::Error::LowOrderPoint);
}

#[test]
fn first_contact_crossing() {
    let v = vector("first-contact-crossing");
    let a2b: [u8; 16] = hex_of(&v["input"]["alice_to_bob_tag"]).try_into().unwrap();
    let b2a: [u8; 16] = hex_of(&v["input"]["bob_to_alice_tag"]).try_into().unwrap();
    // The first-contact-alice-to-bob tag is the one this vector names.
    assert_eq!(hex::encode(a2b), vector("first-contact-alice-to-bob")["expected"]["tag"].as_str().unwrap());
    let alice_keeps_sent = crossing_keeps_sent(&a2b, &b2a);
    let bob_keeps_sent = crossing_keeps_sent(&b2a, &a2b);
    let e = &v["expected"];
    assert_eq!(if alice_keeps_sent { "sent" } else { "received" }, e["alice_keeps"].as_str().unwrap());
    assert_eq!(if bob_keeps_sent { "sent" } else { "received" }, e["bob_keeps"].as_str().unwrap());
    let keep = if alice_keeps_sent { "alice-to-bob" } else { "bob-to-alice" };
    assert_eq!(keep, e["keep"].as_str().unwrap());
    assert_ne!(alice_keeps_sent, bob_keeps_sent, "both sides must keep the same session");
}

#[test]
fn first_contact_recontact() {
    let v = vector("first-contact-recontact");
    for (c, want) in v["input"]["cases"].as_array().unwrap().iter().zip(v["expected"]["results"].as_array().unwrap()) {
        let s = session_from_json(&c["session"]);
        let cur: [u8; 16] = hex_of(&c["current_first_contact_tag"]).try_into().unwrap();
        let rcv: [u8; 16] = hex_of(&c["received_tag"]).try_into().unwrap();
        let got = if keeps_current(&s, &cur, &rcv) { "keep-current" } else { "use-new" };
        assert_eq!(got, want.as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn first_contact_replay() {
    let v = vector("first-contact-replay");
    let r = &v["input"]["recipient"];
    let prekeys = recipient_prekeys(r);
    let me = Recipient { id_x25519_sk: key_of(&r["id_x25519_sk"]), id_x25519_pub: key_of(&r["id_x25519_pub"]), prekeys: &prekeys };
    let reg = registry_of(&v["input"]["registry"]);
    let lookup = |name: &str| reg.get(name).cloned();
    let mut seen = SeenFirstContacts::default();
    for (i, (step, want)) in v["input"]["steps"].as_array().unwrap().iter().zip(v["expected"]["results"].as_array().unwrap()).enumerate() {
        let label = format!("first-contact-replay step {i}");
        let before = seen.clone();
        let mut rng = Injected::new(&step["rand"]);
        match (want["result"].as_str().unwrap(), receive_first_contact(&mut seen, &me, &lookup, &hex_of(&step["payload"]), &mut rng)) {
            ("accept", Ok(o)) => {
                assert_eq!(o.from, want["from"].as_str().unwrap(), "{label}: from");
                assert_eq!(o.kind as u64, want["kind"].as_u64().unwrap(), "{label}: kind");
                assert_eq!(o.content, want["text"].as_str().unwrap().as_bytes(), "{label}: text");
                assert_session(&label, &want["session"], &o.session);
            }
            ("replay", Err(kaspaveil_wire::Error::Replay)) | ("reject", Err(_)) => assert_eq!(seen, before, "{label}: no state change"),
            (w, got) => panic!("{label}: expected {w}, got {got:?}"),
        }
        check_all_consumed(&label, &rng);
    }
    let want: Vec<([u8; 16], u32)> = v["expected"]["seen_after"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (hex_of(&e["tag"]).try_into().unwrap(), e["spk_id"].as_u64().unwrap() as u32))
        .collect();
    assert_eq!(seen.0, want, "seen_after");
}

// -------------------------------------------------------------------------------- ratchet runner

fn run_session_steps(id: &str) {
    let v = vector(id);
    let mut sessions: BTreeMap<String, Session> =
        v["input"]["sessions"].as_object().unwrap().iter().map(|(k, s)| (k.clone(), session_from_json(s))).collect();
    let steps = v["input"]["steps"].as_array().unwrap();
    let results = v["expected"]["results"].as_array().unwrap();
    assert_eq!(steps.len(), results.len());
    for (i, (step, want)) in steps.iter().zip(results).enumerate() {
        let who = step["session"].as_str().unwrap();
        let label = format!("{id} step {i} ({} on {who})", step["op"].as_str().unwrap());
        let s = sessions.get_mut(who).unwrap();
        let mut rng = Injected::new(&step["rand"]);
        match step["op"].as_str().unwrap() {
            "encrypt" => {
                let p = s.encrypt(step["kind"].as_u64().unwrap() as u8, &hex_of(&step["content"]), &mut rng).unwrap();
                assert_hex(&format!("{label}: payload"), &want["payload"], &p);
            }
            "kem_offer" => {
                let seed = rng.mlkem_keygen_seed();
                let c = s.kem_offer(seed, 0).unwrap();
                assert_hex(&format!("{label}: offer content"), &want["content"], &c);
            }
            "decrypt" => {
                let before = s.clone();
                let r = s.decrypt(&hex_of(&step["payload"]), &mut rng, 0);
                if want["reject"] == true {
                    assert!(r.is_err(), "{label}: expected reject, got {r:?}");
                    assert_eq!(*s, before, "{label}: a rejected payload must leave the session unchanged");
                } else {
                    let r = r.unwrap_or_else(|e| panic!("{label}: expected success, got {e:?}"));
                    assert_eq!(r.kind as u64, want["kind"].as_u64().unwrap(), "{label}: kind");
                    assert_hex(&format!("{label}: content"), &want["content"], &r.content);
                    match (&want["kem_answer"], &r.kem_answer) {
                        (Value::Null, None) => {}
                        (w, Some(a)) if !w.is_null() => assert_hex(&format!("{label}: kem_answer"), w, a),
                        (w, a) => panic!("{label}: kem_answer expected {w}, got {a:?}"),
                    }
                }
            }
            op => panic!("unknown op {op}"),
        }
        check_all_consumed(&label, &rng);
    }
    for (who, want) in v["expected"]["sessions_after"].as_object().unwrap() {
        assert_session(&format!("{id}: {who} after"), want, &sessions[who]);
    }
}

#[test]
fn ratchet_conversation() {
    run_session_steps("ratchet-conversation");
}

#[test]
fn ratchet_out_of_order() {
    run_session_steps("ratchet-out-of-order");
}

#[test]
fn ratchet_reject_tampered() {
    let v = vector("ratchet-reject-tampered");
    let a = hex_of(&v["input"]["steps"][1]["payload"]);
    let b = hex_of(&v["input"]["steps"][2]["payload"]);
    let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert_eq!(diff, vec![500], "the tampered payload differs at offset 500 only");
    run_session_steps("ratchet-reject-tampered");
}

#[test]
fn ratchet_skipped_key_state() {
    run_session_steps("ratchet-skipped-key-state");
}

#[test]
fn ratchet_receiver_edge_cases() {
    run_session_steps("ratchet-receiver-edge-cases");
}

#[test]
fn ratchet_reject_low_order_ratchet_key() {
    run_session_steps("ratchet-reject-low-order-ratchet-key");
}

#[test]
fn kem_step_full() {
    run_session_steps("kem-step-full");
}

#[test]
fn kem_step_crossing_offers() {
    run_session_steps("kem-step-crossing-offers");
}

#[test]
fn kem_step_offer_pending() {
    run_session_steps("kem-step-offer-pending");
}

#[test]
fn kem_step_malformed_offer() {
    run_session_steps("kem-step-malformed-offer");
}

#[test]
fn ratchet_late_from_older_ratchet_key() {
    run_session_steps("ratchet-late-from-older-ratchet-key");
}

#[test]
fn kem_step_responder_keeps_offer_on_malformed() {
    run_session_steps("kem-step-responder-keeps-offer-on-malformed");
}

// -------------------------------------------------------------------------------- groups

fn members_of(v: &Value) -> Vec<Member> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|m| Member { owner_pub: key_of(&m["owner_pub"]), id_x25519_pub: key_of(&m["id_x25519_pub"]), name: m["name"].as_str().unwrap().into() })
        .collect()
}

#[test]
fn group_state_encode() {
    let v = vector("group-state-encode");
    let i = &v["input"];
    let sk = key_of(&i["admin_owner_sk"]);
    let admin = kaspaveil_wire::primitives::schnorr_pub(&sk).unwrap();
    let st = GroupState::create(
        &sk,
        admin,
        hex_of(&i["group_id"]).try_into().unwrap(),
        i["epoch"].as_u64().unwrap() as u32,
        members_of(&i["members"]),
        &key_of(&i["rand"]["schnorr_aux"]),
    )
    .unwrap();
    let bytes = st.to_bytes();
    assert_hex("content", &v["expected"]["content"], &bytes);
    assert_eq!(bytes.len(), 118 + 85 * 2);
    assert_eq!(GroupState::parse(&bytes).unwrap(), st);
}

#[test]
fn group_state_over_session() {
    run_session_steps("group-state-over-session");
}

#[test]
fn group_text_encode() {
    let v = vector("group-text-encode");
    let i = &v["input"];
    let t = GroupText {
        group_id: hex_of(&i["group_id"]).try_into().unwrap(),
        epoch: i["epoch"].as_u64().unwrap() as u32,
        msg_id: hex_of(&i["msg_id"]).try_into().unwrap(),
        text: i["text"].as_str().unwrap().as_bytes().to_vec(),
    };
    assert_hex("content", &v["expected"]["content"], &t.to_bytes().unwrap());
}

#[test]
fn group_text_over_session() {
    run_session_steps("group-text-over-session");
}

fn run_group_steps(id: &str) {
    let v = vector(id);
    let mut rx = GroupReceiver::new(key_of(&v["input"]["me_owner_pub"]));
    let senders: BTreeMap<String, Key32> = v["input"]["senders"].as_object().unwrap().iter().map(|(k, o)| (k.clone(), key_of(o))).collect();
    let results = v["expected"]["results"].as_array().unwrap();
    for (i, (step, want)) in v["input"]["steps"].as_array().unwrap().iter().zip(results).enumerate() {
        let from = senders[step["from"].as_str().unwrap()];
        let content = hex_of(&step["content"]);
        let label = format!("{id} step {i} ({})", step["note"].as_str().unwrap_or(""));
        let got = match step["op"].as_str().unwrap() {
            "group_state" => match rx.receive_state(&from, &content) {
                Ok((StateEvent::Joined { epoch }, _)) => serde_json::json!({"event": "joined", "epoch": epoch}),
                Ok((StateEvent::Updated { epoch }, _)) => serde_json::json!({"event": "updated", "epoch": epoch}),
                Ok((StateEvent::Removed { epoch }, _)) => serde_json::json!({"event": "removed", "epoch": epoch}),
                Err(_) => serde_json::json!({"reject": true}),
            },
            "group_text" => match rx.receive_text(&from, &content) {
                Ok(TextOutcome::Accepted { text, epoch, older_epoch, .. }) => {
                    serde_json::json!({"text": text, "epoch": epoch, "older_epoch": older_epoch})
                }
                Ok(TextOutcome::Pending) => serde_json::json!({"pending": true}),
                Err(_) => serde_json::json!({"reject": true}),
            },
            op => panic!("unknown op {op}"),
        };
        assert_eq_val(&label, want, &got);
    }
}

#[test]
fn group_receive_rules() {
    run_group_steps("group-receive-rules");
}

#[test]
fn group_state_duplicate_identity_key() {
    let v = vector("group-state-duplicate-identity-key");
    let st = GroupState::parse(&hex_of(&v["input"]["steps"][0]["content"])).unwrap();
    assert_eq!(st.members[0].id_x25519_pub, st.members[1].id_x25519_pub, "the vector shares an identity key");
    run_group_steps("group-state-duplicate-identity-key");
}

// -------------------------------------------------------------------------------- settings

fn prefs_of(p: &Value, epoch: u32) -> Option<Prefs> {
    if p.is_null() {
        return None;
    }
    Some(Prefs { version: 1, epoch, group_id: None, timer_off: p["timer_off"].as_bool().unwrap(), screenshot_protection: p["screenshot_protection"].as_bool().unwrap() })
}

#[test]
fn settings_encode() {
    let v = vector("settings-encode");
    for (p, want) in v["input"]["prefs"].as_array().unwrap().iter().zip(v["expected"]["contents"].as_array().unwrap()) {
        let prefs = prefs_of(p, p["epoch"].as_u64().unwrap() as u32).unwrap();
        let bytes = settings::encode(&prefs).unwrap();
        assert_hex("content", want, &bytes);
        assert_eq!(settings::decode(&bytes).unwrap(), prefs);
    }
}

#[test]
fn settings_reject() {
    let v = vector("settings-reject");
    for (c, want) in v["input"]["contents"].as_array().unwrap().iter().zip(v["expected"]["results"].as_array().unwrap()) {
        assert_eq!(want, "reject");
        assert!(settings::decode(&hex_of(c)).is_err(), "{c} must be rejected");
    }
}

fn settings_v2_vector(id: &str) {
    let v = vector(id);
    let i = &v["input"];
    assert_eq!(i["version"], 2);
    let flags = i["flags"].as_u64().unwrap();
    let group_id = match i["context"].as_u64().unwrap() {
        0 => None,
        1 => Some(hex_of(&i["group_id"]).try_into().unwrap()),
        c => panic!("context {c}"),
    };
    let prefs = Prefs { version: 2, epoch: i["epoch"].as_u64().unwrap() as u32, group_id, timer_off: flags & 1 != 0, screenshot_protection: flags & 2 != 0 };
    let bytes = settings::encode(&prefs).unwrap();
    assert_hex("bytes", &v["expected"]["bytes"], &bytes);
    assert_eq!(bytes.len() as u64, v["expected"]["length"].as_u64().unwrap());
    assert_eq!(settings::decode(&bytes).unwrap(), prefs);
}

#[test]
fn settings_encode_v2() {
    settings_v2_vector("settings-encode-v2");
}

#[test]
fn settings_encode_group() {
    settings_v2_vector("settings-encode-group");
}

#[test]
fn settings_reject_v2() {
    let v = vector("settings-reject-v2");
    for (c, want) in v["input"]["cases"].as_array().unwrap().iter().zip(v["expected"]["results"].as_array().unwrap()) {
        assert_eq!(want, "reject");
        let mut b = vec![c["version"].as_u64().unwrap() as u8];
        b.extend_from_slice(&(c["epoch"].as_u64().unwrap() as u32).to_be_bytes());
        b.push(c["context"].as_u64().unwrap() as u8);
        b.extend_from_slice(&hex_of(&c["context_data"]));
        b.push(c["flags"].as_u64().unwrap() as u8);
        assert_hex("assembled content", &c["content"], &b);
        assert!(settings::decode(&b).is_err(), "{} must be rejected", c["content"]);
    }
}

#[test]
fn settings_effective() {
    let v = vector("settings-effective");
    for (case, want) in v["input"]["cases"].as_array().unwrap().iter().zip(v["expected"]["results"].as_array().unwrap()) {
        let members: Vec<(bool, Option<Prefs>)> =
            case["members"].as_array().unwrap().iter().map(|m| (m["plus"].as_bool().unwrap(), prefs_of(&m["prefs"], 1))).collect();
        let e = settings::effective(&members);
        let got = serde_json::json!({"timer_seconds": e.timer_seconds, "screenshot_protection": e.screenshot_protection});
        assert_eq_val(case["name"].as_str().unwrap(), want, &got);
    }
}

// -------------------------------------------------------------------------------- transaction

#[test]
fn transaction_relay_paid_pot() {
    transaction_vector("transaction-relay-paid-pot");
}

fn transaction_vector(id: &str) {
    let v = vector(id);
    let i = &v["input"];
    let inputs = i["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Input {
            previous_txid: key_of(&x["previous_txid"]),
            previous_index: x["previous_index"].as_u64().unwrap() as u32,
            sequence: x["sequence"].as_u64().unwrap(),
            compute_budget: x["compute_budget"].as_u64().unwrap() as u16,
            signature_script: hex_of(&x["signature_script"]),
            utxo_amount: x["utxo_amount"].as_u64().unwrap(),
            utxo_script_public_key: hex_of(&x["utxo_script_public_key"]),
            utxo_script_version: x["utxo_script_version"].as_u64().unwrap() as u16,
            utxo_daa_score: x["utxo_daa_score"].as_u64().unwrap(),
            utxo_covenant_id: x.get("utxo_covenant_id").map(key_of),
        })
        .collect();
    let outputs = i["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| Output {
            value: o["value"].as_u64().unwrap(),
            script_public_key: hex_of(&o["script_public_key"]),
            script_version: o["script_version"].as_u64().unwrap() as u16,
            covenant: o.get("covenant").map(|c| (c["authorizing_input"].as_u64().unwrap() as u16, key_of(&c["covenant_id"]))),
        })
        .collect();
    let tx = Transaction::kaspaveil(inputs, outputs, i["lock_time"].as_u64().unwrap(), hex_of(&i["payload"]));
    // The Kaspaveil-specific fields match the spec's constants.
    assert_eq!(tx.version as u64, i["version"].as_u64().unwrap());
    assert_hex("subnetwork_id", &i["subnetwork_id"], &tx.subnetwork_id);
    assert_eq!(tx.gas, i["gas"].as_u64().unwrap());
    // The payload is ratchet-conversation step 0's.
    assert_eq!(i["payload"], vector("ratchet-conversation")["expected"]["results"][0]["payload"]);
    let e = &v["expected"];
    assert_hex("transaction_id", &e["transaction_id"], &tx.id());
    assert_eq!(tx.estimated_serialized_size(), e["estimated_serialized_size"].as_u64().unwrap(), "estimated_serialized_size");
    assert_eq!(tx.compute_mass(), e["compute_mass"].as_u64().unwrap(), "compute_mass");
    assert_eq!(tx.transient_mass(), e["transient_mass"].as_u64().unwrap(), "transient_mass");
    assert_eq!(tx.storage_mass(), e["storage_mass"].as_u64().unwrap(), "storage_mass");
    assert_eq!(tx.min_fee(), e["min_fee"].as_u64().unwrap(), "min_fee");
    assert_eq!(tx.fee().unwrap(), e["fee_paid"].as_u64().unwrap(), "fee_paid");
    assert!(tx.fee().unwrap() >= tx.min_fee());
    if tx.outputs[0].covenant.is_some() {
        // The spending pot's shape (SC-0012).
        assert!(tx.check_pot_paid(tx.lock_time));
        assert!(!tx.check_pot_paid(tx.lock_time - 1), "lock time must already have passed");
        let mut unbound = tx.clone();
        unbound.outputs[0].covenant = None;
        assert!(!unbound.check_pot_paid(tx.lock_time), "the continuation must carry the pot's covenant binding");
        assert_ne!(unbound.id(), tx.id(), "the binding is part of the transaction ID");
        let mut final_seq = tx.clone();
        final_seq.inputs[0].sequence = u64::MAX;
        assert!(!final_seq.check_pot_paid(tx.lock_time), "a final sequence would switch the lock time off");
        return;
    }
    // Retired certificate-based hot wallet: lock_time = epoch 22 start (570,240,000 = 22 × 25,920,000).
    let epoch = tx.lock_time / 25_920_000;
    assert!(tx.check_relay_paid(epoch, tx.lock_time));
    assert!(!tx.check_relay_paid(epoch + 1, tx.lock_time + 25_920_000));
}

// -------------------------------------------------------------------------------- completeness

#[test]
fn every_vector_has_a_test() {
    let in_file: Vec<&str> = file()["vectors"].as_array().unwrap().iter().map(|v| v["id"].as_str().unwrap()).collect();
    assert_eq!(in_file.len(), 49, "the file holds 49 vectors");
    let mut a = in_file.clone();
    a.sort();
    let mut b = VECTOR_IDS.to_vec();
    b.sort();
    assert_eq!(a, b, "every vector id in the file has exactly one test here");
    // And each id's test function exists: the name is the id with '-' → '_' (cover-first-contact
    // is `cover_first_contact_vector` to avoid clashing with the library function).
    let src = include_str!("vectors.rs");
    for id in VECTOR_IDS {
        let name = if *id == "cover-first-contact" { "cover_first_contact_vector".to_string() } else { id.replace('-', "_") };
        assert!(src.contains(&format!("fn {name}()")), "missing test fn {name} for vector {id}");
    }
}
