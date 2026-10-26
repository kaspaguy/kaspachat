//! WIRE_FORMAT §4.2: first contact (PQXDH-style), including the crossing rule.

use crate::buckets::{inbox_bucket, with_bucket};
use crate::bundle::Bundle;
use crate::keys::Prekey;
use crate::primitives::{blake2b_128, kdf32, kdf_ck, kdf_rk, mlkem, open, seal, to32, x25519, x25519_pub, Key32};
use crate::random::RandomSource;
use crate::session::{decode_body, encode_body, tag_keys, Session};
use crate::{Error, PAYLOAD_LEN};

pub const INNER_BODY_LEN: usize = 245;
pub const MAX_FC_CONTENT: usize = INNER_BODY_LEN - 3;
const INNER_CT_LEN: usize = INNER_BODY_LEN + 16;
const SEALED_PT_LEN: usize = 1 + 21 + 32 + 32 + 4 + 32 + INNER_CT_LEN;
pub const ALLOWED_KINDS: [u8; 3] = [0x01, 0x03, 0x04];

/// `len u8 ‖ UTF-8 name ‖ 0x00 × (20 − len)`, 1 ≤ len ≤ 20.
pub fn encode_name_field(name: &str) -> Result<[u8; 21], Error> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 20 {
        return Err(Error::Malformed);
    }
    let mut f = [0u8; 21];
    f[0] = b.len() as u8;
    f[1..1 + b.len()].copy_from_slice(b);
    Ok(f)
}

/// Receivers reject another `len` and ignore the padding.
pub fn decode_name_field(f: &[u8]) -> Result<String, Error> {
    let len = f[0] as usize;
    if !(1..=20).contains(&len) {
        return Err(Error::Malformed);
    }
    String::from_utf8(f[1..1 + len].to_vec()).map_err(|_| Error::Malformed)
}

pub struct Sender<'a> {
    pub owner_pub: Key32,
    pub id_x25519_sk: Key32,
    pub id_x25519_pub: Key32,
    pub name: &'a str,
}

#[derive(Debug, Clone)]
pub struct FirstContactOut {
    pub dh1: Key32,
    pub dh2: Key32,
    pub dh3: Key32,
    pub mlkem_ciphertext: Vec<u8>,
    pub mlkem_shared_secret: Key32,
    pub sk: Key32,
    pub tag: [u8; 16],
    pub inbox_bucket: u16,
    pub payload: Vec<u8>,
    pub session: Session,
}

fn fc_tag(dh2: &Key32, recipient_idx_pub: &Key32) -> [u8; 16] {
    with_bucket(&blake2b_128(&[b"kasveil/v1/fc-tag", dh2]), inbox_bucket(recipient_idx_pub))
}

fn pqxdh_sk(dh1: &Key32, dh2: &Key32, dh3: &Key32, ss: &Key32) -> Key32 {
    let mut ikm = Vec::with_capacity(160);
    ikm.extend_from_slice(&[0xff; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(ss);
    kdf32(&ikm, "pqxdh")
}

fn outer_key(dh2: &Key32, ss: &Key32) -> Key32 {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh2);
    ikm[32..].copy_from_slice(ss);
    kdf32(&ikm, "fc-outer")
}

/// Alice → Bob. Random values are drawn in the order ephemeral, ML-KEM `m`, ratchet key.
pub fn send(alice: &Sender, bob: &Bundle, kind: u8, content: &[u8], rng: &mut dyn RandomSource) -> Result<FirstContactOut, Error> {
    if !ALLOWED_KINDS.contains(&kind) {
        return Err(Error::FirstContact);
    }
    let body = encode_body(kind, content, INNER_BODY_LEN)?;
    let name_field = encode_name_field(alice.name)?;
    let eph = rng.ephemeral_x25519_sk();
    let m = rng.mlkem_encaps_m();
    let ratchet_sk = rng.ratchet_x25519_sk();

    let dh1 = x25519(&alice.id_x25519_sk, &bob.spk_x25519_pub)?;
    let dh2 = x25519(&eph, &bob.id_x25519_pub)?;
    let dh3 = x25519(&eph, &bob.spk_x25519_pub)?;
    let (kem_ct, ss) = mlkem::encaps(&bob.spk_mlkem_pub, &m)?;
    let tag = fc_tag(&dh2, &bob.id_x25519_pub);
    let sk = pqxdh_sk(&dh1, &dh2, &dh3, &ss);
    let mut ad = alice.id_x25519_pub.to_vec();
    ad.extend_from_slice(&bob.id_x25519_pub);

    let ratchet_pub = x25519_pub(&ratchet_sk);
    let (rk, ck) = kdf_rk(&sk, &x25519(&ratchet_sk, &bob.spk_x25519_pub)?);
    let (next_ck, mk) = kdf_ck(&ck);
    let mut inner_ad = ad.clone();
    inner_ad.extend_from_slice(&ratchet_pub);
    let inner_ct = seal(&mk, &body, &inner_ad);

    let mut pt = Vec::with_capacity(SEALED_PT_LEN);
    pt.push(0x01);
    pt.extend_from_slice(&name_field);
    pt.extend_from_slice(&alice.owner_pub);
    pt.extend_from_slice(&alice.id_x25519_pub);
    pt.extend_from_slice(&bob.spk_id.to_be_bytes());
    pt.extend_from_slice(&ratchet_pub);
    pt.extend_from_slice(&inner_ct);
    let sealed = seal(&outer_key(&dh2, &ss), &pt, &tag);

    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.push(1);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&x25519_pub(&eph));
    payload.extend_from_slice(&kem_ct);
    payload.extend_from_slice(&sealed);
    debug_assert_eq!(payload.len(), PAYLOAD_LEN);

    let (i2r, r2i) = tag_keys(&sk);
    let session = Session {
        ad,
        initiator: true,
        root_key: rk,
        our_ratchet_sk: ratchet_sk,
        our_ratchet_pub: ratchet_pub,
        their_ratchet_pub: bob.spk_x25519_pub,
        sending_chain_key: Some(next_ck),
        receiving_chain_key: None,
        ns: 1,
        nr: 0,
        pn: 0,
        tag_key_out: i2r,
        tag_key_in: r2i,
        tag_out: 0,
        tag_in: 0,
        seen_in: vec![],
        skipped: vec![],
        pq_epoch: 0,
        pq_offer: None,
        pq_secret: None,
        tag_key_in_next: None,
        previous_in: None,
        kem_messages: 1,
        kem_since: 0,
        receive_only: false,
    };
    Ok(FirstContactOut {
        dh1,
        dh2,
        dh3,
        mlkem_ciphertext: kem_ct,
        mlkem_shared_secret: ss,
        sk,
        tag,
        inbox_bucket: inbox_bucket(&bob.id_x25519_pub),
        payload,
        session,
    })
}

pub struct Recipient<'a> {
    pub id_x25519_sk: Key32,
    pub id_x25519_pub: Key32,
    /// Current signed prekey first, then the previous one.
    pub prekeys: &'a [Prekey],
}

/// What the registry says about a name: its owner key and that owner's bundle identity key.
#[derive(Clone, Debug)]
pub struct RegistryEntry {
    pub owner_pub: Key32,
    pub id_x25519_pub: Key32,
}

#[derive(Debug, Clone)]
pub struct Opened {
    pub from: String,
    pub sender_owner_pub: Key32,
    pub kind: u8,
    pub content: Vec<u8>,
    pub tag: [u8; 16],
    /// The prekey that opened it.
    pub spk_id: u32,
    pub session: Session,
}

/// Bob scanning a payload from his inbox bucket.
pub fn open_first_contact(
    me: &Recipient,
    registry: &dyn Fn(&str) -> Option<RegistryEntry>,
    p: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<Opened, Error> {
    if p.len() != PAYLOAD_LEN || p[0] != 1 {
        return Err(Error::Malformed);
    }
    let tag: [u8; 16] = p[1..17].try_into().unwrap();
    let eph = to32(&p[17..49]);
    let kem_ct = &p[49..49 + mlkem::CT_LEN];
    let sealed = &p[49 + mlkem::CT_LEN..];

    let dh2 = x25519(&me.id_x25519_sk, &eph)?;
    if fc_tag(&dh2, &me.id_x25519_pub) != tag {
        return Err(Error::UnknownTag);
    }
    let mut found = None;
    for pk in me.prekeys {
        let Ok(ss) = mlkem::decaps(&pk.mlkem_seed, kem_ct) else { continue };
        if let Ok(pt) = open(&outer_key(&dh2, &ss), sealed, &tag) {
            if pt.len() == SEALED_PT_LEN && pt[0] == 0x01 {
                found = Some((pk, ss, pt));
                break;
            }
        }
    }
    let (pk, ss, pt) = found.ok_or(Error::FirstContact)?;
    let name = decode_name_field(&pt[1..22])?;
    let owner = to32(&pt[22..]);
    let alice_idx = to32(&pt[54..]);
    let spk_id = u32::from_be_bytes(pt[86..90].try_into().unwrap());
    let alice_ratchet = to32(&pt[90..]);
    let inner_ct = &pt[122..];
    if spk_id != pk.spk_id {
        return Err(Error::FirstContact);
    }
    let entry = registry(&name).ok_or(Error::FirstContact)?;
    if entry.owner_pub != owner || entry.id_x25519_pub != alice_idx {
        return Err(Error::FirstContact);
    }

    let dh1 = x25519(&pk.x25519_sk, &alice_idx)?;
    let dh3 = x25519(&pk.x25519_sk, &eph)?;
    let sk = pqxdh_sk(&dh1, &dh2, &dh3, &ss);
    let mut ad = alice_idx.to_vec();
    ad.extend_from_slice(&me.id_x25519_pub);
    let (rk, ckr) = kdf_rk(&sk, &x25519(&pk.x25519_sk, &alice_ratchet)?);
    let (next_ckr, mk) = kdf_ck(&ckr);
    let mut inner_ad = ad.clone();
    inner_ad.extend_from_slice(&alice_ratchet);
    let body = open(&mk, inner_ct, &inner_ad)?;
    let (kind, content) = decode_body(&body)?;
    if !ALLOWED_KINDS.contains(&kind) {
        return Err(Error::FirstContact);
    }

    let new_sk = rng.ratchet_x25519_sk();
    let (rk2, cks) = kdf_rk(&rk, &x25519(&new_sk, &alice_ratchet)?);
    let (i2r, r2i) = tag_keys(&sk);
    let session = Session {
        ad,
        initiator: false,
        root_key: rk2,
        our_ratchet_sk: new_sk,
        our_ratchet_pub: x25519_pub(&new_sk),
        their_ratchet_pub: alice_ratchet,
        sending_chain_key: Some(cks),
        receiving_chain_key: Some(next_ckr),
        ns: 0,
        nr: 1,
        pn: 0,
        tag_key_out: r2i,
        tag_key_in: i2r,
        tag_out: 0,
        tag_in: 0,
        seen_in: vec![],
        skipped: vec![],
        pq_epoch: 0,
        pq_offer: None,
        pq_secret: None,
        tag_key_in_next: None,
        previous_in: None,
        kem_messages: 1,
        kem_since: 0,
        receive_only: false,
    };
    Ok(Opened { from: name, sender_owner_pub: owner, kind, content, tag, spk_id, session })
}

/// Crossing first contacts: both sides keep the session whose first-contact tag is lower
/// (bytewise, unsigned big-endian). Returns true if the session we *sent* is the one to keep.
pub fn crossing_keeps_sent(sent_tag: &[u8; 16], received_tag: &[u8; 16]) -> bool {
    sent_tag < received_tag
}

/// Tags of the first contacts already opened, each with the prekey that opened it, in the order seen (§4.2).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SeenFirstContacts(pub Vec<([u8; 16], u32)>);

impl SeenFirstContacts {
    /// A prekey rotated out: first contacts it opened can no longer be decrypted, so their tags are forgotten.
    pub fn forget_prekey(&mut self, spk_id: u32) {
        self.0.retain(|(_, id)| *id != spk_id);
    }
}

/// `open_first_contact` plus the replay rule: a tag already opened is `Error::Replay` with no state changed.
/// Only a first contact that opens is remembered, so a forged payload copying a genuine tag can't get it dropped.
pub fn receive_first_contact(
    seen: &mut SeenFirstContacts,
    me: &Recipient,
    registry: &dyn Fn(&str) -> Option<RegistryEntry>,
    p: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<Opened, Error> {
    if p.len() == PAYLOAD_LEN && seen.0.iter().any(|(t, _)| t[..] == p[1..17]) {
        return Err(Error::Replay);
    }
    let o = open_first_contact(me, registry, p, rng)?;
    seen.0.push((o.tag, o.spk_id));
    Ok(o)
}

/// Our first contact to this peer is still pending: we initiated and have received nothing on it.
pub fn pending_first_contact(s: &Session) -> bool {
    s.initiator && s.receiving_chain_key.is_none()
}

/// A first contact from a peer we already hold a session with (§4.2). Only a crossing (ours still
/// pending) uses the lower-tag rule; any other first contact is a re-contact (e.g. the peer restored
/// from its phrase) and replaces ours. True = keep the current session, the new one is receive-only.
pub fn keeps_current(current: &Session, current_fc_tag: &[u8; 16], received_fc_tag: &[u8; 16]) -> bool {
    pending_first_contact(current) && crossing_keeps_sent(current_fc_tag, received_fc_tag)
}

/// Delivery window after which a losing crossing session is discarded entirely (§4.2).
pub const CROSSING_RECEIVE_ONLY_SECONDS: u64 = 7 * 24 * 3600;

/// The sessions a client holds with one peer. After crossing first contacts, the session with
/// the lower first-contact tag is the one used to send (including KEM offers and answers); the
/// other is receive-only until the delivery window ends, then discarded, keys included.
pub struct PeerSessions {
    pub primary: Session,
    pub primary_fc_tag: [u8; 16],
    pub receive_only: Option<(Session, u64)>,
}

impl PeerSessions {
    pub fn new(session: Session, fc_tag: [u8; 16]) -> Self {
        PeerSessions { primary: session, primary_fc_tag: fc_tag, receive_only: None }
    }

    /// A first contact from this peer was opened while we already hold a session with them (§4.2).
    pub fn on_first_contact_received(&mut self, session: Session, fc_tag: [u8; 16], now: u64) {
        if keeps_current(&self.primary, &self.primary_fc_tag, &fc_tag) {
            self.receive_only = Some((session, now + CROSSING_RECEIVE_ONLY_SECONDS));
        } else {
            let old = std::mem::replace(&mut self.primary, session);
            self.primary_fc_tag = fc_tag;
            self.receive_only = Some((old, now + CROSSING_RECEIVE_ONLY_SECONDS));
        }
    }

    /// A second session with the same peer appeared (the crossing case): lower tag wins.
    pub fn add_crossing(&mut self, other: Session, other_fc_tag: [u8; 16], now: u64) {
        let expires = now + CROSSING_RECEIVE_ONLY_SECONDS;
        if other_fc_tag < self.primary_fc_tag {
            let old = std::mem::replace(&mut self.primary, other);
            self.primary_fc_tag = other_fc_tag;
            self.receive_only = Some((old, expires));
        } else {
            self.receive_only = Some((other, expires));
        }
    }

    pub fn expire(&mut self, now: u64) {
        if matches!(self.receive_only, Some((_, exp)) if now >= exp) {
            self.receive_only = None;
        }
    }

    /// Tries the primary session, then the receive-only one. A KEM answer produced on the
    /// receive-only session is dropped: it is never used to send.
    pub fn receive(&mut self, p: &[u8], rng: &mut dyn RandomSource, now: u64) -> Result<crate::session::Received, Error> {
        self.expire(now);
        match self.primary.decrypt(p, rng, now) {
            Ok(r) => Ok(r),
            Err(e) => match &mut self.receive_only {
                Some((s, _)) => s.decrypt_receive_only(p, rng, now).map_err(|_| e),
                None => Err(e),
            },
        }
    }
}
