//! WIRE_FORMAT §4.1 (double ratchet, encrypted headers, tag chains) and §4.5 (KEM ratchet step).

use crate::primitives::{
    blake2b_128, kdf32, kdf32_salt, kdf_ck, kdf_rk, kdf_rk_pq, mlkem, open, seal, to32, u32be, x25519, x25519_pub, Key32,
};
use crate::random::RandomSource;
use crate::{Error, PAYLOAD_LEN};

pub const BODY_LEN: usize = 1407;
pub const MAX_CONTENT: usize = BODY_LEN - 3;
pub const HEADER_LEN: usize = 48;
pub const MAX_SKIP: u32 = 1000;
/// Receivers MUST watch at least 64 unreceived indices per incoming chain (§4.1).
pub const TAG_WINDOW: u32 = 64;
/// Skipped keys are deleted 7 days after they were stored (§4.1).
pub const SKIPPED_KEY_LIFETIME: u64 = 7 * 24 * 3600;

pub const KIND_KEM: u8 = 0x05;
pub const OFFER_LEN: usize = 1 + 4 + mlkem::PUB_LEN;
pub const ANSWER_LEN: usize = 1 + 4 + 16 + mlkem::CT_LEN;
/// KEM step due policy (§4.5): at least every 50 messages or 24 hours.
pub const KEM_DUE_MESSAGES: u32 = 50;
pub const KEM_DUE_SECONDS: u64 = 24 * 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedKey {
    pub their_ratchet_pub: Key32,
    pub n: u32,
    pub message_key: Key32,
    /// Local storage time (Unix seconds); not part of the vector harness.
    pub stored_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqOffer {
    pub epoch: u32,
    pub mlkem_keygen_seed: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqSecret {
    pub epoch: u32,
    pub shared_secret: Key32,
    /// true: offerer (mixes into its next sending chain); false: answerer (mixes on receive).
    pub mix_on_send: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingChain {
    pub tag_key_in: Key32,
    pub tag_in: u32,
    pub seen_in: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub ad: Vec<u8>,
    pub initiator: bool,
    pub root_key: Key32,
    pub our_ratchet_sk: Key32,
    pub our_ratchet_pub: Key32,
    pub their_ratchet_pub: Key32,
    pub sending_chain_key: Option<Key32>,
    pub receiving_chain_key: Option<Key32>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub tag_key_out: Key32,
    pub tag_key_in: Key32,
    pub tag_out: u32,
    pub tag_in: u32,
    pub seen_in: Vec<u32>,
    pub skipped: Vec<SkippedKey>,
    pub pq_epoch: u32,
    pub pq_offer: Option<PqOffer>,
    pub pq_secret: Option<PqSecret>,
    pub tag_key_in_next: Option<Key32>,
    pub previous_in: Option<IncomingChain>,
    /// Local KEM due-policy state (not in the harness): messages sent + received, and the time,
    /// since this side last offered or answered (or since the session started).
    pub kem_messages: u32,
    pub kem_since: u64,
    /// Transient flag while receiving on a losing crossing session.
    pub receive_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    pub kind: u8,
    pub content: Vec<u8>,
    /// Body content to send back (kind 0x05) when the message was a KEM offer we answered.
    pub kem_answer: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Watched {
    Current,
    Next,
    Previous,
}

pub fn tag_for(tag_key: &Key32, i: u32) -> [u8; 16] {
    blake2b_128(&[tag_key, &u32be(i)])
}

pub fn header_key(tag_key: &Key32, i: u32) -> Key32 {
    kdf32_salt(tag_key, "header", &u32be(i))
}

pub fn pq_tag_key(tag_key: &Key32, ss: &Key32) -> Key32 {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(tag_key);
    ikm[32..].copy_from_slice(ss);
    kdf32(&ikm, "pq-tag")
}

pub fn offer_id(mlkem_pub: &[u8]) -> [u8; 16] {
    blake2b_128(&[b"kasveil/v1/kem-offer", mlkem_pub])
}

/// `kind u8 ‖ length u16 ‖ content ‖ zero padding`, `total` bytes.
pub fn encode_body(kind: u8, content: &[u8], total: usize) -> Result<Vec<u8>, Error> {
    if content.len() > total - 3 {
        return Err(Error::TooLong);
    }
    let mut b = Vec::with_capacity(total);
    b.push(kind);
    b.extend_from_slice(&(content.len() as u16).to_be_bytes());
    b.extend_from_slice(content);
    b.resize(total, 0);
    Ok(b)
}

/// Rejects a `length` that overruns the body or padding that isn't all zero.
pub fn decode_body(b: &[u8]) -> Result<(u8, Vec<u8>), Error> {
    let len = u16::from_be_bytes([b[1], b[2]]) as usize;
    if 3 + len > b.len() || b[3 + len..].iter().any(|&x| x != 0) {
        return Err(Error::Malformed);
    }
    Ok((b[0], b[3..3 + len].to_vec()))
}

struct Header {
    ratchet_pub: Key32,
    pn: u32,
    n: u32,
    pq_epoch: u32,
}

fn mark_received(tag_in: &mut u32, seen: &mut Vec<u32>, i: u32) {
    if i == *tag_in {
        *tag_in += 1;
        while let Some(pos) = seen.iter().position(|&s| s == *tag_in) {
            seen.remove(pos);
            *tag_in += 1;
        }
    } else if let Err(pos) = seen.binary_search(&i) {
        seen.insert(pos, i);
    }
}

/// The next `TAG_WINDOW` unreceived indices from `tag_in` (received ones above `tag_in` are
/// skipped and don't count against the window).
fn window(tag_in: u32, seen: &[u32]) -> impl Iterator<Item = u32> + '_ {
    (tag_in..).filter(move |i| !seen.contains(i)).take(TAG_WINDOW as usize)
}

fn find_in(tag_key: &Key32, tag_in: u32, seen: &[u32], tag: &[u8]) -> Option<u32> {
    window(tag_in, seen).find(|&i| tag_for(tag_key, i) == tag)
}

impl Session {
    /// Next tags a receiver watches, for indexers/clients filtering a bucket.
    pub fn watched_tags(&self) -> Vec<[u8; 16]> {
        let mut v: Vec<[u8; 16]> = window(self.tag_in, &self.seen_in).map(|i| tag_for(&self.tag_key_in, i)).collect();
        if let Some(k) = &self.tag_key_in_next {
            v.extend(window(0, &[]).map(|i| tag_for(k, i)));
        }
        if let Some(p) = &self.previous_in {
            v.extend(window(p.tag_in, &p.seen_in).map(|i| tag_for(&p.tag_key_in, i)));
        }
        v
    }

    /// §4.1 ongoing message.
    pub fn encrypt(&mut self, kind: u8, content: &[u8], rng: &mut dyn RandomSource) -> Result<Vec<u8>, Error> {
        let body = encode_body(kind, content, BODY_LEN)?;
        let ck = self.sending_chain_key.ok_or(Error::State)?;
        let (next_ck, mk) = kdf_ck(&ck);
        let i = self.tag_out;
        let tag = tag_for(&self.tag_key_out, i);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&self.our_ratchet_pub);
        header.extend_from_slice(&self.pn.to_be_bytes());
        header.extend_from_slice(&self.ns.to_be_bytes());
        header.push(0);
        header.extend_from_slice(&self.pq_epoch.to_be_bytes());
        header.extend_from_slice(&[0, 0, 0]);
        let header_ct = seal(&header_key(&self.tag_key_out, i), &header, &tag);
        let mut ad = self.ad.clone();
        ad.extend_from_slice(&header_ct);
        let body_ct = seal(&mk, &body, &ad);
        let mut p = Vec::with_capacity(PAYLOAD_LEN);
        p.push(1);
        p.extend_from_slice(&tag);
        p.extend_from_slice(&rng.random_field());
        p.extend_from_slice(&header_ct);
        p.extend_from_slice(&body_ct);
        debug_assert_eq!(p.len(), PAYLOAD_LEN);
        self.sending_chain_key = Some(next_ck);
        self.ns += 1;
        self.tag_out += 1;
        self.kem_messages += 1;
        Ok(p)
    }

    fn locate(&self, tag: &[u8]) -> Option<(Watched, Key32, u32)> {
        if let Some(i) = find_in(&self.tag_key_in, self.tag_in, &self.seen_in, tag) {
            return Some((Watched::Current, self.tag_key_in, i));
        }
        if let Some(k) = &self.tag_key_in_next {
            if let Some(i) = find_in(k, 0, &[], tag) {
                return Some((Watched::Next, *k, i));
            }
        }
        if let Some(p) = &self.previous_in {
            if let Some(i) = find_in(&p.tag_key_in, p.tag_in, &p.seen_in, tag) {
                return Some((Watched::Previous, p.tag_key_in, i));
            }
        }
        None
    }

    /// Stores skipped keys of the current receiving chain up to (not including) `until`.
    fn skip_to(&mut self, until: u32, now: u64) -> Result<(), Error> {
        let Some(mut ck) = self.receiving_chain_key else { return Ok(()) };
        if until <= self.nr {
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(Error::TooManySkipped);
        }
        while self.nr < until {
            let (next, mk) = kdf_ck(&ck);
            self.skipped.push(SkippedKey { their_ratchet_pub: self.their_ratchet_pub, n: self.nr, message_key: mk, stored_at: now });
            ck = next;
            self.nr += 1;
        }
        self.receiving_chain_key = Some(ck);
        Ok(())
    }

    fn mix_outgoing_tag(&mut self, ss: &Key32) {
        self.tag_key_out = pq_tag_key(&self.tag_key_out, ss);
        self.tag_out = 0;
    }

    /// Eager DH ratchet step (§4.1 steps 1–5 minus the skipping), with the §4.5 `pqEpoch` rule
    /// and both mix points.
    fn dh_step(&mut self, h: &Header, rng: &mut dyn RandomSource) -> Result<(), Error> {
        let recv_pq = if h.pq_epoch == self.pq_epoch {
            None
        } else {
            match &self.pq_secret {
                Some(s) if !s.mix_on_send && s.epoch == h.pq_epoch && h.pq_epoch == self.pq_epoch.wrapping_add(1) => {
                    Some(s.shared_secret)
                }
                _ => return Err(Error::PqEpoch),
            }
        };
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.their_ratchet_pub = h.ratchet_pub;
        let dh = x25519(&self.our_ratchet_sk, &h.ratchet_pub)?;
        let (rk, ckr) = match &recv_pq {
            Some(ss) => kdf_rk_pq(&self.root_key, &dh, ss),
            None => kdf_rk(&self.root_key, &dh),
        };
        self.root_key = rk;
        self.receiving_chain_key = Some(ckr);
        if let Some(ss) = recv_pq {
            // Answerer's mix (§4.5 step 6): pqEpoch advances, outgoing tag chain re-keyed.
            self.pq_epoch = h.pq_epoch;
            self.mix_outgoing_tag(&ss);
            self.pq_secret = None;
        }
        let new_sk = rng.ratchet_x25519_sk();
        let new_pub = x25519_pub(&new_sk);
        let dh2 = x25519(&new_sk, &h.ratchet_pub)?;
        let send_pq = match &self.pq_secret {
            Some(s) if s.mix_on_send => Some((s.epoch, s.shared_secret)),
            _ => None,
        };
        let (rk, cks) = match &send_pq {
            Some((_, ss)) => kdf_rk_pq(&self.root_key, &dh2, ss),
            None => kdf_rk(&self.root_key, &dh2),
        };
        self.root_key = rk;
        self.sending_chain_key = Some(cks);
        self.our_ratchet_sk = new_sk;
        self.our_ratchet_pub = new_pub;
        if let Some((epoch, ss)) = send_pq {
            // Offerer's mix (§4.5 step 5).
            self.pq_epoch = epoch;
            self.mix_outgoing_tag(&ss);
            self.pq_secret = None;
        }
        Ok(())
    }

    pub fn expire_skipped(&mut self, now: u64) {
        self.skipped.retain(|k| now.saturating_sub(k.stored_at) < SKIPPED_KEY_LIFETIME);
    }

    /// Receives one payload. On any failure the session is left unchanged.
    pub fn decrypt(&mut self, payload: &[u8], rng: &mut dyn RandomSource, now: u64) -> Result<Received, Error> {
        self.expire_skipped(now);
        let mut s = self.clone();
        let r = s.decrypt_inner(payload, rng, now)?;
        *self = s;
        Ok(r)
    }

    /// Receiving on a crossing session that lost (§4.2): messages are received as normal, but
    /// KEM offers are not answered and no KEM state changes, since this session never sends.
    pub fn decrypt_receive_only(&mut self, payload: &[u8], rng: &mut dyn RandomSource, now: u64) -> Result<Received, Error> {
        self.receive_only = true;
        let r = self.decrypt(payload, rng, now);
        self.receive_only = false;
        r
    }

    fn decrypt_inner(&mut self, p: &[u8], rng: &mut dyn RandomSource, now: u64) -> Result<Received, Error> {
        if p.len() != PAYLOAD_LEN || p[0] != 1 {
            return Err(Error::Malformed);
        }
        let tag = &p[1..17];
        let header_ct = &p[49..113];
        let body_ct = &p[113..];
        let (watched, tag_key, idx) = self.locate(tag).ok_or(Error::UnknownTag)?;
        let hp = open(&header_key(&tag_key, idx), header_ct, tag)?;
        // flags (byte 40) and the 3 trailing bytes are reserved: ignored on receive.
        let h = Header {
            ratchet_pub: to32(&hp[0..32]),
            pn: u32::from_be_bytes(hp[32..36].try_into().unwrap()),
            n: u32::from_be_bytes(hp[36..40].try_into().unwrap()),
            pq_epoch: u32::from_be_bytes(hp[41..45].try_into().unwrap()),
        };
        let mk = if let Some(pos) = self.skipped.iter().position(|k| k.their_ratchet_pub == h.ratchet_pub && k.n == h.n) {
            self.skipped.remove(pos).message_key
        } else {
            if h.ratchet_pub != self.their_ratchet_pub {
                self.skip_to(h.pn, now)?;
                self.dh_step(&h, rng)?;
            }
            self.skip_to(h.n, now)?;
            let ck = self.receiving_chain_key.ok_or(Error::State)?;
            let (next, mk) = kdf_ck(&ck);
            self.receiving_chain_key = Some(next);
            self.nr += 1;
            mk
        };
        let mut ad = self.ad.clone();
        ad.extend_from_slice(header_ct);
        let body = open(&mk, body_ct, &ad)?;
        let (kind, content) = decode_body(&body)?;

        match watched {
            Watched::Current => mark_received(&mut self.tag_in, &mut self.seen_in, idx),
            Watched::Next => {
                self.previous_in =
                    Some(IncomingChain { tag_key_in: self.tag_key_in, tag_in: self.tag_in, seen_in: std::mem::take(&mut self.seen_in) });
                self.tag_key_in = tag_key;
                self.tag_in = 0;
                self.tag_key_in_next = None;
                mark_received(&mut self.tag_in, &mut self.seen_in, idx);
            }
            Watched::Previous => {
                let prev = self.previous_in.as_mut().expect("located on previous");
                mark_received(&mut prev.tag_in, &mut prev.seen_in, idx);
            }
        }
        self.kem_messages += 1;

        let kem_answer = if kind == KIND_KEM && !self.receive_only { self.receive_kem(&content, rng, now) } else { None };
        Ok(Received { kind, content, kem_answer })
    }

    /// §4.5 state table. Stale or malformed steps are ignored (the message still counts as received).
    fn receive_kem(&mut self, c: &[u8], rng: &mut dyn RandomSource, now: u64) -> Option<Vec<u8>> {
        match (c.first(), c.len()) {
            (Some(0x01), OFFER_LEN) => {
                let epoch = u32::from_be_bytes(c[1..5].try_into().unwrap());
                let pk = &c[5..];
                if epoch != self.pq_epoch.wrapping_add(1) {
                    return None;
                }
                match (&self.pq_offer, &self.pq_secret) {
                    (_, Some(s)) if s.mix_on_send => return None,
                    (Some(_), _) if self.initiator => return None,
                    _ => {}
                }
                let m = rng.mlkem_encaps_m();
                let (ct, ss) = mlkem::encaps(pk, &m).ok()?;
                self.pq_offer = None;
                self.pq_secret = Some(PqSecret { epoch, shared_secret: ss, mix_on_send: false });
                self.tag_key_in_next = Some(pq_tag_key(&self.tag_key_in, &ss));
                self.kem_messages = 0;
                self.kem_since = now;
                let mut a = Vec::with_capacity(ANSWER_LEN);
                a.push(0x02);
                a.extend_from_slice(&epoch.to_be_bytes());
                a.extend_from_slice(&offer_id(pk));
                a.extend_from_slice(&ct);
                Some(a)
            }
            (Some(0x02), ANSWER_LEN) => {
                let epoch = u32::from_be_bytes(c[1..5].try_into().unwrap());
                let offer = self.pq_offer.as_ref()?;
                if offer.epoch != epoch || self.pq_secret.is_some() {
                    return None;
                }
                let (pk, _) = mlkem::keygen(&offer.mlkem_keygen_seed);
                if c[5..21] != offer_id(&pk) {
                    return None;
                }
                let ss = mlkem::decaps(&offer.mlkem_keygen_seed, &c[21..]).ok()?;
                self.pq_offer = None;
                self.pq_secret = Some(PqSecret { epoch, shared_secret: ss, mix_on_send: true });
                self.tag_key_in_next = Some(pq_tag_key(&self.tag_key_in, &ss));
                self.kem_messages = 0;
                self.kem_since = now;
                None
            }
            _ => None,
        }
    }

    /// Starts (or replaces) a KEM offer; returns the kind-0x05 body content to send.
    /// A side never offers while it holds an `SS`.
    pub fn kem_offer(&mut self, seed: [u8; 64], now: u64) -> Result<Vec<u8>, Error> {
        if self.pq_secret.is_some() {
            return Err(Error::State);
        }
        let epoch = self.pq_epoch + 1;
        let (pk, _) = mlkem::keygen(&seed);
        self.pq_offer = Some(PqOffer { epoch, mlkem_keygen_seed: seed });
        self.kem_messages = 0;
        self.kem_since = now;
        let mut c = Vec::with_capacity(OFFER_LEN);
        c.push(0x01);
        c.extend_from_slice(&epoch.to_be_bytes());
        c.extend_from_slice(&pk);
        Ok(c)
    }

    /// Whether a KEM step is due (§4.5): 50 messages sent and received, or 24 hours, since this
    /// side last offered or answered (or since the session started), and no `SS` held.
    pub fn kem_due(&self, now: u64) -> bool {
        self.pq_secret.is_none()
            && (self.kem_messages >= KEM_DUE_MESSAGES || now.saturating_sub(self.kem_since) >= KEM_DUE_SECONDS)
    }
}

/// Helper used by first contact and tests: 64-byte seed from a slice.
pub fn seed64(b: &[u8]) -> [u8; 64] {
    let mut s = [0u8; 64];
    s.copy_from_slice(&b[..64]);
    s
}

/// Used by first contact (§4.2): session tag keys from SK.
pub fn tag_keys(sk: &Key32) -> (Key32, Key32) {
    (kdf32(sk, "tag-i2r"), kdf32(sk, "tag-r2i"))
}
