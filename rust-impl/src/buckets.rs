//! WIRE_FORMAT §6 (buckets), §4.4 (cover traffic, dummy first contact) and
//! PROTOCOL_SPEC §3.4 (free default names).

use crate::primitives::{blake2b, x25519_pub, Key32};
use crate::PAYLOAD_LEN;

pub fn message_bucket(tag: &[u8]) -> u16 {
    ((tag[0] as u16) << 4) | (tag[1] as u16 >> 4)
}

pub fn registry_bucket(name: &str) -> u8 {
    blake2b(&[name.as_bytes()])[0]
}

pub fn inbox_bucket(id_x25519_pub: &Key32) -> u16 {
    let h = blake2b(&[b"kasveil/v1/inbox", id_x25519_pub]);
    ((h[0] as u16) << 4) | (h[1] as u16 >> 4)
}

/// Replaces the first 12 bits of a 16-byte tag with `bucket`.
pub fn with_bucket(tag: &[u8; 16], bucket: u16) -> [u8; 16] {
    let mut t = *tag;
    t[0] = (bucket >> 4) as u8;
    t[1] = ((bucket as u8 & 0x0f) << 4) | (t[1] & 0x0f);
    t
}

/// §4.4 cover traffic: `0x01 ‖ 2,047 random bytes`.
pub fn cover_payload(random: &[u8]) -> Vec<u8> {
    assert_eq!(random.len(), PAYLOAD_LEN - 1);
    let mut p = Vec::with_capacity(PAYLOAD_LEN);
    p.push(1);
    p.extend_from_slice(random);
    p
}

/// §4.4 dummy first contact:
/// `0x01 ‖ withBucket(16 random bytes, bucket) ‖ X25519 public key of a random secret ‖ 1,999 random bytes`.
pub fn cover_first_contact(bucket: u16, random_tag: &[u8; 16], eph_sk: &Key32, random_rest: &[u8]) -> Vec<u8> {
    assert_eq!(random_rest.len(), PAYLOAD_LEN - 1 - 16 - 32);
    let mut p = Vec::with_capacity(PAYLOAD_LEN);
    p.push(1);
    p.extend_from_slice(&with_bucket(random_tag, bucket));
    p.extend_from_slice(&x25519_pub(eph_sk));
    p.extend_from_slice(random_rest);
    p
}

/// PROTOCOL_SPEC §3.4: `"kv" ‖ base32(BLAKE2b(ownerPub ‖ n))[0..8]`, n one byte, alphabet a–z2–7,
/// first 40 bits of the hash, big-endian.
pub fn default_name(owner_pub: &Key32, n: u8) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let h = blake2b(&[owner_pub, &[n]]);
    let bits = h[..5].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    let mut s = String::from("kv");
    for i in (0..8).rev() {
        s.push(ALPHABET[((bits >> (5 * i)) & 31) as usize] as char);
    }
    s
}
