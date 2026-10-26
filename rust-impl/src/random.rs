//! Every random value the protocol consumes, by the names the vector harness uses.
//! Production code uses [`OsRandom`]; the vector harness injects values.

use crate::primitives::Key32;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;

pub trait RandomSource {
    /// A new X25519 ratchet secret (a party creating a new sending chain).
    fn ratchet_x25519_sk(&mut self) -> Key32;
    /// The 32 random bytes of an ongoing message (§4.1 `random`).
    fn random_field(&mut self) -> Key32;
    /// The ML-KEM `m` for encapsulation (first contact, answering an offer).
    fn mlkem_encaps_m(&mut self) -> Key32;
    /// 64-byte `d ‖ z` for a KEM offer.
    fn mlkem_keygen_seed(&mut self) -> [u8; 64];
    /// First contact's ephemeral X25519 secret.
    fn ephemeral_x25519_sk(&mut self) -> Key32;
    /// BIP-340 aux randomness.
    fn schnorr_aux(&mut self) -> Key32;
}

pub struct OsRandom;

impl OsRandom {
    fn fill<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        OsRng.fill_bytes(&mut b);
        b
    }
}

impl RandomSource for OsRandom {
    fn ratchet_x25519_sk(&mut self) -> Key32 {
        Self::fill()
    }
    fn random_field(&mut self) -> Key32 {
        Self::fill()
    }
    fn mlkem_encaps_m(&mut self) -> Key32 {
        Self::fill()
    }
    fn mlkem_keygen_seed(&mut self) -> [u8; 64] {
        Self::fill()
    }
    fn ephemeral_x25519_sk(&mut self) -> Key32 {
        Self::fill()
    }
    fn schnorr_aux(&mut self) -> Key32 {
        Self::fill()
    }
}
