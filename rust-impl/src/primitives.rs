//! WIRE_FORMAT §1: every primitive, wrapped around audited libraries only.

use blake2::digest::{Update, VariableOutput};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Error;

pub type Key32 = [u8; 32];

pub const LABEL_PREFIX: &[u8] = b"kasveil/v1/";

/// `KDF(ikm, label, len, salt) = HKDF-SHA-256(ikm, salt, "kasveil/v1/" ‖ label, len)`.
pub fn kdf(ikm: &[u8], label: &str, len: usize, salt: Option<&[u8]>) -> Vec<u8> {
    let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
    let mut info = Vec::with_capacity(LABEL_PREFIX.len() + label.len());
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label.as_bytes());
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("HKDF length within limits");
    out
}

/// `KDF(ikm, label)` with the defaults: len 32, salt absent.
pub fn kdf32(ikm: &[u8], label: &str) -> Key32 {
    to32(&kdf(ikm, label, 32, None))
}

pub fn kdf32_salt(ikm: &[u8], label: &str, salt: &[u8]) -> Key32 {
    to32(&kdf(ikm, label, 32, Some(salt)))
}

pub fn to32(b: &[u8]) -> Key32 {
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[..32]);
    k
}

/// BLAKE2b-256 of the concatenation of `parts`.
pub fn blake2b(parts: &[&[u8]]) -> Key32 {
    blake2b_var::<32>(parts)
}

/// BLAKE2b with its output-length parameter set to 16 (not a truncation).
pub fn blake2b_128(parts: &[&[u8]]) -> [u8; 16] {
    blake2b_var::<16>(parts)
}

fn blake2b_var<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut h = blake2::Blake2bVar::new(N).expect("valid output size");
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; N];
    h.finalize_variable(&mut out).expect("size matches");
    out
}

pub fn u32be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

// ---------------------------------------------------------------- X25519

/// X25519 public key of a raw (unclamped) secret; clamping happens inside the function.
pub fn x25519_pub(sk: &Key32) -> Key32 {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// X25519(sk, pk). An all-zero result (a low-order peer key) is an error (§1).
pub fn x25519(sk: &Key32, pk: &Key32) -> Result<Key32, Error> {
    let out = x25519_dalek::x25519(*sk, *pk);
    if out.iter().all(|&b| b == 0) {
        return Err(Error::LowOrderPoint);
    }
    Ok(out)
}

// ---------------------------------------------------------------- AEAD

/// XChaCha20-Poly1305 with the 24-byte zero nonce.
pub fn seal(key: &Key32, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let c = XChaCha20Poly1305::new(key.into());
    c.encrypt(&XNonce::default(), Payload { msg: plaintext, aad: ad }).expect("encryption cannot fail")
}

pub fn open(key: &Key32, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    let c = XChaCha20Poly1305::new(key.into());
    c.decrypt(&XNonce::default(), Payload { msg: ciphertext, aad: ad }).map_err(|_| Error::Aead)
}

// ---------------------------------------------------------------- HMAC chain

pub fn hmac_sha256(key: &Key32, data: &[u8]) -> Key32 {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    Mac::update(&mut m, data);
    to32(&m.finalize().into_bytes())
}

/// `KDF_CK(ck)` → (next chain key, message key).
pub fn kdf_ck(ck: &Key32) -> (Key32, Key32) {
    (hmac_sha256(ck, &[0x02]), hmac_sha256(ck, &[0x01]))
}

/// `KDF_RK(rk, dh) = KDF(dh, "root", 64, rk)` → (rk, ck).
pub fn kdf_rk(rk: &Key32, dh: &Key32) -> (Key32, Key32) {
    let out = kdf(dh, "root", 64, Some(rk));
    (to32(&out[..32]), to32(&out[32..]))
}

/// §4.5: `KDF(dh ‖ SS, "root-pq", 64, rk)`.
pub fn kdf_rk_pq(rk: &Key32, dh: &Key32, ss: &Key32) -> (Key32, Key32) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(ss);
    let out = kdf(&ikm, "root-pq", 64, Some(rk));
    (to32(&out[..32]), to32(&out[32..]))
}

// ---------------------------------------------------------------- BIP-340

/// BIP-340 signature over the 32-byte digest `m`, signed as is.
pub fn schnorr_sign(sk: &Key32, m: &Key32, aux: &Key32) -> Result<[u8; 64], Error> {
    let key = k256::schnorr::SigningKey::from_bytes(sk).map_err(|_| Error::InvalidKey)?;
    let sig = key.sign_raw(m, aux).map_err(|_| Error::InvalidKey)?;
    Ok(sig.to_bytes())
}

pub fn schnorr_verify(pubkey: &Key32, m: &Key32, sig: &[u8]) -> bool {
    let Ok(vk) = k256::schnorr::VerifyingKey::from_bytes(pubkey) else { return false };
    let Ok(sig) = k256::schnorr::Signature::try_from(sig) else { return false };
    vk.verify_raw(m, &sig).is_ok()
}

pub fn schnorr_pub(sk: &Key32) -> Result<Key32, Error> {
    let key = k256::schnorr::SigningKey::from_bytes(sk).map_err(|_| Error::InvalidKey)?;
    Ok(to32(&key.verifying_key().to_bytes()))
}

// ---------------------------------------------------------------- ML-KEM-768

pub mod mlkem {
    use super::{to32, Key32};
    use crate::Error;
    use kem::Decapsulate;
    use ml_kem::{array::Array, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768};

    pub const PUB_LEN: usize = 1184;
    pub const SK_LEN: usize = 2400;
    pub const CT_LEN: usize = 1088;
    const Q: u16 = 3329;

    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;

    fn split(seed: &[u8; 64]) -> (ml_kem::B32, ml_kem::B32) {
        let d = Array::try_from(&seed[..32]).expect("32");
        let z = Array::try_from(&seed[32..]).expect("32");
        (d, z)
    }

    /// `ML-KEM.KeyGen_internal(d, z)` from the 64-byte seed `d ‖ z` → (public 1,184 B, secret 2,400 B).
    pub fn keygen(seed: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
        let (d, z) = split(seed);
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
    }

    /// FIPS 203 §7.2 encapsulation-key check: the right length, and every 12-bit coefficient
    /// of the encoded vector is below q (equivalently ByteEncode12(ByteDecode12(ek)) == ek).
    /// This is an input check around the library, not a primitive: ml-kem 0.2.1 does not run it.
    pub fn check_pub(pk: &[u8]) -> Result<(), Error> {
        if pk.len() != PUB_LEN {
            return Err(Error::MlKemKey);
        }
        for c in pk[..PUB_LEN - 32].as_chunks::<3>().0 {
            let a = c[0] as u16 | ((c[1] as u16 & 0x0f) << 8);
            let b = (c[1] as u16 >> 4) | ((c[2] as u16) << 4);
            if a >= Q || b >= Q {
                return Err(Error::MlKemKey);
            }
        }
        Ok(())
    }

    /// `ML-KEM.Encaps_internal(ek, m)` → (ciphertext, shared secret). The key is checked first.
    pub fn encaps(pk: &[u8], m: &Key32) -> Result<(Vec<u8>, Key32), Error> {
        check_pub(pk)?;
        let enc = Array::try_from(pk).map_err(|_| Error::MlKemKey)?;
        let ek = Ek::from_bytes(&enc);
        let m = Array::from(*m);
        let (ct, ss) = ek.encapsulate_deterministic(&m).map_err(|_| Error::MlKemKey)?;
        Ok((ct.to_vec(), to32(&ss)))
    }

    /// Decapsulation with the key pair regenerated from its 64-byte seed.
    pub fn decaps(seed: &[u8; 64], ct: &[u8]) -> Result<Key32, Error> {
        let (d, z) = split(seed);
        let (dk, _): (Dk, Ek) = MlKem768::generate_deterministic(&d, &z);
        let ct = Array::try_from(ct).map_err(|_| Error::Malformed)?;
        let ss = dk.decapsulate(&ct).map_err(|_| Error::Malformed)?;
        Ok(to32(&ss))
    }
}
