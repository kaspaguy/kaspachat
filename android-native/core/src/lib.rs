//! KaspaChat Android core: the only place the app touches key material. Everything protocol-shaped comes from
//! `rust-impl` (the byte-exact Kaspaveil v1 implementation); this crate adds the app-local pieces (claim secrets,
//! the passcode vault layer, the doorman's proof of work) and the JNI surface in `jni_glue`.

mod jni_glue;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use kaspaveil_wire::bundle::{publication_payload, Bundle};
use kaspaveil_wire::keys::{identity_from_seed, prekey};
use kaspaveil_wire::{buckets, Error};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub type Key32 = [u8; 32];

/// 32 bytes of entropy (from the platform's CSPRNG) to a 24-word English phrase.
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<String, Error> {
    if entropy.len() != 32 {
        return Err(Error::Malformed);
    }
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy).map(|m| m.to_string()).map_err(|_| Error::Mnemonic)
}

/// WIRE_FORMAT §2: BIP-39 seed (empty passphrase) of a valid 24-word phrase.
pub fn seed_from_mnemonic(phrase: &str) -> Result<[u8; 64], Error> {
    let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let r = kaspaveil_wire::keys::seed_from_mnemonic(&normalized);
    let mut normalized = normalized;
    normalized.zeroize();
    r
}

fn seed64(seed: &[u8]) -> Result<[u8; 64], Error> {
    seed.try_into().map_err(|_| Error::Malformed)
}

pub fn owner_pub(seed: &[u8]) -> Result<Key32, Error> {
    let mut id = identity_from_seed(seed64(seed)?);
    let p = id.owner_pub;
    id.seed.zeroize();
    id.owner_sk.zeroize();
    id.id_x25519_sk.zeroize();
    Ok(p)
}

pub fn default_name(owner_pub: &[u8], n: u8) -> Result<String, Error> {
    Ok(buckets::default_name(&owner_pub.try_into().map_err(|_| Error::Malformed)?, n))
}

pub fn registry_bucket(name: &str) -> u8 {
    buckets::registry_bucket(name)
}

/// §3/§4.3: this identity's bundle for signed prekey `spk_id`, as a 1,536-byte publication payload.
pub fn bundle_publication(seed: &[u8], spk_id: u32, created_sec: u64, aux: &[u8]) -> Result<Vec<u8>, Error> {
    let mut id = identity_from_seed(seed64(seed)?);
    let mut spk = prekey(&id.seed, spk_id);
    let aux: Key32 = aux.try_into().map_err(|_| Error::Malformed)?;
    let b = Bundle::create(&id.owner_sk, id.owner_pub, id.id_x25519_pub, spk_id, spk.x25519_pub, spk.mlkem_pub.clone(), created_sec, vec![], &aux);
    id.seed.zeroize();
    id.owner_sk.zeroize();
    id.id_x25519_sk.zeroize();
    spk.x25519_sk.zeroize();
    spk.mlkem_seed.zeroize();
    spk.mlkem_sk.zeroize();
    publication_payload(&b?.to_bytes())
}

pub fn bundle_tag(owner_pub: &[u8]) -> Result<[u8; 16], Error> {
    Ok(kaspaveil_wire::bundle::bundle_tag(&owner_pub.try_into().map_err(|_| Error::Malformed)?))
}

/// §3/§4.3 on a directory hit: the bundle's `spkId` if `payload` is a valid publication by `owner_pub` that is not
/// more than 24 hours in the future (a restore continues from the next prekey, WIRE_FORMAT §2).
pub fn own_bundle_spk_id(payload: &[u8], owner_pub: &[u8], now_sec: u64) -> Option<u32> {
    let b = kaspaveil_wire::bundle::parse_publication(payload).ok()?;
    (b.owner_pub[..] == *owner_pub && b.created <= now_sec + 24 * 3600).then_some(b.spk_id)
}

/// The relay account secret number `i` (app/src/lib/engine.ts `claim`): HMAC-SHA256 keyed by
/// SHA256(seed ‖ "kaspachat/v1/accounts") over the decimal index. A restore finds the same accounts again.
pub fn claim_secret(seed: &[u8], i: u32) -> Key32 {
    let mut k: Key32 = Sha256::new().chain_update(seed).chain_update(b"kaspachat/v1/accounts").finalize().into();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&k).expect("any key length");
    k.zeroize();
    mac.update(i.to_string().as_bytes());
    mac.finalize().into_bytes().into()
}

/// SC-0024: an order's extras account, derived from its claim exactly as the relay does.
pub fn extra_secret(claim: &[u8]) -> Key32 {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(claim).expect("any key length");
    mac.update(b"kaspachat/v1/extra");
    mac.finalize().into_bytes().into()
}

/// Device-local keys (e.g. the database key), never sent anywhere: HKDF-SHA256(seed, "kaspachat/android/v1/" ‖ label).
pub fn local_key(seed: &[u8], label: &str) -> Key32 {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(None, seed).expand(format!("kaspachat/android/v1/{label}").as_bytes(), &mut out).expect("32 bytes");
    out
}

/// The passcode layer of the seed vault: the same scrypt (N = 2^15, r = 8, p = 1) as protocol/src/vault.ts.
pub fn vault_key(passcode: &[u8], salt: &[u8]) -> Key32 {
    let params = scrypt::Params::new(15, 8, 1, 32).expect("valid params");
    let mut out = [0u8; 32];
    scrypt::scrypt(passcode, salt, &params, &mut out).expect("32-byte output");
    out
}

pub fn vault_seal(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if iv.len() != 12 {
        return Err(Error::Malformed);
    }
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    c.encrypt(Nonce::from_slice(iv), plaintext).map_err(|_| Error::Aead)
}

/// Fails (`Error::Aead`) on a wrong passcode or an altered blob.
pub fn vault_open(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
    if iv.len() != 12 {
        return Err(Error::Malformed);
    }
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    c.decrypt(Nonce::from_slice(iv), ct).map_err(|_| Error::Aead)
}

/// The doorman's puzzle (app/src/lib/pow.worker.ts): a nonce, as lowercase hex text, such that
/// SHA256(challenge ‖ nonce) starts with `bits` zero bits. Searches `count` nonces from `start` so the caller can
/// report progress and cancel between slices.
pub fn solve_pow(challenge: &[u8], bits: u32, start: u64, count: u64) -> Option<String> {
    let base = Sha256::new().chain_update(challenge);
    for n in start..start.saturating_add(count) {
        let nonce = format!("{n:x}");
        let h = base.clone().chain_update(nonce.as_bytes()).finalize();
        if leading_zero_bits(&h) >= bits {
            return Some(nonce);
        }
    }
    None
}

fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut z = 0;
    for &b in h {
        if b == 0 {
            z += 8;
        } else {
            return z + b.leading_zeros();
        }
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Vec<Value> {
        let s = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../protocol/vectors/v1.json")).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        v["vectors"].as_array().unwrap().clone()
    }
    fn vector(id: &str) -> Value {
        vectors().into_iter().find(|v| v["id"] == id).unwrap()
    }
    fn h(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn keys_match_vectors() {
        for id in ["keys-alice", "keys-bob"] {
            let v = vector(id);
            let seed = seed_from_mnemonic(v["input"]["mnemonic"].as_str().unwrap()).unwrap();
            assert_eq!(seed.to_vec(), h(&v["expected"]["seed"]));
            assert_eq!(owner_pub(&seed).unwrap().to_vec(), h(&v["expected"]["owner_pub"]));
        }
    }

    #[test]
    fn mnemonic_round_trip_and_whitespace() {
        let m = mnemonic_from_entropy(&[7u8; 32]).unwrap();
        assert_eq!(m.split(' ').count(), 24);
        let messy = format!("  {}  ", m.to_uppercase().replace(' ', "   "));
        assert_eq!(seed_from_mnemonic(&messy).unwrap(), seed_from_mnemonic(&m).unwrap());
        assert!(seed_from_mnemonic("abandon abandon").is_err());
        assert!(mnemonic_from_entropy(&[0u8; 16]).is_err());
    }

    #[test]
    fn default_names_match_vectors() {
        let v = vector("registry-default-names");
        let owners = v["input"]["owner_pubs"].as_array().unwrap();
        let names = v["expected"]["names"].as_array().unwrap();
        assert!(!owners.is_empty());
        for (o, per) in owners.iter().zip(names) {
            for (n, name) in per.as_array().unwrap().iter().enumerate() {
                assert_eq!(default_name(&h(o), n as u8).unwrap(), name.as_str().unwrap());
            }
        }
    }

    #[test]
    fn bundle_publication_parses_and_verifies() {
        let v = vector("keys-bob");
        let seed = seed_from_mnemonic(v["input"]["mnemonic"].as_str().unwrap()).unwrap();
        let p = bundle_publication(&seed, 1, 1_760_000_000, &[9u8; 32]).unwrap();
        assert_eq!(p.len(), kaspaveil_wire::PAYLOAD_LEN);
        let b = kaspaveil_wire::bundle::parse_publication(&p).unwrap();
        assert_eq!(b.owner_pub.to_vec(), h(&v["expected"]["owner_pub"]));
        assert_eq!((b.spk_id, b.created), (1, 1_760_000_000));
        let owner = owner_pub(&seed).unwrap();
        assert_eq!(own_bundle_spk_id(&p, &owner, 1_760_000_000), Some(1));
        assert_eq!(own_bundle_spk_id(&p, &[0u8; 32], 1_760_000_000), None);
        assert_eq!(own_bundle_spk_id(&p, &owner, 1_760_000_000 - 2 * 86_400), None);
        assert_eq!(&p[1..17], &bundle_tag(&owner).unwrap());
    }

    #[test]
    fn claim_and_extra_secrets_are_stable() {
        // Same derivation as the web app's engine.ts, checked against values computed with Node's crypto.
        let seed = [1u8; 64];
        assert_eq!(hex::encode(claim_secret(&seed, 0)), CLAIM0);
        assert_eq!(hex::encode(extra_secret(&claim_secret(&seed, 0))), EXTRA0);
        assert_ne!(claim_secret(&seed, 0), claim_secret(&seed, 1));
    }
    const CLAIM0: &str = include_str!("../testdata/claim0.hex");
    const EXTRA0: &str = include_str!("../testdata/extra0.hex");

    #[test]
    fn vault_round_trip_and_wrong_key() {
        let k = vault_key(b"correct horse", &[3u8; 16]);
        assert_eq!(hex::encode(k), include_str!("../testdata/vaultkey.hex"));
        let ct = vault_seal(&k, &[4u8; 12], b"phrase").unwrap();
        assert_eq!(vault_open(&k, &[4u8; 12], &ct).unwrap(), b"phrase");
        let wrong = vault_key(b"correct horsf", &[3u8; 16]);
        assert_eq!(vault_open(&wrong, &[4u8; 12], &ct), Err(Error::Aead));
    }

    #[test]
    fn pow_meets_target() {
        let c = [5u8; 32];
        let nonce = solve_pow(&c, 12, 0, 1 << 24).unwrap();
        let hsh = Sha256::new().chain_update(c).chain_update(nonce.as_bytes()).finalize();
        assert!(leading_zero_bits(&hsh) >= 12);
    }
}
