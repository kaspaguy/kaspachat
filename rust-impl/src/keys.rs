//! WIRE_FORMAT §2: keys from the recovery phrase.

use crate::primitives::{kdf, kdf32, kdf32_salt, mlkem, schnorr_pub, u32be, x25519_pub, Key32};
use crate::Error;

/// secp256k1 group order n.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6,
    0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// BIP-39 seed of a 24-word English phrase, with the empty passphrase (always).
pub fn seed_from_mnemonic(phrase: &str) -> Result<[u8; 64], Error> {
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).map_err(|_| Error::Mnemonic)?;
    if m.word_count() != 24 {
        return Err(Error::Mnemonic);
    }
    Ok(m.to_seed(""))
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub seed: [u8; 64],
    pub owner_sk: Key32,
    pub owner_pub: Key32,
    pub id_x25519_sk: Key32,
    pub id_x25519_pub: Key32,
}

pub fn owner_sk(seed: &[u8]) -> Key32 {
    let mut i: u64 = 0;
    loop {
        let cand = kdf32(seed, &format!("owner/{i}"));
        if cand != [0u8; 32] && cand < SECP256K1_N {
            return cand;
        }
        i += 1;
    }
}

pub fn identity_from_seed(seed: [u8; 64]) -> Identity {
    let owner_sk = owner_sk(&seed);
    let owner_pub = schnorr_pub(&owner_sk).expect("valid by construction");
    let id_x25519_sk = kdf32(&seed, "id-x25519");
    Identity { seed, owner_sk, owner_pub, id_x25519_sk, id_x25519_pub: x25519_pub(&id_x25519_sk) }
}

pub fn identity_from_mnemonic(phrase: &str) -> Result<Identity, Error> {
    Ok(identity_from_seed(seed_from_mnemonic(phrase)?))
}

#[derive(Clone, Debug)]
pub struct Prekey {
    pub spk_id: u32,
    pub x25519_sk: Key32,
    pub x25519_pub: Key32,
    pub mlkem_seed: [u8; 64],
    pub mlkem_pub: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

impl Prekey {
    pub fn from_parts(spk_id: u32, x25519_sk: Key32, mlkem_seed: [u8; 64]) -> Self {
        let (mlkem_pub, mlkem_sk) = mlkem::keygen(&mlkem_seed);
        Prekey { spk_id, x25519_sk, x25519_pub: x25519_pub(&x25519_sk), mlkem_seed, mlkem_pub, mlkem_sk }
    }
}

/// Signed prekey number `n` (the bundle's `spkId`).
pub fn prekey(seed: &[u8], n: u32) -> Prekey {
    let x25519_sk = kdf32_salt(seed, "spk-x25519", &u32be(n));
    let mut mlkem_seed = [0u8; 64];
    mlkem_seed.copy_from_slice(&kdf(seed, "spk-mlkem", 64, Some(&u32be(n))));
    Prekey::from_parts(n, x25519_sk, mlkem_seed)
}
