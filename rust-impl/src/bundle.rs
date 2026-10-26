//! WIRE_FORMAT §3 (key bundle) and §4.3 (bundle publication).

use crate::primitives::{blake2b, blake2b_128, mlkem, schnorr_sign, schnorr_verify, to32, Key32};
use crate::{Error, PAYLOAD_LEN};

pub const BUNDLE_BASE_LEN: usize = 1358;
pub const MAX_DEVICES: usize = 4;
const UNSIGNED_BASE_LEN: usize = BUNDLE_BASE_LEN - 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub owner_pub: Key32,
    pub id_x25519_pub: Key32,
    pub spk_id: u32,
    pub spk_x25519_pub: Key32,
    pub spk_mlkem_pub: Vec<u8>,
    pub created: u64,
    pub devices: Vec<Key32>,
    pub signature: [u8; 64],
}

impl Bundle {
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(UNSIGNED_BASE_LEN + 32 * self.devices.len());
        v.push(1);
        v.extend_from_slice(&self.owner_pub);
        v.extend_from_slice(&self.id_x25519_pub);
        v.extend_from_slice(&self.spk_id.to_be_bytes());
        v.extend_from_slice(&self.spk_x25519_pub);
        v.extend_from_slice(&self.spk_mlkem_pub);
        v.extend_from_slice(&self.created.to_be_bytes());
        v.push(self.devices.len() as u8);
        for d in &self.devices {
            v.extend_from_slice(d);
        }
        v
    }

    pub fn digest(unsigned: &[u8]) -> Key32 {
        blake2b(&[b"kasveil/v1/bundle", unsigned])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        owner_sk: &Key32,
        owner_pub: Key32,
        id_x25519_pub: Key32,
        spk_id: u32,
        spk_x25519_pub: Key32,
        spk_mlkem_pub: Vec<u8>,
        created: u64,
        devices: Vec<Key32>,
        aux: &Key32,
    ) -> Result<Bundle, Error> {
        if devices.len() > MAX_DEVICES || spk_mlkem_pub.len() != mlkem::PUB_LEN {
            return Err(Error::Malformed);
        }
        let mut b = Bundle { owner_pub, id_x25519_pub, spk_id, spk_x25519_pub, spk_mlkem_pub, created, devices, signature: [0; 64] };
        b.signature = schnorr_sign(owner_sk, &Self::digest(&b.unsigned_bytes()), aux)?;
        Ok(b)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.unsigned_bytes();
        v.extend_from_slice(&self.signature);
        v
    }

    /// Parses a bundle at the start of `b`; returns it and its length (from `nDevices`).
    /// Does not verify the signature.
    pub fn parse_prefix(b: &[u8]) -> Result<(Bundle, usize), Error> {
        if b.len() < BUNDLE_BASE_LEN || b[0] != 1 {
            return Err(Error::Malformed);
        }
        let nd_off = 1 + 32 + 32 + 4 + 32 + mlkem::PUB_LEN + 8;
        let nd = b[nd_off] as usize;
        if nd > MAX_DEVICES {
            return Err(Error::Malformed);
        }
        let len = BUNDLE_BASE_LEN + 32 * nd;
        if b.len() < len {
            return Err(Error::Malformed);
        }
        let devices = (0..nd).map(|i| to32(&b[nd_off + 1 + 32 * i..])).collect();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&b[len - 64..len]);
        let bundle = Bundle {
            owner_pub: to32(&b[1..]),
            id_x25519_pub: to32(&b[33..]),
            spk_id: u32::from_be_bytes(b[65..69].try_into().unwrap()),
            spk_x25519_pub: to32(&b[69..]),
            spk_mlkem_pub: b[101..101 + mlkem::PUB_LEN].to_vec(),
            created: u64::from_be_bytes(b[nd_off - 8..nd_off].try_into().unwrap()),
            devices,
            signature,
        };
        Ok((bundle, len))
    }

    pub fn verify_signature(&self) -> bool {
        schnorr_verify(&self.owner_pub, &Self::digest(&self.unsigned_bytes()), &self.signature)
    }

    /// A standalone bundle: exactly `1,358 + 32 × nDevices` bytes, signed by `expected_owner`
    /// (the owner key the registry maps the name to).
    pub fn accept(b: &[u8], expected_owner: &Key32) -> Result<Bundle, Error> {
        let (bundle, len) = Self::parse_prefix(b)?;
        if len != b.len() {
            return Err(Error::Malformed);
        }
        if &bundle.owner_pub != expected_owner {
            return Err(Error::WrongOwner);
        }
        if !bundle.verify_signature() {
            return Err(Error::BadSignature);
        }
        // §3: a bundle whose ML-KEM key fails the FIPS 203 check is invalid, even if correctly signed.
        mlkem::check_pub(&bundle.spk_mlkem_pub)?;
        Ok(bundle)
    }
}

pub fn bundle_tag(owner_pub: &Key32) -> [u8; 16] {
    blake2b_128(&[b"kasveil/v1/bundle-tag", owner_pub])
}

pub fn bundle_marker() -> Key32 {
    blake2b(&[b"kasveil/v1/bundle-marker"])
}

/// §4.3 publication payload.
pub fn publication_payload(bundle: &[u8]) -> Result<Vec<u8>, Error> {
    let (b, len) = Bundle::parse_prefix(bundle)?;
    if len != bundle.len() {
        return Err(Error::Malformed);
    }
    let mut p = Vec::with_capacity(PAYLOAD_LEN);
    p.push(1);
    p.extend_from_slice(&bundle_tag(&b.owner_pub));
    p.extend_from_slice(&bundle_marker());
    p.extend_from_slice(bundle);
    p.resize(PAYLOAD_LEN, 0);
    Ok(p)
}

/// Indexer/client side of §4.3: a publication is used only if the marker, the tag and the
/// signature all check out. Padding after the bundle is ignored.
pub fn parse_publication(p: &[u8]) -> Result<Bundle, Error> {
    if p.len() != PAYLOAD_LEN || p[0] != 1 || p[17..49] != bundle_marker() {
        return Err(Error::Malformed);
    }
    let (b, _) = Bundle::parse_prefix(&p[49..])?;
    if p[1..17] != bundle_tag(&b.owner_pub) {
        return Err(Error::Malformed);
    }
    if !b.verify_signature() {
        return Err(Error::BadSignature);
    }
    mlkem::check_pub(&b.spk_mlkem_pub)?;
    Ok(b)
}

/// "The current bundle": highest `created`, ties highest `spkId`; more than 24 h in the future ignored.
pub fn current_bundle(valid: &[Bundle], now: u64) -> Option<&Bundle> {
    valid.iter().filter(|b| b.created <= now + 24 * 3600).max_by_key(|b| (b.created, b.spk_id))
}
