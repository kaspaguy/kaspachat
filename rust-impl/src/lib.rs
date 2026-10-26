//! Kaspaveil v1 wire format — an independent implementation written from `WIRE_FORMAT.md`
//! and `PROTOCOL_SPEC.md` alone.

pub mod buckets;
pub mod bundle;
pub mod first_contact;
pub mod groups;
pub mod harness;
pub mod keys;
pub mod primitives;
pub mod random;
pub mod session;
pub mod settings;
pub mod transaction;

pub const PAYLOAD_LEN: usize = 1536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Payload or field has the wrong length or layout.
    Malformed,
    /// An X25519 result was all zero (low-order peer key), §1.
    LowOrderPoint,
    /// AEAD authentication failed.
    Aead,
    /// An ML-KEM encapsulation key failed the FIPS 203 §7.2 check.
    MlKemKey,
    InvalidKey,
    BadSignature,
    WrongOwner,
    Mnemonic,
    /// No watched tag matches.
    UnknownTag,
    /// More than 1,000 message keys would be skipped in one chain.
    TooManySkipped,
    /// Header `pqEpoch` fails the §4.5 receive rule.
    PqEpoch,
    /// First contact: prekey/`spkId`/registry/kind checks failed.
    FirstContact,
    /// Operation not allowed in the current state (e.g. offering while holding `SS`).
    State,
    /// Content too long for the body.
    TooLong,
    /// First contact whose tag was already opened (§4.2, replays): dropped, no state changed.
    Replay,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
