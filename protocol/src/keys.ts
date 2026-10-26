import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { kdf, u32 } from './crypto.ts';

export type Identity = {
  seed: Uint8Array;
  ownerSk: Uint8Array;
  ownerPub: Uint8Array; // x-only secp256k1 Schnorr key, 32 bytes (checkable by Kaspa covenants)
  idXSk: Uint8Array;
  idXPub: Uint8Array;
};

export type SignedPrekey = {
  spkId: number;
  xSk: Uint8Array;
  xPub: Uint8Array;
  kemSk: Uint8Array;
  kemPub: Uint8Array;
};

function validScalar(seed: Uint8Array, label: string): Uint8Array {
  for (let i = 0; ; i++) {
    const k = kdf(seed, `${label}/${i}`);
    if (secp256k1.utils.isValidSecretKey(k)) return k;
  }
}

export function identityFromSeed(seed: Uint8Array): Identity {
  if (seed.length !== 64) throw new Error('seed must be 64 bytes');
  const ownerSk = validScalar(seed, 'owner');
  const idXSk = kdf(seed, 'id-x25519');
  return { seed, ownerSk, ownerPub: schnorr.getPublicKey(ownerSk), idXSk, idXPub: x25519.getPublicKey(idXSk) };
}

// 24-word BIP-39 recovery phrase (English wordlist, empty passphrase) -> 64-byte seed -> all keys.
// No recovery exists without the phrase.
export function identityFromMnemonic(mnemonic: string): Identity {
  if (mnemonic.normalize('NFKD').trim().split(/\s+/).length !== 24 || !validateMnemonic(mnemonic, wordlist)) throw new Error('not a valid 24-word phrase');
  return identityFromSeed(mnemonicToSeedSync(mnemonic, ''));
}

// Signed prekeys are derived from the seed by index, so a restored phrase can rebuild them.
export function signedPrekey(id: Identity, spkId: number): SignedPrekey {
  const xSk = kdf(id.seed, 'spk-x25519', 32, u32(spkId));
  const kem = ml_kem768.keygen(kdf(id.seed, 'spk-mlkem', 64, u32(spkId)));
  return { spkId, xSk, xPub: x25519.getPublicKey(xSk), kemSk: kem.secretKey, kemPub: kem.publicKey };
}
