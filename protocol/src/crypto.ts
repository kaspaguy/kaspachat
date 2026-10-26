import { blake2b } from '@noble/hashes/blake2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';

export type Rand = (n: number) => Uint8Array;
export const systemRand: Rand = (n) => crypto.getRandomValues(new Uint8Array(n));

const enc = new TextEncoder();
const ZERO_NONCE = new Uint8Array(24);

export const utf8 = (s: string) => enc.encode(s);

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// Not constant-time: only ever compares public values (tags, public keys, offer IDs).
export const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

export const b2 = (data: Uint8Array, len = 32) => blake2b(data, { dkLen: len });

// Domain-separated HKDF-SHA-256; every label is prefixed "kasveil/v1/".
export const kdf = (ikm: Uint8Array, label: string, len = 32, salt?: Uint8Array) =>
  hkdf(sha256, ikm, salt, utf8(`kasveil/v1/${label}`), len);

export const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};
export const readU32 = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset).getUint32(o, false);

// Every AEAD key in Kaspaveil is used exactly once, so the nonce is fixed at zero.
export const seal = (key: Uint8Array, pt: Uint8Array, ad?: Uint8Array) => xchacha20poly1305(key, ZERO_NONCE, ad).encrypt(pt);
export function open(key: Uint8Array, ct: Uint8Array, ad?: Uint8Array): Uint8Array | null {
  try {
    return xchacha20poly1305(key, ZERO_NONCE, ad).decrypt(ct);
  } catch {
    return null;
  }
}

export const dh = (sk: Uint8Array, pub: Uint8Array) => x25519.getSharedSecret(sk, pub);
export function x25519Pair(rand: Rand) {
  const sk = rand(32);
  return { sk, pub: x25519.getPublicKey(sk) };
}

// Double-ratchet KDFs (Signal spec): root key step and chain key step.
export function kdfRoot(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = kdf(dhOut, 'root', 64, rk);
  return [out.slice(0, 32), out.slice(32)];
}
export function kdfChain(ck: Uint8Array): [Uint8Array, Uint8Array] {
  return [hmac(sha256, ck, new Uint8Array([0x02])), hmac(sha256, ck, new Uint8Array([0x01]))];
}

// Fixed-length content block: kind | u16 length | content | zero padding.
export function packBody(kind: number, content: Uint8Array, len: number): Uint8Array {
  if (content.length > len - 3) throw new Error(`content too long: ${content.length} > ${len - 3}`);
  const out = new Uint8Array(len);
  out[0] = kind;
  out[1] = content.length >> 8;
  out[2] = content.length & 0xff;
  out.set(content, 3);
  return out;
}
export function unpackBody(pt: Uint8Array): { kind: number; content: Uint8Array } | null {
  if (pt.length < 3) return null;
  const n = (pt[1] << 8) | pt[2];
  if (n > pt.length - 3 || pt.subarray(3 + n).some((b) => b !== 0)) return null;
  return { kind: pt[0], content: pt.slice(3, 3 + n) };
}
