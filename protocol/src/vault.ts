// The device vault: everything secret an app keeps (identity, sessions, messages) is one AES-256-GCM blob, under a
// key derived from the device passcode with scrypt (N = 2^15, r = 8, p = 1). Nothing leaves the device unencrypted.
// Pure JavaScript (noble), not WebCrypto, so it also works where crypto.subtle is missing (.onion over http://).
import { scrypt } from '@noble/hashes/scrypt.js';
import { gcm } from '@noble/ciphers/aes.js';
import { systemRand } from './crypto.ts';
import type { Rand } from './crypto.ts';

export const VAULT_SCRYPT = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 };
export type SealedVault = { v: 2; salt: Uint8Array; iv: Uint8Array; ct: Uint8Array };

// JSON with Uint8Array, Map and bigint.
function enc(v: unknown): unknown {
  if (v instanceof Uint8Array) return { $u: btoa(String.fromCharCode(...v)) };
  if (v instanceof Map) return { $m: [...v].map(([k, x]) => [enc(k), enc(x)]) };
  if (typeof v === 'bigint') return { $b: v.toString() };
  if (Array.isArray(v)) return v.map(enc);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => [k, enc(x)]));
  return v;
}
function dec(v: any): any {
  if (Array.isArray(v)) return v.map(dec);
  if (v && typeof v === 'object') {
    if ('$u' in v) return Uint8Array.from(atob(v.$u), (c) => c.charCodeAt(0));
    if ('$m' in v) return new Map(v.$m.map(([k, x]: [any, any]) => [dec(k), dec(x)]));
    if ('$b' in v) return BigInt(v.$b);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)]));
  }
  return v;
}
export const pack = (v: unknown) => new TextEncoder().encode(JSON.stringify(enc(v)));
export const unpack = <T>(b: Uint8Array): T => dec(JSON.parse(new TextDecoder().decode(b)));

export const vaultKey = (pass: string, salt: Uint8Array) => scrypt(new TextEncoder().encode(pass), salt, VAULT_SCRYPT);

export function sealVault(key: Uint8Array, salt: Uint8Array, data: unknown, rand: Rand = systemRand): SealedVault {
  const iv = rand(12);
  return { v: 2, salt, iv, ct: gcm(key, iv).encrypt(pack(data)) };
}

// Throws if the passcode is wrong or the blob was altered.
export function openVault<T>(key: Uint8Array, rec: SealedVault): T {
  return unpack<T>(gcm(key, rec.iv).decrypt(rec.ct));
}
