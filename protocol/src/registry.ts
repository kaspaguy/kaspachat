import { b2, concat } from './crypto.ts';

// Free default names (PROTOCOL_SPEC §3.4): "kv" + base32 (a–z, 2–7) of the first 40 bits of BLAKE2b-256(ownerPub || n), n one byte in 0..2.
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
export function defaultName(ownerPub: Uint8Array, n: number): string {
  if (n < 0 || n > 2) throw new Error('re-roll must be 0, 1 or 2');
  const h = b2(concat(ownerPub, new Uint8Array([n])));
  let v = 0n;
  for (const b of h.subarray(0, 5)) v = (v << 8n) | BigInt(b);
  let out = 'kv';
  for (let i = 7; i >= 0; i--) out += B32[Number((v >> BigInt(5 * i)) & 31n)];
  return out;
}
