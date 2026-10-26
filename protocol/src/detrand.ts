import { b2, concat, utf8 } from './crypto.ts';
import type { Rand } from './crypto.ts';

// Deterministic "randomness" for test vectors only. Never use for real keys or messages.
export function detRand(label: string): Rand {
  let ctr = 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += 64) out.set(b2(concat(utf8(label), new Uint8Array([ctr >> 8, ctr++ & 0xff])), 64).subarray(0, n - o), o);
    return out;
  };
}
