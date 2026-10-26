// Proof of work for the doorman: find a nonce so that sha256(challenge || nonce) starts with `bits` zero bits.
import { sha256 } from '@noble/hashes/sha2.js';

self.onmessage = (e: MessageEvent<{ challenge: string; bits: number }>) => {
  const c = Uint8Array.from(e.data.challenge.match(/../g)!, (h) => parseInt(h, 16));
  const bits = e.data.bits;
  const te = new TextEncoder();
  const buf = new Uint8Array(c.length + 16);
  buf.set(c);
  for (let n = 0; ; n++) {
    const nonce = n.toString(16);
    const nb = te.encode(nonce);
    buf.set(nb, c.length);
    const h = sha256(buf.subarray(0, c.length + nb.length));
    let ok = true;
    for (let i = 0; i < bits && ok; i++) if ((h[i >> 3] >> (7 - (i & 7))) & 1) ok = false;
    if (ok) {
      (self as unknown as Worker).postMessage({ nonce });
      return;
    }
    if ((n & 0xffff) === 0) (self as unknown as Worker).postMessage({ progress: n });
  }
};
