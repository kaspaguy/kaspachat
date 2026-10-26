// Shared by the vector generator and the vector runner test: how sessions and named random inputs appear in
// vectors/v1.json. Everything here is test-harness format, not wire format (see the file's own "format" block).
import type { Rand } from '../src/crypto.ts';
import type { Session } from '../src/index.ts';

export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
export const unhex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const opt = (b: Uint8Array | null) => (b ? hex(b) : null);
const unopt = (h: string | null) => (h === null ? null : unhex(h));

export type SessionJson = ReturnType<typeof sessionToJson>;

export function sessionToJson(s: Session) {
  return {
    ad: hex(s.ad),
    initiator: s.initiator,
    root_key: hex(s.rk),
    our_ratchet_sk: hex(s.dhs.sk),
    our_ratchet_pub: hex(s.dhs.pub),
    their_ratchet_pub: opt(s.dhr),
    sending_chain_key: opt(s.cks),
    receiving_chain_key: opt(s.ckr),
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    tag_key_out: hex(s.tks),
    tag_key_in: hex(s.tkr),
    tag_out: s.tagOut,
    tag_in: s.tagIn,
    seen_in: [...s.seenIn],
    skipped: [...s.skipped].map(([k, mk]) => {
      const [pub, n] = k.split(':');
      return { their_ratchet_pub: pub, n: Number(n), message_key: hex(mk) };
    }),
    pq_epoch: s.pqEpoch,
    pq_offer: s.pqOffer && { epoch: s.pqOffer.epoch, mlkem_keygen_seed: hex(s.pqOffer.seed) },
    pq_secret: s.pqSecret && { epoch: s.pqSecret.epoch, shared_secret: hex(s.pqSecret.ss), mix_on_send: s.pqSecret.mixOnSend },
    tag_key_in_next: opt(s.tkrNext),
    previous_in: s.prevIn && { tag_key_in: hex(s.prevIn.tkr), tag_in: s.prevIn.tagIn, seen_in: [...s.prevIn.seenIn] },
  };
}

export function sessionFromJson(j: SessionJson): Session {
  return {
    ad: unhex(j.ad), initiator: j.initiator, rk: unhex(j.root_key),
    dhs: { sk: unhex(j.our_ratchet_sk), pub: unhex(j.our_ratchet_pub) },
    dhr: unopt(j.their_ratchet_pub), cks: unopt(j.sending_chain_key), ckr: unopt(j.receiving_chain_key),
    ns: j.ns, nr: j.nr, pn: j.pn, tks: unhex(j.tag_key_out), tkr: unhex(j.tag_key_in),
    tagOut: j.tag_out, tagIn: j.tag_in, seenIn: [...j.seen_in],
    skipped: new Map(j.skipped.map((e) => [`${e.their_ratchet_pub}:${e.n}`, unhex(e.message_key)])),
    pqEpoch: j.pq_epoch,
    pqOffer: j.pq_offer && { epoch: j.pq_offer.epoch, seed: unhex(j.pq_offer.mlkem_keygen_seed) },
    pqSecret: j.pq_secret && { epoch: j.pq_secret.epoch, ss: unhex(j.pq_secret.shared_secret), mixOnSend: j.pq_secret.mix_on_send },
    tkrNext: unopt(j.tag_key_in_next),
    prevIn: j.previous_in && { tkr: unhex(j.previous_in.tag_key_in), tagIn: j.previous_in.tag_in, seenIn: [...j.previous_in.seen_in] },
    pqMsgs: 0, pqAt: 0,
  };
}

// Records every random draw so the generator can publish it as a named input.
export class Recorder {
  draws: Uint8Array[] = [];
  inner: Rand;
  constructor(inner: Rand) {
    this.inner = inner;
  }
  rand: Rand = (n) => {
    const x = this.inner(n);
    this.draws.push(x);
    return x;
  };
  take(names: string[]): Record<string, string> {
    if (this.draws.length !== names.length) throw new Error(`expected ${names.length} random draws (${names}), got ${this.draws.length}`);
    const out = Object.fromEntries(names.map((n, i) => [n, hex(this.draws[i])]));
    this.draws = [];
    return out;
  }
}

// Replays named random inputs in the order the protocol consumes them (see the file's "format" block).
export function replay(values: string[]): Rand {
  let i = 0;
  return (n) => {
    const v = unhex(values[i++]);
    if (v.length !== n) throw new Error(`random input ${i - 1} has ${v.length} bytes, needed ${n}`);
    return v;
  };
}
