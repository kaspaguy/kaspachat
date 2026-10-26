import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  BODY_CT_LEN, BODY_PT_LEN, FIELD_LEN, HEADER_CT_LEN, HEADER_PT_LEN, KIND_KEM_STEP, MAX_SKIP, MLKEM_CT_LEN, MLKEM_PK_LEN,
  PAYLOAD_LEN, TAG_LEN, TAG_WINDOW, VERSION,
} from './constants.ts';
import {
  b2, concat, dh, equal, hex, kdf, kdfChain, kdfRoot, open, packBody, readU32, seal, systemRand, u32, unpackBody, x25519Pair,
} from './crypto.ts';
import type { Rand } from './crypto.ts';
import { chainTag, headerKey } from './tags.ts';

// Double ratchet (Signal spec) with Kaspaveil routing: every message carries a fresh tag from a
// per-direction tag chain, and its header is encrypted under a key tied to that tag index.
// On top runs a post-quantum KEM ratchet (body kind 0x05, WIRE_FORMAT.md §4.5): an ML-KEM-768
// offer/answer whose shared secret is mixed into the root key and re-keys both tag chains.
export type InChain = { tkr: Uint8Array; tagIn: number; seenIn: number[] };

export type Session = {
  ad: Uint8Array; // initiator idXPub || responder idXPub
  initiator: boolean;
  rk: Uint8Array;
  dhs: { sk: Uint8Array; pub: Uint8Array };
  dhr: Uint8Array | null;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number;
  nr: number;
  pn: number;
  tks: Uint8Array; // outgoing tag key
  tkr: Uint8Array; // incoming tag key
  tagOut: number; // next outgoing tag index
  tagIn: number; // lowest incoming tag index not yet received
  seenIn: number[]; // received indices above tagIn
  skipped: Map<string, Uint8Array>;
  skippedAt?: Map<string, number>; // when each skipped key was stored (ms); local only, not part of the vector harness
  pqEpoch: number; // latest KEM epoch mixed into the root key
  pqOffer: { epoch: number; seed: Uint8Array } | null; // our outstanding offer
  pqSecret: { epoch: number; ss: Uint8Array; mixOnSend: boolean } | null; // agreed, not yet mixed into the root key
  tkrNext: Uint8Array | null; // the peer's re-keyed tag chain, watched once the KEM secret is known
  prevIn: InChain | null; // the peer's previous tag chain, still watched for late messages
  pqMsgs: number; // messages since the last KEM step started
  pqAt: number; // when the last KEM step started (ms)
};

export const KEM_OFFER = 0x01;
export const KEM_ANSWER = 0x02;
export const KEM_EVERY_MSGS = 50;
export const KEM_EVERY_MS = 24 * 3600 * 1000;
export const SKIPPED_KEY_TTL_MS = 7 * 24 * 3600 * 1000; // the delivery window
const OFFER_ID_LEN = 16;
const OFFER_LEN = 1 + 4 + MLKEM_PK_LEN; // 1,189
const ANSWER_LEN = 1 + 4 + OFFER_ID_LEN + MLKEM_CT_LEN; // 1,109

const clone = (s: Session): Session => structuredClone(s);
const offerId = (pk: Uint8Array) => b2(concat(new TextEncoder().encode('kasveil/v1/kem-offer'), pk), OFFER_ID_LEN);
const pqTagKey = (tk: Uint8Array, ss: Uint8Array) => kdf(concat(tk, ss), 'pq-tag');
// Root step that also absorbs a KEM secret; a separate label keeps it apart from the plain DH step.
function kdfRootPq(rk: Uint8Array, dhOut: Uint8Array, ss: Uint8Array): [Uint8Array, Uint8Array] {
  const out = kdf(concat(dhOut, ss), 'root-pq', 64, rk);
  return [out.slice(0, 32), out.slice(32)];
}

export function newSessionState(initiator: boolean, now: number) {
  return { initiator, pqEpoch: 0, pqOffer: null, pqSecret: null, tkrNext: null, prevIn: null, pqMsgs: 0, pqAt: now };
}

type Watch = { index: number; tag: Uint8Array; chain: 'cur' | 'next' | 'prev' };

function watch(tkr: Uint8Array, tagIn: number, seenIn: number[], chain: Watch['chain']): Watch[] {
  const out = [];
  for (let i = tagIn; i < tagIn + TAG_WINDOW; i++) if (!seenIn.includes(i)) out.push({ index: i, tag: chainTag(tkr, i), chain });
  return out;
}

// Tags this session is currently watching for, with their tag-chain index.
export function expectedTags(s: Session): Watch[] {
  const out = watch(s.tkr, s.tagIn, s.seenIn, 'cur');
  if (s.tkrNext) out.push(...watch(s.tkrNext, 0, [], 'next'));
  if (s.prevIn) out.push(...watch(s.prevIn.tkr, s.prevIn.tagIn, s.prevIn.seenIn, 'prev'));
  return out;
}

export function encrypt(s: Session, kind: number, content: Uint8Array, rand: Rand = systemRand): Uint8Array {
  if (!s.cks) throw new Error('no sending chain');
  const [cks, mk] = kdfChain(s.cks);
  s.cks = cks;
  const header = new Uint8Array(HEADER_PT_LEN);
  header.set(s.dhs.pub, 0);
  header.set(u32(s.pn), 32);
  header.set(u32(s.ns), 36);
  header.set(u32(s.pqEpoch), 41);
  s.ns++;
  s.pqMsgs++;
  const i = s.tagOut++;
  const tag = chainTag(s.tks, i);
  const hct = seal(headerKey(s.tks, i), header, tag);
  const bct = seal(mk, packBody(kind, content, BODY_PT_LEN), concat(s.ad, hct));
  return concat(new Uint8Array([VERSION]), tag, rand(FIELD_LEN), hct, bct);
}

function skipTo(s: Session, until: number, now: number) {
  if (!s.ckr || !s.dhr) return;
  if (until - s.nr > MAX_SKIP) throw new Error('too many skipped messages');
  while (s.nr < until) {
    const [ckr, mk] = kdfChain(s.ckr);
    s.ckr = ckr;
    s.skipped.set(`${hex(s.dhr)}:${s.nr}`, mk);
    (s.skippedAt ??= new Map()).set(`${hex(s.dhr)}:${s.nr}`, now);
    s.nr++;
  }
}

function switchSendTags(s: Session, ss: Uint8Array) {
  s.tks = pqTagKey(s.tks, ss);
  s.tagOut = 0;
}

// The KEM secret enters the root key exactly once, at a step both sides can identify: the first
// sending chain the decapsulating side creates after it learns the secret. Its header announces the
// new epoch, and the encapsulating side mixes the same secret into the matching receiving step.
export function ratchetStep(s: Session, theirPub: Uint8Array, theirPq: number, rand: Rand) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = theirPub;
  if (theirPq !== s.pqEpoch) {
    const p = s.pqSecret;
    if (theirPq !== s.pqEpoch + 1 || !p || p.epoch !== theirPq || p.mixOnSend) throw new Error('KEM epoch mismatch');
    [s.rk, s.ckr] = kdfRootPq(s.rk, dh(s.dhs.sk, s.dhr), p.ss);
    s.pqEpoch = p.epoch;
    s.pqSecret = null;
    switchSendTags(s, p.ss);
  } else {
    [s.rk, s.ckr] = kdfRoot(s.rk, dh(s.dhs.sk, s.dhr));
  }
  s.dhs = x25519Pair(rand);
  const p = s.pqSecret;
  if (p?.mixOnSend) {
    [s.rk, s.cks] = kdfRootPq(s.rk, dh(s.dhs.sk, s.dhr), p.ss);
    s.pqEpoch = p.epoch;
    s.pqSecret = null;
    switchSendTags(s, p.ss);
  } else {
    [s.rk, s.cks] = kdfRoot(s.rk, dh(s.dhs.sk, s.dhr));
  }
}

// Whether this side should start a KEM step now: at least every 50 messages or every 24 hours.
export const kemStepDue = (s: Session, now = Date.now()) =>
  !s.pqOffer && !s.pqSecret && (s.pqMsgs >= KEM_EVERY_MSGS || now - s.pqAt >= KEM_EVERY_MS);

// Starts a KEM step: returns the content of a kind-0x05 message to send with encrypt().
// Calling it again before an answer arrives replaces the offer (e.g. after a lost message).
export function kemOffer(s: Session, rand: Rand = systemRand, now = Date.now()): Uint8Array {
  if (s.pqSecret) throw new Error('previous KEM step not finished');
  const seed = rand(64);
  const epoch = s.pqEpoch + 1;
  s.pqOffer = { epoch, seed };
  s.pqMsgs = 0;
  s.pqAt = now;
  return concat(new Uint8Array([KEM_OFFER]), u32(epoch), ml_kem768.keygen(seed).publicKey);
}

// Handles a received kind-0x05 body; returns the answer content to send back, if any. A stale or
// malformed step is ignored, but the message itself still counts as received (so its tag never stalls the window).
function kemReceive(s: Session, c: Uint8Array, rand: Rand, now: number): Uint8Array | null {
  const epoch = c.length >= 5 ? readU32(c, 1) : -1;
  if (c[0] === KEM_OFFER && c.length === OFFER_LEN) {
    if (epoch !== s.pqEpoch + 1 || s.pqSecret?.mixOnSend) return null;
    if (s.pqOffer && s.initiator) return null; // both offered at once: the initiator's offer wins, theirs is dropped
    const pk = c.slice(5);
    let enc: { cipherText: Uint8Array; sharedSecret: Uint8Array };
    try {
      enc = ml_kem768.encapsulate(pk, rand(32)); // FIPS 203 input check: a malformed key is a malformed step
    } catch {
      return null; // changes no state: a responder's own pending offer is kept
    }
    s.pqOffer = null;
    const { cipherText, sharedSecret } = enc;
    s.pqSecret = { epoch, ss: sharedSecret, mixOnSend: false };
    s.tkrNext = pqTagKey(s.tkr, sharedSecret);
    s.pqMsgs = 0;
    s.pqAt = now;
    return concat(new Uint8Array([KEM_ANSWER]), u32(epoch), offerId(pk), cipherText);
  }
  if (c[0] === KEM_ANSWER && c.length === ANSWER_LEN) {
    const o = s.pqOffer;
    if (!o || epoch !== o.epoch) return null;
    const { publicKey, secretKey } = ml_kem768.keygen(o.seed);
    if (!equal(c.subarray(5, 5 + OFFER_ID_LEN), offerId(publicKey))) return null; // answer to a replaced offer
    const ss = ml_kem768.decapsulate(c.subarray(5 + OFFER_ID_LEN), secretKey);
    s.pqSecret = { epoch, ss, mixOnSend: true };
    s.pqOffer = null;
    s.tkrNext = pqTagKey(s.tkr, ss);
    return null;
  }
  return null;
}

// Deletes skipped message keys stored more than 7 days ago (WIRE_FORMAT §4.1). decrypt() calls it; apps may too.
export function expireSkipped(s: Session, now = Date.now()) {
  for (const [k, at] of s.skippedAt ?? []) {
    if (now - at >= SKIPPED_KEY_TTL_MS) {
      s.skipped.delete(k);
      s.skippedAt!.delete(k);
    }
  }
}

export type Decrypted = { kind: number; content: Uint8Array; kemAnswer?: Uint8Array };

// Returns null (and leaves the session untouched) if the payload isn't for this session or fails to authenticate.
// If the result carries kemAnswer, send it back as a kind-0x05 message: encrypt(session, KIND_KEM_STEP, kemAnswer).
export function decrypt(session: Session, payload: Uint8Array, rand: Rand = systemRand, now = Date.now()): Decrypted | null {
  expireSkipped(session, now);
  if (payload.length !== PAYLOAD_LEN || payload[0] !== VERSION) return null;
  const tag = payload.subarray(1, 1 + TAG_LEN);
  const match = expectedTags(session).find((e) => equal(e.tag, tag));
  if (!match) return null;
  const tkr = match.chain === 'cur' ? session.tkr : match.chain === 'next' ? session.tkrNext! : session.prevIn!.tkr;
  const o = 1 + TAG_LEN + FIELD_LEN;
  const hct = payload.subarray(o, o + HEADER_CT_LEN);
  const bct = payload.subarray(o + HEADER_CT_LEN, o + HEADER_CT_LEN + BODY_CT_LEN);
  const header = open(headerKey(tkr, match.index), hct, tag);
  if (!header) return null;
  const theirPub = header.slice(0, 32);
  const pn = readU32(header, 32);
  const n = readU32(header, 36);
  const theirPq = readU32(header, 41);

  const s = clone(session);
  let mk = s.skipped.get(`${hex(theirPub)}:${n}`);
  if (mk) {
    s.skipped.delete(`${hex(theirPub)}:${n}`);
    s.skippedAt?.delete(`${hex(theirPub)}:${n}`);
  }
  else {
    try {
      if (!s.dhr || !equal(theirPub, s.dhr)) {
        skipTo(s, pn, now);
        ratchetStep(s, theirPub, theirPq, rand);
      }
      skipTo(s, n, now);
    } catch {
      return null;
    }
    const [ckr, k] = kdfChain(s.ckr!);
    s.ckr = ckr;
    s.nr++;
    mk = k;
  }
  const pt = open(mk, bct, concat(s.ad, hct));
  const body = pt && unpackBody(pt);
  if (!body) return null;

  const result: Decrypted = body;
  if (body.kind === KIND_KEM_STEP) {
    const answer = kemReceive(s, body.content, rand, now);
    if (answer) result.kemAnswer = answer;
  }

  // The first message on the peer's re-keyed chain retires the old chain to "previous".
  if (match.chain === 'next') {
    s.prevIn = { tkr: s.tkr, tagIn: s.tagIn, seenIn: s.seenIn };
    s.tkr = s.tkrNext!;
    s.tagIn = 0;
    s.seenIn = [];
    s.tkrNext = null;
  }
  const chain: InChain = match.chain === 'prev' ? s.prevIn! : s;
  chain.seenIn.push(match.index);
  while (chain.seenIn.includes(chain.tagIn)) {
    chain.seenIn.splice(chain.seenIn.indexOf(chain.tagIn), 1);
    chain.tagIn++;
  }
  s.pqMsgs++;
  Object.assign(session, s);
  return result;
}
