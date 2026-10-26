import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  FC_INNER_PT_LEN, FC_SEALED_CT_LEN, FC_SEALED_PT_LEN, FC_TYPE, FIELD_LEN, KIND_GROUP_STATE, KIND_GROUP_TEXT, KIND_TEXT, MLKEM_CT_LEN, NAME_FIELD_LEN,
  PAYLOAD_LEN, TAG_LEN, VERSION,
} from './constants.ts';
import {
  b2, concat, dh, equal, hex, kdf, kdfChain, kdfRoot, open, packBody, readU32, seal, systemRand, u32, unpackBody, utf8, x25519Pair,
} from './crypto.ts';
import type { Rand } from './crypto.ts';
import type { Bundle } from './bundle.ts';
import type { Identity, SignedPrekey } from './keys.ts';
import { newSessionState } from './ratchet.ts';
import type { Session } from './ratchet.ts';
import { inboxBucket, withBucket } from './tags.ts';

// First contact (PQXDH-style): ver | tag | ephemeral X25519 | ML-KEM-768 ct | sealed.
// Routing uses classical X25519 (the tag); the sealed part, including who the sender is, needs
// both the X25519 and the ML-KEM secret, so it stays confidential against a future quantum attacker.

const fcTag = (dh2: Uint8Array, recipientIdXPub: Uint8Array) =>
  withBucket(b2(concat(utf8('kasveil/v1/fc-tag'), dh2), TAG_LEN), inboxBucket(recipientIdXPub));

// A first contact carries text, or a group message to a fellow member we have no session with yet.
const FC_KINDS = [KIND_TEXT, KIND_GROUP_STATE, KIND_GROUP_TEXT];

const pqxdh = (dh1: Uint8Array, dh2: Uint8Array, dh3: Uint8Array, ss: Uint8Array) =>
  kdf(concat(new Uint8Array(32).fill(0xff), dh1, dh2, dh3, ss), 'pqxdh');

export function nameField(name: string): Uint8Array {
  const b = utf8(name);
  if (b.length < 1 || b.length > NAME_FIELD_LEN - 1) throw new Error('bad name');
  const f = new Uint8Array(NAME_FIELD_LEN);
  f[0] = b.length;
  f.set(b, 1);
  return f;
}

export function buildFirstContact(
  me: Identity, myName: string, peer: Bundle, text: Uint8Array, rand: Rand = systemRand, now = Date.now(), kind = KIND_TEXT,
): { payload: Uint8Array; session: Session } {
  if (!FC_KINDS.includes(kind)) throw new Error('kind not allowed in a first contact');
  const eph = x25519Pair(rand);
  const dh1 = dh(me.idXSk, peer.spkXPub);
  const dh2 = dh(eph.sk, peer.idXPub);
  const dh3 = dh(eph.sk, peer.spkXPub);
  const { cipherText: kemCt, sharedSecret: ss } = ml_kem768.encapsulate(peer.spkKemPub, rand(32));
  const tag = fcTag(dh2, peer.idXPub);
  const sk = pqxdh(dh1, dh2, dh3, ss);
  const ad = concat(me.idXPub, peer.idXPub);

  const dhs = x25519Pair(rand);
  const [rk, ck0] = kdfRoot(sk, dh(dhs.sk, peer.spkXPub));
  const [cks, mk] = kdfChain(ck0);
  const innerCt = seal(mk, packBody(kind, text, FC_INNER_PT_LEN), concat(ad, dhs.pub));
  const sealedPt = concat(new Uint8Array([FC_TYPE]), nameField(myName), me.ownerPub, me.idXPub, u32(peer.spkId), dhs.pub, innerCt);
  if (sealedPt.length !== FC_SEALED_PT_LEN) throw new Error('first-contact layout');
  const sealedCt = seal(kdf(concat(dh2, ss), 'fc-outer'), sealedPt, tag);

  const session: Session = {
    ad, rk, dhs, dhr: peer.spkXPub, cks, ckr: null, ns: 1, nr: 0, pn: 0,
    tks: kdf(sk, 'tag-i2r'), tkr: kdf(sk, 'tag-r2i'), tagOut: 0, tagIn: 0, seenIn: [], skipped: new Map(),
    ...newSessionState(true, now),
  };
  return { payload: concat(new Uint8Array([VERSION]), tag, eph.pub, kemCt, sealedCt), session };
}

export type SenderRecord = { ownerPub: Uint8Array; idXPub: Uint8Array };

// Try a payload from the inbox bucket as a first contact. `lookup` resolves a sender name through the
// registry and returns its owner key and its bundle's identity key (bundle signature already checked).
export function openFirstContact(
  me: Identity, prekeys: SignedPrekey[], payload: Uint8Array, lookup: (name: string) => SenderRecord | null, rand: Rand = systemRand, now = Date.now(),
): { from: string; kind: number; text: Uint8Array; session: Session; spkId: number } | null {
  if (payload.length !== PAYLOAD_LEN || payload[0] !== VERSION) return null;
  let o = 1;
  const tag = payload.subarray(o, (o += TAG_LEN));
  const ephPub = payload.subarray(o, (o += FIELD_LEN));
  const kemCt = payload.subarray(o, (o += MLKEM_CT_LEN));
  const sealedCt = payload.subarray(o, o + FC_SEALED_CT_LEN);
  let dh2: Uint8Array;
  try {
    dh2 = dh(me.idXSk, ephPub);
  } catch {
    return null;
  }
  if (!equal(fcTag(dh2, me.idXPub), tag)) return null;

  for (const spk of prekeys) {
    const ss = ml_kem768.decapsulate(kemCt, spk.kemSk);
    const pt = open(kdf(concat(dh2, ss), 'fc-outer'), sealedCt, tag);
    if (!pt || pt[0] !== FC_TYPE) continue;
    let p = 1;
    const nameLen = pt[p];
    if (nameLen < 1 || nameLen > NAME_FIELD_LEN - 1) return null;
    const from = new TextDecoder().decode(pt.subarray(p + 1, p + 1 + nameLen));
    p += NAME_FIELD_LEN;
    const ownerPub = pt.slice(p, (p += 32));
    const theirIdX = pt.slice(p, (p += 32));
    const spkId = readU32(pt, p);
    p += 4;
    const theirRatchet = pt.slice(p, (p += 32));
    const innerCt = pt.subarray(p);
    const rec = lookup(from);
    if (spkId !== spk.spkId || !rec || !equal(rec.ownerPub, ownerPub) || !equal(rec.idXPub, theirIdX)) return null;

    // A peer key with an all-zero X25519 result (a low-order point) makes the whole first contact invalid.
    let sk: Uint8Array, rk: Uint8Array, ck0: Uint8Array;
    try {
      sk = pqxdh(dh(spk.xSk, theirIdX), dh2, dh(spk.xSk, ephPub), ss);
      [rk, ck0] = kdfRoot(sk, dh(spk.xSk, theirRatchet));
    } catch {
      return null;
    }
    const ad = concat(theirIdX, me.idXPub);
    const [ckr, mk] = kdfChain(ck0);
    const inner = open(mk, innerCt, concat(ad, theirRatchet));
    const body = inner && unpackBody(inner);
    if (!body || !FC_KINDS.includes(body.kind)) return null;

    const session: Session = {
      ad, rk, dhs: { sk: spk.xSk, pub: spk.xPub }, dhr: theirRatchet, cks: null, ckr, ns: 0, nr: 1, pn: 0,
      tks: kdf(sk, 'tag-r2i'), tkr: kdf(sk, 'tag-i2r'), tagOut: 0, tagIn: 0, seenIn: [], skipped: new Map(),
      ...newSessionState(false, now),
    };
    session.dhs = x25519Pair(rand);
    [session.rk, session.cks] = kdfRoot(session.rk, dh(session.dhs.sk, theirRatchet));
    return { from, kind: body.kind, text: body.content, session, spkId };
  }
  return null;
}

// Crossing first contacts (WIRE_FORMAT §4.2): both peers keep the session whose first-contact tag is lower
// (bytewise, unsigned). The other is receive-only for 7 days, then discarded.
export function crossingKeeps(sentTag: Uint8Array, receivedTag: Uint8Array): 'sent' | 'received' {
  for (let i = 0; i < TAG_LEN; i++) if (sentTag[i] !== receivedTag[i]) return sentTag[i] < receivedTag[i] ? 'sent' : 'received';
  throw new Error('identical first-contact tags');
}

// Our first contact to this peer is still pending: we initiated the session and have received nothing on it.
export const pendingFirstContact = (s: Session) => s.initiator && s.ckr === null;

// A first contact from a peer we already hold a session with (WIRE_FORMAT §4.2). Only a crossing (ours still
// pending) uses the lower-tag rule; anything else is a re-contact and the new session replaces ours. The session
// not kept becomes receive-only for 7 days.
export function onFirstContactFromKnownPeer(current: Session, currentFirstContactTag: Uint8Array, receivedTag: Uint8Array): 'keep-current' | 'use-new' {
  if (!pendingFirstContact(current)) return 'use-new';
  return crossingKeeps(currentFirstContactTag, receivedTag) === 'sent' ? 'keep-current' : 'use-new';
}

// Tags of the first contacts already opened, each with the prekey that opened it (WIRE_FORMAT §4.2, replays).
export type SeenFirstContacts = Map<string, number>;
const tagHex = (payload: Uint8Array) => hex(payload.subarray(1, 1 + TAG_LEN));

// openFirstContact plus the replay rule: a tag already opened is dropped ('replay') without touching any state.
// Only a first contact that opens is remembered, so a forged payload copying a genuine tag can't get it dropped.
export function receiveFirstContact(
  seen: SeenFirstContacts, me: Identity, prekeys: SignedPrekey[], payload: Uint8Array, lookup: (name: string) => SenderRecord | null,
  rand: Rand = systemRand, now = Date.now(),
): ReturnType<typeof openFirstContact> | 'replay' {
  const t = tagHex(payload);
  if (seen.has(t)) return 'replay';
  const got = openFirstContact(me, prekeys, payload, lookup, rand, now);
  if (got) seen.set(t, got.spkId);
  return got;
}

// A prekey rotated out: first contacts it opened can't be decrypted any more, so their tags are forgotten.
export function forgetPrekey(seen: SeenFirstContacts, spkId: number) {
  for (const [t, id] of seen) if (id === spkId) seen.delete(t);
}

// Cover traffic: indistinguishable from real messages, readable by nobody.
export const coverPayload = (rand: Rand = systemRand) => concat(new Uint8Array([VERSION]), rand(PAYLOAD_LEN - 1));

// A dummy first contact into an inbox bucket (WIRE_FORMAT §4.4): shaped like §4.2, readable by nobody.
export const coverFirstContact = (bucket: number, rand: Rand = systemRand) =>
  concat(new Uint8Array([VERSION]), withBucket(rand(TAG_LEN), bucket), x25519Pair(rand).pub, rand(PAYLOAD_LEN - 1 - TAG_LEN - FIELD_LEN));
