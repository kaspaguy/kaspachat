import { test } from 'node:test';
import assert from 'node:assert/strict';
import { utf8 } from '../src/crypto.ts';
import type { Rand } from '../src/crypto.ts';
import { detRand } from '../src/detrand.ts';
import {
  KEM_EVERY_MS, KIND_KEM_STEP, KIND_TEXT, buildFirstContact, decrypt, encrypt, expectedTags, identityFromSeed, kemOffer,
  kemStepDue, makeBundle, openFirstContact, parseBundle, signedPrekey,
} from '../src/index.ts';
import type { Session } from '../src/index.ts';

const str = (b: Uint8Array) => new TextDecoder().decode(b);

function pair(label: string, rbOverride?: Rand) {
  const alice = identityFromSeed(detRand('alice-seed')(64));
  const bob = identityFromSeed(detRand('bob-seed')(64));
  const bobSpk = signedPrekey(bob, 7);
  const bundle = parseBundle(makeBundle(bob, bobSpk, 1n), bob.ownerPub)!;
  const lookup = (n: string) => (n === 'alice-21' ? { ownerPub: alice.ownerPub, idXPub: alice.idXPub } : null);
  const ra = detRand(`${label}-a`), rb = rbOverride ?? detRand(`${label}-b`);
  const fc = buildFirstContact(alice, 'alice-21', bundle, utf8('hi'), ra, 0);
  const B = openFirstContact(bob, [bobSpk], fc.payload, lookup, rb, 0)!.session;
  return { A: fc.session, B, ra, rb };
}

// Sends one message and delivers it; if the receiver owes a KEM answer, returns it (undelivered).
function send(from: Session, to: Session, rf: Rand, rt: Rand, msg: string) {
  const p = encrypt(from, KIND_TEXT, utf8(msg), rf);
  const d = decrypt(to, p, rt, 0);
  assert.ok(d, `decrypt "${msg}"`);
  assert.equal(str(d.content), msg);
  return p;
}

// Runs a full KEM step started by `from`, then enough traffic for both sides to mix it in.
function kemStep(from: Session, to: Session, rf: Rand, rt: Rand) {
  const offer = encrypt(from, KIND_KEM_STEP, kemOffer(from, rf, 0), rf);
  const got = decrypt(to, offer, rt, 0)!;
  assert.ok(got.kemAnswer, 'offer answered');
  const answer = encrypt(to, KIND_KEM_STEP, got.kemAnswer, rt);
  assert.ok(decrypt(from, answer, rf, 0), 'answer received');
  for (let i = 0; i < 2; i++) {
    send(from, to, rf, rt, `after step ${i}`);
    send(to, from, rt, rf, `reply ${i}`);
  }
}

test('KEM step: both sides reach the new epoch, both tag chains re-keyed, conversation continues', () => {
  const { A, B, ra, rb } = pair('k1');
  send(B, A, rb, ra, 'hey');
  const tksA = A.tks, tksB = B.tks;
  kemStep(A, B, ra, rb);
  for (const s of [A, B]) {
    assert.equal(s.pqEpoch, 1);
    assert.equal(s.pqSecret, null, 'KEM secret deleted once mixed in');
    assert.equal(s.pqOffer, null);
    assert.equal(s.tkrNext, null, 'both sides moved onto the re-keyed chains');
  }
  assert.notDeepEqual(A.tks, tksA);
  assert.notDeepEqual(B.tks, tksB);
  assert.deepEqual(A.tks, B.tkr);
  assert.deepEqual(B.tks, A.tkr);
  kemStep(B, A, rb, ra); // the responder can start the next one
  assert.equal(A.pqEpoch, 2);
  assert.equal(B.pqEpoch, 2);
  send(A, B, ra, rb, 'still talking');
});

// A "harvest now, decrypt later" attacker with a quantum computer: she knows every X25519 secret
// (modelled by replaying Bob's randomness into a copy of Bob's session) but not the ML-KEM secret.
test('KEM step heals against an attacker who has broken X25519', () => {
  const draws: Uint8Array[] = [];
  const base = detRand('k2-b');
  const rb: Rand = (n) => {
    const x = base(n);
    draws.push(x);
    return x;
  };
  const { A, B, ra } = pair('k2', rb);
  const start = draws.length;
  const snapshot = structuredClone(B);
  const log: (['dec', Uint8Array] | ['enc', Uint8Array, Uint8Array, number])[] = [];
  let encapsDraw = -1;
  const toB = (p: Uint8Array) => {
    const d = decrypt(B, p, rb, 0);
    log.push(['dec', p]);
    if (d?.kemAnswer) encapsDraw = draws.length - 1; // the last draw of this call is ML-KEM's encapsulation randomness
    return d;
  };
  const fromB = (kind: number, c: Uint8Array) => {
    const p = encrypt(B, kind, c, rb);
    log.push(['enc', p, c, kind]);
    return p;
  };

  decrypt(A, fromB(KIND_TEXT, utf8('hey')), ra, 0);
  const pre = encrypt(A, KIND_TEXT, utf8('before the step'), ra);
  toB(pre);
  const answer = toB(encrypt(A, KIND_KEM_STEP, kemOffer(A, ra, 0), ra))!.kemAnswer!;
  decrypt(A, fromB(KIND_KEM_STEP, answer), ra, 0);
  const msgs = ['a1', 'a2', 'a3'];
  for (const m of msgs) {
    toB(encrypt(A, KIND_TEXT, utf8(m), ra));
    decrypt(A, fromB(KIND_TEXT, utf8(`re ${m}`)), ra, 0);
  }
  assert.equal(B.pqEpoch, 1);

  const replay = (breakKem: boolean) => {
    const eve = structuredClone(snapshot);
    let k = start;
    const r: Rand = (n) => {
      const x = draws[k].slice();
      if (breakKem && k === encapsDraw) x[0] ^= 1; // she can't know the ML-KEM secret
      k++;
      assert.equal(x.length, n);
      return x;
    };
    const read: string[] = [];
    for (const e of log) {
      if (e[0] === 'dec') {
        const d = decrypt(eve, e[1], r, 0);
        read.push(d ? (d.kind === KIND_TEXT ? str(d.content) : 'kem') : '✗');
      } else {
        const p = encrypt(eve, e[3], e[2], r);
        read.push(Buffer.compare(Buffer.from(p.subarray(49)), Buffer.from(e[1].subarray(49))) === 0 ? 'same' : 'differs');
      }
    }
    return read;
  };
  // Control: with the ML-KEM secret too, the copy follows everything (so the model is faithful).
  assert.deepEqual(replay(false), ['same', 'before the step', 'kem', 'same', 'a1', 'same', 'a2', 'same', 'a3', 'same']);
  // Without it: she reads up to the step, then loses the conversation for good, both directions.
  const eve = replay(true);
  assert.deepEqual(eve.slice(0, 5), ['same', 'before the step', 'kem', 'same', 'a1']);
  assert.deepEqual(eve.slice(-4), ['✗', 'differs', '✗', 'differs']);
});

test('offers that cross: the initiator\'s wins, both still end on the same epoch', () => {
  const { A, B, ra, rb } = pair('k3');
  send(B, A, rb, ra, 'hey');
  const offerA = encrypt(A, KIND_KEM_STEP, kemOffer(A, ra, 0), ra);
  const offerB = encrypt(B, KIND_KEM_STEP, kemOffer(B, rb, 0), rb);
  assert.equal(decrypt(A, offerB, ra, 0)!.kemAnswer, undefined, 'initiator ignores the crossing offer');
  const got = decrypt(B, offerA, rb, 0)!;
  assert.ok(got.kemAnswer, 'responder drops its own offer and answers');
  assert.equal(B.pqOffer, null);
  decrypt(A, encrypt(B, KIND_KEM_STEP, got.kemAnswer, rb), ra, 0);
  for (let i = 0; i < 2; i++) {
    send(A, B, ra, rb, `x${i}`);
    send(B, A, rb, ra, `y${i}`);
  }
  assert.equal(A.pqEpoch, 1);
  assert.equal(B.pqEpoch, 1);
});

test('lost answer: a re-offer replaces it, and the late original answer is ignored safely', () => {
  const { A, B, ra, rb } = pair('k4');
  send(B, A, rb, ra, 'hey');
  const first = decrypt(B, encrypt(A, KIND_KEM_STEP, kemOffer(A, ra, 0), ra), rb, 0)!.kemAnswer!;
  const lateAnswer = encrypt(B, KIND_KEM_STEP, first, rb); // not delivered yet
  const second = decrypt(B, encrypt(A, KIND_KEM_STEP, kemOffer(A, ra, 0), ra), rb, 0)!.kemAnswer!;
  assert.ok(decrypt(A, encrypt(B, KIND_KEM_STEP, second, rb), ra, 0));
  assert.equal(A.pqSecret?.mixOnSend, true);
  const d = decrypt(A, lateAnswer, ra, 0);
  assert.equal(d?.kind, KIND_KEM_STEP, 'the late answer is still received as a message');
  for (let i = 0; i < 2; i++) {
    send(A, B, ra, rb, `x${i}`);
    send(B, A, rb, ra, `y${i}`);
  }
  assert.equal(A.pqEpoch, 1);
  assert.equal(B.pqEpoch, 1);
});

test('messages sent before the switch still arrive after it, in any order', () => {
  const { A, B, ra, rb } = pair('k5');
  send(B, A, rb, ra, 'hey');
  const answer = decrypt(B, encrypt(A, KIND_KEM_STEP, kemOffer(A, ra, 0), ra), rb, 0)!.kemAnswer!;
  decrypt(A, encrypt(B, KIND_KEM_STEP, answer, rb), ra, 0);
  const late = encrypt(A, KIND_TEXT, utf8('sent on the old chain'), ra);
  send(A, B, ra, rb, 'x');
  send(B, A, rb, ra, 'y'); // A mixes the secret in here and re-keys its outgoing tags
  const n1 = encrypt(A, KIND_TEXT, utf8('new chain 1'), ra);
  const n2 = encrypt(A, KIND_TEXT, utf8('new chain 2'), ra);
  assert.equal(str(decrypt(B, n2, rb, 0)!.content), 'new chain 2');
  assert.equal(B.pqEpoch, 1);
  assert.ok(B.prevIn, 'old chain kept for late messages');
  assert.equal(str(decrypt(B, late, rb, 0)!.content), 'sent on the old chain');
  assert.equal(str(decrypt(B, n1, rb, 0)!.content), 'new chain 1');
  assert.equal(decrypt(B, n1, rb, 0), null, 'replay rejected');
});

test('a stale or malformed step message is ignored without stalling the conversation', () => {
  const { A, B, ra, rb } = pair('k6');
  send(B, A, rb, ra, 'hey');
  const junk = new Uint8Array(1189);
  junk[0] = 1;
  junk[4] = 9; // an offer for epoch 9
  const d = decrypt(B, encrypt(A, KIND_KEM_STEP, junk, ra), rb, 0)!;
  assert.equal(d.kemAnswer, undefined);
  assert.equal(B.pqSecret, null);
  const before = expectedTags(B)[0].index;
  send(A, B, ra, rb, 'next');
  assert.ok(expectedTags(B)[0].index > before, 'the tag window keeps moving');
});

test('a malformed ML-KEM key in an offer is ignored, never a crash', () => {
  const { A, B, ra, rb } = pair('k8');
  send(B, A, rb, ra, 'hey');
  const bad = new Uint8Array(1189).fill(0xff);
  bad.set([1, 0, 0, 0, 1], 0); // offer, epoch 1, then a public key failing the FIPS 203 modulus check
  const d = decrypt(B, encrypt(A, KIND_KEM_STEP, bad, ra), rb, 0)!;
  assert.equal(d.kind, KIND_KEM_STEP);
  assert.equal(d.kemAnswer, undefined);
  assert.equal(B.pqSecret, null);
  send(A, B, ra, rb, 'still fine');
});

test('a step is due every 50 messages or every 24 hours', () => {
  const { A, B, ra, rb } = pair('k7');
  assert.equal(kemStepDue(A, 1000), false);
  assert.equal(kemStepDue(A, KEM_EVERY_MS), true);
  for (let i = 0; i < 25; i++) {
    send(A, B, ra, rb, 'a');
    send(B, A, rb, ra, 'b');
  }
  assert.equal(kemStepDue(A, 1000), true);
  kemOffer(A, ra, 1000);
  assert.equal(kemStepDue(A, 1000), false, 'not while a step is in flight');
});
