import { test } from 'node:test';
import assert from 'node:assert/strict';
import { utf8 } from '../src/crypto.ts';
import { detRand } from '../src/detrand.ts';
import {
  BUNDLE_MARKER, FIELD_LEN, KIND_TEXT, MAX_TEXT, MAX_TEXT_FIRST_CONTACT, PAYLOAD_LEN, TAG_LEN,
  buildFirstContact, bundlePayload, coverPayload, decrypt, encrypt, identityFromMnemonic, identityFromSeed,
  inboxBucket, makeBundle, openFirstContact, parseBundle, registryBucket, signedPrekey, tagBucket, crossingKeeps, SKIPPED_KEY_TTL_MS, receiveFirstContact, forgetPrekey,
} from '../src/index.ts';

const text = (s: string) => utf8(s);
const str = (b: Uint8Array) => new TextDecoder().decode(b);

function setup() {
  const alice = identityFromSeed(detRand('alice-seed')(64));
  const bob = identityFromSeed(detRand('bob-seed')(64));
  const bobSpk = signedPrekey(bob, 7);
  const bobBundle = parseBundle(makeBundle(bob, bobSpk, 1_750_000_000n), bob.ownerPub)!;
  const registry = new Map([['alice-21', { ownerPub: alice.ownerPub, idXPub: alice.idXPub }]]);
  return { alice, bob, bobSpk, bobBundle, lookup: (n: string) => registry.get(n) ?? null };
}

test('recovery phrase derives the same keys every time', () => {
  const m = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
  const a = identityFromMnemonic(m);
  const b = identityFromMnemonic(m);
  assert.deepEqual(a.ownerPub, b.ownerPub);
  assert.deepEqual(signedPrekey(a, 1).kemPub, signedPrekey(b, 1).kemPub);
  assert.notDeepEqual(signedPrekey(a, 1).xPub, signedPrekey(a, 2).xPub);
});

test('bundle: signature binds it to the registry owner key; it fits one payload', () => {
  const { alice, bob, bobSpk } = setup();
  const bytes = makeBundle(bob, bobSpk, 1n);
  assert.ok(parseBundle(bytes, bob.ownerPub));
  assert.equal(parseBundle(bytes, alice.ownerPub), null, 'wrong owner rejected');
  const tampered = bytes.slice();
  tampered[40] ^= 1;
  assert.equal(parseBundle(tampered, bob.ownerPub), null, 'tampered bundle rejected');
  const p = bundlePayload(bytes);
  assert.equal(p.length, PAYLOAD_LEN);
  assert.deepEqual(p.subarray(1 + TAG_LEN, 1 + TAG_LEN + FIELD_LEN), BUNDLE_MARKER);
});

test('first contact then conversation both ways, every payload exactly 1,536 bytes', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const ra = detRand('a'), rb = detRand('b');
  const fc = buildFirstContact(alice, 'alice-21', bobBundle, text('hi bob'), ra);
  assert.equal(fc.payload.length, PAYLOAD_LEN);
  assert.equal(tagBucket(fc.payload.subarray(1, 17)), inboxBucket(bob.idXPub), 'first contact lands in the inbox bucket');

  const got = openFirstContact(bob, [signedPrekey(bob, 6), bobSpk], fc.payload, lookup, rb)!;
  assert.equal(got.from, 'alice-21');
  assert.equal(str(got.text), 'hi bob');
  const A = fc.session, B = got.session;

  const script: [string, 'A' | 'B'][] = [['hey alice', 'B'], ['how are you', 'A'], ['fine', 'A'], ['good', 'B'], ['bye', 'B'], ['ciao', 'A']];
  for (const [msg, who] of script) {
    const [from, to] = who === 'A' ? [A, B] : [B, A];
    const p = encrypt(from, KIND_TEXT, text(msg), who === 'A' ? ra : rb);
    assert.equal(p.length, PAYLOAD_LEN);
    const d = decrypt(to, p, who === 'A' ? rb : ra);
    assert.ok(d, `decrypt ${msg}`);
    assert.equal(str(d.content), msg);
  }
});

test('out-of-order and lost messages still decrypt', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const ra = detRand('a2'), rb = detRand('b2');
  const fc = buildFirstContact(alice, 'alice-21', bobBundle, text('0'), ra);
  const B = openFirstContact(bob, [bobSpk], fc.payload, lookup, rb)!.session;
  const A = fc.session;
  const ps = ['1', '2', '3', '4'].map((m) => encrypt(A, KIND_TEXT, text(m), ra));
  assert.equal(str(decrypt(B, ps[2], rb)!.content), '3');
  assert.equal(str(decrypt(B, ps[0], rb)!.content), '1');
  assert.equal(str(decrypt(B, ps[3], rb)!.content), '4');
  assert.equal(decrypt(B, ps[0], rb), null, 'replay rejected');
  const r = encrypt(B, KIND_TEXT, text('got 1 3 4'), rb);
  assert.equal(str(decrypt(A, r, ra)!.content), 'got 1 3 4');
  assert.equal(str(decrypt(B, ps[1], rb)!.content), '2', 'late message from the previous chain');
});

test('tampering, wrong recipients and impersonation are rejected', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const eve = identityFromSeed(detRand('eve-seed')(64));
  const ra = detRand('a3'), rb = detRand('b3');
  const fc = buildFirstContact(alice, 'alice-21', bobBundle, text('secret'), ra);
  assert.equal(openFirstContact(eve, [signedPrekey(eve, 7)], fc.payload, lookup, rb), null, 'not for eve');
  const bad = fc.payload.slice();
  bad[1500] ^= 1;
  assert.equal(openFirstContact(bob, [bobSpk], bad, lookup, rb), null, 'tampered first contact');

  const forged = buildFirstContact(eve, 'alice-21', bobBundle, text('i am alice'), detRand('e'));
  assert.equal(openFirstContact(bob, [bobSpk], forged.payload, lookup, rb), null, 'eve claiming alice-21');

  const B = openFirstContact(bob, [bobSpk], fc.payload, lookup, rb)!.session;
  const p = encrypt(fc.session, KIND_TEXT, text('x'), ra);
  const t = p.slice();
  t[500] ^= 1;
  assert.equal(decrypt(B, t, rb), null, 'tampered body');
  assert.equal(str(decrypt(B, p, rb)!.content), 'x', 'session unharmed by the failed attempt');
});

test('a first contact whose sender key is a low-order X25519 point is refused, never a crash', () => {
  const { alice, bob, bobSpk, bobBundle } = setup();
  const evil = { ...alice, idXPub: new Uint8Array(32) }; // all-zero point: every X25519 result with it is zero
  const fc = buildFirstContact(evil, 'alice-21', bobBundle, text('boom'), detRand('a6'));
  const lookup = (n: string) => (n === 'alice-21' ? { ownerPub: alice.ownerPub, idXPub: evil.idXPub } : null);
  assert.equal(openFirstContact(bob, [bobSpk], fc.payload, lookup, detRand('b6')), null);
});

test('skipped keys are deleted 7 days after they were stored', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const ra = detRand('a7'), rb = detRand('b7');
  const fc = buildFirstContact(alice, 'alice-21', bobBundle, text('0'), ra, 0);
  const B = openFirstContact(bob, [bobSpk], fc.payload, lookup, rb, 0)!.session;
  const p1 = encrypt(fc.session, KIND_TEXT, text('late'), ra);
  const p2 = encrypt(fc.session, KIND_TEXT, text('first'), ra);
  const p3 = encrypt(fc.session, KIND_TEXT, text('later still'), ra);
  const t0 = 1_000_000;
  assert.equal(str(decrypt(B, p3, rb, t0)!.content), 'later still');
  assert.equal(B.skipped.size, 2);
  assert.equal(str(decrypt(B, p2, rb, t0 + SKIPPED_KEY_TTL_MS - 1)!.content), 'first', 'within 7 days: still decryptable');
  assert.equal(decrypt(B, p1, rb, t0 + SKIPPED_KEY_TTL_MS), null, 'after 7 days the key is gone');
  assert.equal(B.skipped.size, 0);
});

test('crossing first contacts: both sides pick the same session', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const aliceSpk = signedPrekey(alice, 1);
  const aliceBundle = parseBundle(makeBundle(alice, aliceSpk, 1n), alice.ownerPub)!;
  const a2b = buildFirstContact(alice, 'alice-21', bobBundle, text('hi bob'), detRand('a8'));
  const b2a = buildFirstContact(bob, 'bob-22', aliceBundle, text('hi alice'), detRand('b8'));
  const [ta, tb] = [a2b.payload.subarray(1, 17), b2a.payload.subarray(1, 17)];
  const aliceKeeps = crossingKeeps(ta, tb), bobKeeps = crossingKeeps(tb, ta);
  assert.notEqual(aliceKeeps, bobKeeps, 'one keeps what it sent, the other what it received: the same session');
  assert.throws(() => crossingKeeps(ta, ta));
  void lookup; void bobSpk;
});

test('nothing repeats in the clear across a conversation', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const ra = detRand('a4'), rb = detRand('b4');
  const fc = buildFirstContact(alice, 'alice-21', bobBundle, text('0'), ra);
  const B = openFirstContact(bob, [bobSpk], fc.payload, lookup, rb)!.session;
  const ps: Uint8Array[] = [fc.payload];
  for (let i = 0; i < 20; i++) {
    const p = encrypt(i % 3 ? fc.session : B, KIND_TEXT, text('same text'), i % 3 ? ra : rb);
    ps.push(p);
    decrypt(i % 3 ? B : fc.session, p, i % 3 ? rb : ra);
  }
  const seen = new Set<string>();
  for (const p of ps) {
    for (const field of [p.subarray(1, 17), p.subarray(17, 49)]) {
      const h = Buffer.from(field).toString('hex');
      assert.ok(!seen.has(h), 'a tag or 32-byte field repeated');
      seen.add(h);
    }
  }
});

test('size limits and helpers', () => {
  const { alice, bobBundle } = setup();
  assert.throws(() => buildFirstContact(alice, 'alice-21', bobBundle, new Uint8Array(MAX_TEXT_FIRST_CONTACT + 1)));
  assert.ok(buildFirstContact(alice, 'alice-21', bobBundle, new Uint8Array(MAX_TEXT_FIRST_CONTACT)));
  assert.equal(MAX_TEXT, 1404);
  assert.equal(MAX_TEXT_FIRST_CONTACT, 242);
  assert.equal(coverPayload().length, PAYLOAD_LEN);
  assert.ok(registryBucket('catch22') >= 0 && registryBucket('catch22') < 256);
});

test('replayed first contacts are dropped while the prekey is kept, forgotten with it', () => {
  const { alice, bob, bobSpk, bobBundle, lookup } = setup();
  const fc = buildFirstContact(alice, 'alice-21', bobBundle, text('hi'), detRand('rp-a'));
  const seen = new Map<string, number>();
  assert.ok(receiveFirstContact(seen, bob, [bobSpk], fc.payload, lookup, detRand('rp-b')));
  assert.equal(receiveFirstContact(seen, bob, [bobSpk], fc.payload, lookup, detRand('rp-b')), 'replay');
  forgetPrekey(seen, bobSpk.spkId);
  assert.equal(seen.size, 0);
  assert.equal(receiveFirstContact(seen, bob, [signedPrekey(bob, bobSpk.spkId + 1)], fc.payload, lookup, detRand('rp-b')), null, 'too old to open once its prekey is gone');
});

test('unpackBody rejects a body shorter than its 3-byte header', async () => {
  const { unpackBody } = await import('../src/crypto.ts');
  assert.equal(unpackBody(new Uint8Array(0)), null);
  assert.equal(unpackBody(new Uint8Array([0x01, 0x00])), null);
  assert.deepEqual(unpackBody(new Uint8Array([0x01, 0x00, 0x00])), { kind: 0x01, content: new Uint8Array(0) });
});

test('a first contact refuses a kind it may not carry', () => {
  const alice = identityFromSeed(detRand('fc-kind-alice')(64));
  const bob = identityFromSeed(detRand('fc-kind-bob')(64));
  const peer = parseBundle(makeBundle(bob, signedPrekey(bob, 1), 1n), bob.ownerPub)!;
  assert.throws(() => buildFirstContact(alice, 'alice', peer, new Uint8Array(0), detRand('r'), 0, 0x05), /kind not allowed/);
});

test('bundle publications: only the owner\'s own tag, a valid signature and a sane created time are accepted', async () => {
  const { parseBundlePayload, bundleTag: tagOf } = await import('../src/index.ts');
  const victim = identityFromSeed(detRand('bp-victim')(64));
  const mallory = identityFromSeed(detRand('bp-mallory')(64));
  const nowSec = 1_780_000_000;
  const pub = (id: typeof victim, created: bigint) => bundlePayload(makeBundle(id, signedPrekey(id, 1), created, [], new Uint8Array(32)));
  const ok = parseBundlePayload(pub(victim, BigInt(nowSec)), nowSec, victim.ownerPub);
  assert.ok(ok && ok.created === BigInt(nowSec));
  assert.ok(parseBundlePayload(pub(victim, BigInt(nowSec)), nowSec), 'the expected owner is optional (indexers)');

  // Mallory's own, validly signed bundle filed under the victim's tag: refused.
  const forged = pub(mallory, BigInt(nowSec));
  forged.set(tagOf(victim.ownerPub), 1);
  assert.equal(parseBundlePayload(forged, nowSec), null);
  assert.equal(parseBundlePayload(pub(mallory, BigInt(nowSec)), nowSec, victim.ownerPub), null, 'someone else\'s bundle for this owner');

  // created more than 24 h ahead (e.g. milliseconds written as seconds): ignored, as §3 requires.
  assert.ok(parseBundlePayload(pub(victim, BigInt(nowSec + 24 * 3600)), nowSec));
  assert.equal(parseBundlePayload(pub(victim, BigInt(nowSec + 24 * 3600 + 1)), nowSec), null);
  assert.equal(parseBundlePayload(pub(victim, BigInt(nowSec) * 1000n), nowSec), null);

  // a flipped signature byte, a wrong marker, a short payload
  const bad = pub(victim, BigInt(nowSec));
  bad[49 + 1358 - 1] ^= 1;
  assert.equal(parseBundlePayload(bad, nowSec), null);
  const marker = pub(victim, BigInt(nowSec));
  marker[20] ^= 1;
  assert.equal(parseBundlePayload(marker, nowSec), null);
  assert.equal(parseBundlePayload(pub(victim, BigInt(nowSec)).subarray(0, 1535), nowSec), null);
});
