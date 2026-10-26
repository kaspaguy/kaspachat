// Generates vectors/v1.json: self-describing, byte-exact test vectors for Kaspaveil v1. Every vector carries
// its complete input (keys, sessions, named random values) and its complete expected output, so any vector can
// be run in isolation by an implementation that has only WIRE_FORMAT.md, PROTOCOL_SPEC.md and this file.
import { readFileSync, writeFileSync } from 'node:fs';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { b2, concat, dh, kdf, kdfChain, packBody, seal, u32, utf8 } from '../src/crypto.ts';
import { BODY_PT_LEN, FIELD_LEN, HEADER_PT_LEN, VERSION } from '../src/constants.ts';
import { chainTag, headerKey } from '../src/tags.ts';
import { detRand } from '../src/detrand.ts';
import {
  KIND_GROUP_STATE, KIND_GROUP_TEXT, KIND_KEM_STEP, KIND_TEXT, bundlePayload, coverFirstContact, crossingKeeps, onFirstContactFromKnownPeer, receiveFirstContact, defaultName, bundleTag, buildFirstContact, decodePrefs,
  decrypt, effectiveSettings, encodePrefs, encrypt, identityFromMnemonic, inboxBucket, kemOffer, makeBundle, makeGroupState,
  makeGroupText, openFirstContact, parseBundle, receiveGroupState, receiveGroupText, registryBucket, signedPrekey, tagBucket, withBucket,
} from '../src/index.ts';
import type { Groups, Identity, SeenFirstContacts, Session } from '../src/index.ts';
import { Recorder, hex, replay, sessionFromJson, sessionToJson, unhex as unhexU } from './vector-format.ts';

type Vec = { id: string; kind: string; description: string; input: unknown; expected: unknown };
const str = (b: Uint8Array) => new TextDecoder().decode(b);

const FORMAT = {
  encoding: 'Every byte string is lowercase hex with no prefix. Integers are JSON numbers. Text fields (text, name, mnemonic) are UTF-8 strings.',
  vector_shape: 'Each vector: id (stable), kind (the WIRE_FORMAT section it exercises), description, input (everything needed; no vector depends on another), expected (every output byte).',
  ordering: 'Arrays are ordered and the order is significant: steps run in order; results[i] belongs to steps[i]; members are in list order.',
  randomness: {
    rule: 'Every random value a step consumes is given in that step\'s "rand" object, by name. An implementation injects these values instead of calling its random number generator.',
    names: {
      ephemeral_x25519_sk: 'first contact: the ephemeral X25519 secret key (WIRE_FORMAT §4.2 "eph")',
      mlkem_encaps_m: '32-byte randomness for ML-KEM-768 encapsulation (the FIPS 203 "m" input): first contact, and answering a KEM offer',
      ratchet_x25519_sk: 'a new X25519 ratchet secret key, generated when a party creates a new sending chain',
      random_field: 'the 32 random bytes of an ongoing message (WIRE_FORMAT §4.1 "random")',
      mlkem_keygen_seed: '64-byte ML-KEM-768 key-generation seed (d || z) for a KEM offer',
      schnorr_aux: 'the 32-byte BIP-340 auxiliary randomness for a Schnorr signature',
      random_tag: 'dummy first contact: 16 random bytes whose first 12 bits are then replaced by the inbox bucket',
      random_rest: 'dummy first contact: the random bytes after the ephemeral key',
    },
    order_within_one_decrypt: 'If one decrypt consumes two values, the ratchet_x25519_sk is drawn first (the DH ratchet step), then mlkem_encaps_m (answering a KEM offer carried in that message). A KEM offer consumes mlkem_encaps_m once it passes the epoch and state checks (WIRE_FORMAT §4.5 state table) and reaches encapsulation, even if its public key then fails the FIPS 203 check and no answer is produced (kem-step-malformed-offer); an offer ignored for its epoch or state consumes nothing (kem-step-crossing-offers, step 6).',
  },
  session_state: 'Sessions are shown in full so ratchet vectors run in isolation. Field names: root_key, our_ratchet_sk/pub (DHs), their_ratchet_pub (DHr), sending/receiving_chain_key (CKs/CKr), ns/nr/pn, tag_key_out/in, ad (the session AD: initiator idXPub || responder idXPub), initiator (true for the side that sent the first contact), tag_out (next outgoing tag index), tag_in (lowest incoming index not yet received), seen_in (received indices above tag_in), skipped (message keys kept for skipped messages, keyed by the sender ratchet key and N, listed in the order they were stored), pq_epoch, pq_offer, pq_secret, tag_key_in_next (the peer\'s re-keyed tag chain, watched after a KEM secret is known), previous_in (the peer\'s previous tag chain, still watched). Shapes: skipped = [{their_ratchet_pub, n, message_key}] (see ratchet-skipped-key-state); pq_offer = {epoch, mlkem_keygen_seed} or null; pq_secret = {epoch, shared_secret, mix_on_send} or null, where mix_on_send is true for the offerer (it mixes the secret into its next sending chain) and false for the answerer (it mixes on receive); see kem-step-offer-pending. This layout is test-harness format, not wire format.',
  clock: 'Every vector runs with a fixed clock: now = 0 (Unix milliseconds) for every step, so skipped keys stored during a vector are stored at time 0 and none expires; the 7-day expiry (WIRE_FORMAT §4.1) is not exercised by any vector.',
  ops: 'Sequence vectors (input.steps) use these ops: encrypt {session, kind, content, rand: {random_field}} -> {payload}; decrypt {session, payload, rand} -> a decrypt result (below); kem_offer {session, rand: {mlkem_keygen_seed}} -> {content} (the offer body to send with encrypt, kind 0x05). Group rule vectors use group_state {from, content} -> {event, epoch} or {reject: true}, and group_text {from, content} -> {text, epoch, older_epoch}, {pending: true} or {reject: true}; from names a key in input.senders and the receiver is input.me_owner_pub.',
  results: 'A decrypt result is {kind, content} (plus kem_answer: the body content to send back when the message was a KEM offer), or {reject: true} when the payload must be refused and the session left unchanged.',
};

const V: Vec[] = [];
const push = (id: string, kind: string, description: string, input: unknown, expected: unknown) => V.push({ id, kind, description, input, expected });

type Party = { s: Session; rec: Recorder };
type Op =
  | { op: 'encrypt'; session: string; kind: number; content: () => Uint8Array; save?: string }
  | { op: 'decrypt'; session: string; payload: () => Uint8Array; save?: string }
  | { op: 'kem_offer'; session: string; save?: string };

// Runs ops on live sessions, recording inputs (state before, named randoms) and outputs (results, state after).
function sequence(id: string, kind: string, description: string, parties: Record<string, Party>, ops: Op[], saved: Record<string, Uint8Array> = {}) {
  const before = Object.fromEntries(Object.entries(parties).map(([k, p]) => [k, sessionToJson(p.s)]));
  const steps: unknown[] = [], results: unknown[] = [];
  for (const o of ops) {
    const p = parties[o.session];
    if (o.op === 'encrypt') {
      const content = o.content();
      const payload = encrypt(p.s, o.kind, content, p.rec.rand);
      steps.push({ op: 'encrypt', session: o.session, kind: o.kind, content: hex(content), rand: p.rec.take(['random_field']) });
      results.push({ payload: hex(payload) });
      if (o.save) saved[o.save] = payload;
    } else if (o.op === 'decrypt') {
      const payload = o.payload();
      const dhr = p.s.dhr && hex(p.s.dhr);
      const d = decrypt(p.s, payload, p.rec.rand, 0);
      const stepped = !!d && (p.s.dhr && hex(p.s.dhr)) !== dhr;
      const names = [...(stepped ? ['ratchet_x25519_sk'] : []), ...(d?.kemAnswer ? ['mlkem_encaps_m'] : [])];
      if (d?.kind === KIND_KEM_STEP && !d.kemAnswer && p.rec.draws.length > names.length) names.push('mlkem_encaps_m'); // malformed offer: drawn, then refused
      if (!d && p.rec.draws.length) names.push(...p.rec.draws.map(() => 'unused'));
      steps.push({ op: 'decrypt', session: o.session, payload: hex(payload), rand: p.rec.take(names) });
      results.push(d ? { kind: d.kind, content: hex(d.content), ...(d.kemAnswer ? { kem_answer: hex(d.kemAnswer) } : {}) } : { reject: true });
      if (o.save && d?.kemAnswer) saved[o.save] = d.kemAnswer;
    } else {
      const content = kemOffer(p.s, p.rec.rand, 0);
      steps.push({ op: 'kem_offer', session: o.session, rand: p.rec.take(['mlkem_keygen_seed']) });
      results.push({ content: hex(content) });
      if (o.save) saved[o.save] = content;
    }
  }
  const after = Object.fromEntries(Object.entries(parties).map(([k, p]) => [k, sessionToJson(p.s)]));
  push(id, kind, description, { sessions: before, steps }, { results, sessions_after: after });
  return saved;
}

function identityJson(id: Identity) {
  return { seed: hex(id.seed), owner_sk: hex(id.ownerSk), owner_pub: hex(id.ownerPub), id_x25519_sk: hex(id.idXSk), id_x25519_pub: hex(id.idXPub) };
}

export function buildVectors() {
  const aliceM = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
  const bobM = 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title';
  const alice = identityFromMnemonic(aliceM);
  const bob = identityFromMnemonic(bobM);

  // --- keys (§2) ---
  for (const [who, m, id] of [['alice', aliceM, alice], ['bob', bobM, bob]] as const) {
    push(`keys-${who}`, 'keys', `Every key derived from ${who}'s 24-word phrase (empty BIP-39 passphrase).`,
      { mnemonic: m, passphrase: '' }, identityJson(id));
  }
  for (const n of [1, 2]) {
    const spk = signedPrekey(bob, n);
    push(`keys-prekey-bob-${n}`, 'keys', `Signed prekey number ${n}: X25519 and ML-KEM-768 keys from the seed and the index.`,
      { seed: hex(bob.seed), spk_id: n },
      { spk_x25519_sk: hex(spk.xSk), spk_x25519_pub: hex(spk.xPub), mlkem_keygen_seed: hex(kdf(bob.seed, 'spk-mlkem', 64, new Uint8Array([0, 0, 0, n]))),
        spk_mlkem_pub: hex(spk.kemPub), spk_mlkem_sk: hex(spk.kemSk) });
  }

  // --- bundle (§3, §4.3) ---
  const bobSpk = signedPrekey(bob, 1);
  const bundleBytes = makeBundle(bob, bobSpk, 1_780_000_000n, [], new Uint8Array(32));
  const bundleIn = { owner_sk: hex(bob.ownerSk), owner_pub: hex(bob.ownerPub), id_x25519_pub: hex(bob.idXPub), spk_id: 1,
    spk_x25519_pub: hex(bobSpk.xPub), spk_mlkem_pub: hex(bobSpk.kemPub), created: 1_780_000_000, devices: [], rand: { schnorr_aux: hex(new Uint8Array(32)) } };
  const unsigned = bundleBytes.subarray(0, bundleBytes.length - 64);
  push('bundle-bob-1', 'bundle', "Bob's bundle for signed prekey 1: layout, signed digest and BIP-340 signature.", bundleIn,
    { unsigned: hex(unsigned), signed_digest: hex(b2(concat(utf8('kasveil/v1/bundle'), unsigned))), signature: hex(bundleBytes.subarray(-64)), bundle: hex(bundleBytes) });
  const tampered = bundleBytes.slice();
  tampered[40] ^= 1;
  push('bundle-reject-tampered', 'bundle', 'A bundle with one flipped byte (offset 40) is refused.',
    { bundle: hex(tampered), expected_owner_pub: hex(bob.ownerPub) }, { result: 'reject' });
  push('bundle-reject-wrong-owner', 'bundle', "A valid bundle is refused when the registry maps the name to a different owner key.",
    { bundle: hex(bundleBytes), expected_owner_pub: hex(alice.ownerPub) }, { result: 'reject' });
  push('bundle-accept', 'bundle', 'The same bundle is accepted against its real owner key; parsed fields.',
    { bundle: hex(bundleBytes), expected_owner_pub: hex(bob.ownerPub) },
    { result: 'accept', ...(() => { const b = parseBundle(bundleBytes, bob.ownerPub)!; return { spk_id: b.spkId, created: Number(b.created), devices: [] }; })() });
  push('bundle-payload', 'bundle', 'Bundle publication payload (§4.3) and its bundle tag.',
    { owner_pub: hex(bob.ownerPub), bundle: hex(bundleBytes) }, { bundle_tag: hex(bundleTag(bob.ownerPub)), payload: hex(bundlePayload(bundleBytes)) });

  // --- buckets (§6) ---
  const someTags = ['00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', 'a1b2c3d4e5f60718293a4b5c6d7e8f90'];
  push('buckets-message', 'buckets', 'Message bucket = first 12 bits of the tag.', { tags: someTags },
    { buckets: someTags.map((t) => tagBucket(new Uint8Array(Buffer.from(t, 'hex')))) });
  const names = ['catch22', 'dog-cat-21', 'kv7f3q9xab'];
  push('buckets-registry', 'buckets', 'Registry bucket = byte 0 of BLAKE2b-256(name).', { names }, { buckets: names.map(registryBucket) });
  push('buckets-inbox', 'buckets', 'Inbox bucket of an identity key.', { id_x25519_pubs: [hex(alice.idXPub), hex(bob.idXPub)] },
    { buckets: [inboxBucket(alice.idXPub), inboxBucket(bob.idXPub)] });
  push('buckets-with-bucket', 'buckets', "Replacing a tag's first 12 bits with a bucket (first-contact tags).",
    { tag: someTags[2], bucket: 0x0abc }, { tag: hex(withBucket(new Uint8Array(Buffer.from(someTags[2], 'hex')), 0x0abc)) });

  // --- first contact (§4.2), then the published conversation ---
  const ra = new Recorder(detRand('kasveil-vector-alice')), rb = new Recorder(detRand('kasveil-vector-bob'));
  const fc = buildFirstContact(alice, 'alice-21', parseBundle(bundleBytes, bob.ownerPub)!, utf8('Hello from Kaspa'), ra.rand, 0);
  const fcRand = ra.take(['ephemeral_x25519_sk', 'mlkem_encaps_m', 'ratchet_x25519_sk']);
  const eph = new Uint8Array(Buffer.from(fcRand.ephemeral_x25519_sk, 'hex'));
  const kem = ml_kem768.encapsulate(bobSpk.kemPub, new Uint8Array(Buffer.from(fcRand.mlkem_encaps_m, 'hex')));
  const dh1 = dh(alice.idXSk, bobSpk.xPub), dh2 = dh(eph, bob.idXPub), dh3 = dh(eph, bobSpk.xPub);
  push('first-contact-alice-to-bob', 'first-contact', "Alice's first contact to Bob: every intermediate secret, the payload, and Alice's session afterwards.",
    { alice: { owner_pub: hex(alice.ownerPub), id_x25519_sk: hex(alice.idXSk), id_x25519_pub: hex(alice.idXPub), name: 'alice-21' },
      bob_bundle: hex(bundleBytes), text: 'Hello from Kaspa', rand: fcRand },
    { dh1: hex(dh1), dh2: hex(dh2), dh3: hex(dh3), mlkem_ciphertext: hex(kem.cipherText), mlkem_shared_secret: hex(kem.sharedSecret),
      sk: hex(kdf(concat(new Uint8Array(32).fill(0xff), dh1, dh2, dh3, kem.sharedSecret), 'pqxdh')),
      tag: hex(fc.payload.subarray(1, 17)), inbox_bucket: inboxBucket(bob.idXPub), payload: hex(fc.payload), session: sessionToJson(fc.session) });
  const lookup = (n: string) => (n === 'alice-21' ? { ownerPub: alice.ownerPub, idXPub: alice.idXPub } : null);
  const registry = { 'alice-21': { owner_pub: hex(alice.ownerPub), id_x25519_pub: hex(alice.idXPub) } };
  const bobIn = { id_x25519_sk: hex(bob.idXSk), id_x25519_pub: hex(bob.idXPub),
    prekeys: [{ spk_id: 1, x25519_sk: hex(bobSpk.xSk), mlkem_keygen_seed: hex(kdf(bob.seed, 'spk-mlkem', 64, new Uint8Array([0, 0, 0, 1]))) }] };
  const opened = openFirstContact(bob, [bobSpk], fc.payload, lookup, rb.rand, 0)!;
  push('first-contact-bob-opens', 'first-contact', 'Bob opens the first contact from his inbox bucket and starts his side of the session.',
    { recipient: bobIn, registry, payload: hex(fc.payload), rand: rb.take(['ratchet_x25519_sk']) },
    { from: opened.from, kind: opened.kind, text: str(opened.text), session: sessionToJson(opened.session) });
  const eve = identityFromMnemonic('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote');
  const eveSpk = signedPrekey(eve, 1);
  push('first-contact-reject-not-for-me', 'first-contact', 'Someone else (Eve) scanning the same payload must refuse it.',
    { recipient: { id_x25519_sk: hex(eve.idXSk), id_x25519_pub: hex(eve.idXPub), prekeys: [{ spk_id: 1, x25519_sk: hex(eveSpk.xSk), mlkem_keygen_seed: hex(kdf(eve.seed, 'spk-mlkem', 64, new Uint8Array([0, 0, 0, 1]))) }] },
      registry, payload: hex(fc.payload), rand: {} }, { result: 'reject' });
  push('first-contact-reject-registry-mismatch', 'first-contact', 'Refused when the registry maps the claimed name to different keys (impersonation).',
    { recipient: bobIn, registry: { 'alice-21': { owner_pub: hex(eve.ownerPub), id_x25519_pub: hex(eve.idXPub) } }, payload: hex(fc.payload), rand: {} },
    { result: 'reject' });

  const A: Party = { s: fc.session, rec: ra }, B: Party = { s: opened.session, rec: rb };
  const saved: Record<string, Uint8Array> = {};
  const msg = (from: string, to: string, t: string, kind = KIND_TEXT, key = `${from}-${t}`): Op[] => [
    { op: 'encrypt', session: from, kind, content: () => utf8(t), save: key }, { op: 'decrypt', session: to, payload: () => saved[key] }];
  sequence('ratchet-conversation', 'ratchet', 'The first three messages after first contact, both directions, including DH ratchet steps.', { alice: A, bob: B },
    [...msg('bob', 'alice', 'Hi alice'), ...msg('alice', 'bob', 'Second message'), ...msg('alice', 'bob', 'Third')], saved);

  // --- KEM ratchet step (§4.5) on the same session ---
  sequence('kem-step-full', 'kem-step', 'A full KEM step started by Alice: offer, answer, then traffic until both sides have mixed the secret into the root key and re-keyed both tag chains (pq_epoch 1).',
    { alice: A, bob: B },
    [{ op: 'kem_offer', session: 'alice', save: 'offer' }, { op: 'encrypt', session: 'alice', kind: KIND_KEM_STEP, content: () => saved.offer, save: 'offerP' },
      { op: 'decrypt', session: 'bob', payload: () => saved.offerP, save: 'answer' }, { op: 'encrypt', session: 'bob', kind: KIND_KEM_STEP, content: () => saved.answer, save: 'answerP' },
      { op: 'decrypt', session: 'alice', payload: () => saved.answerP },
      ...msg('alice', 'bob', 'x'), ...msg('bob', 'alice', 'y'), ...msg('alice', 'bob', 'on the re-keyed chain'), ...msg('bob', 'alice', 'here too')], saved);

  // --- groups (§4.6) over the same session ---
  const groupId = ra.rand(16), members = [{ ownerPub: alice.ownerPub, idXPub: alice.idXPub, name: 'alice-21' }, { ownerPub: bob.ownerPub, idXPub: bob.idXPub, name: 'bob-22' }];
  const groupIdIn = ra.take(['group_id']).group_id;
  const state = makeGroupState(alice, groupId, 1, members, ra.rand);
  push('group-state-encode', 'groups', 'Group state (kind 0x03) made and signed by the admin, Alice.',
    { admin_owner_sk: hex(alice.ownerSk), group_id: groupIdIn, epoch: 1, members: members.map((m) => ({ owner_pub: hex(m.ownerPub), id_x25519_pub: hex(m.idXPub), name: m.name })),
      rand: ra.take(['schnorr_aux']) }, { content: hex(state) });
  sequence('group-state-over-session', 'groups', 'The group state sent to Bob over the pairwise session.', { alice: A, bob: B },
    [{ op: 'encrypt', session: 'alice', kind: KIND_GROUP_STATE, content: () => state, save: 'gs' }, { op: 'decrypt', session: 'bob', payload: () => saved.gs }], saved);
  const msgId = ra.rand(16);
  const gText = makeGroupText(groupId, 1, msgId, utf8('Hello group'));
  push('group-text-encode', 'groups', 'Group text (kind 0x04).', { group_id: groupIdIn, epoch: 1, msg_id: ra.take(['msg_id']).msg_id, text: 'Hello group' }, { content: hex(gText) });
  sequence('group-text-over-session', 'groups', 'A group text sent to Bob over the pairwise session, after the state.', { alice: A, bob: B },
    [{ op: 'encrypt', session: 'alice', kind: KIND_GROUP_TEXT, content: () => gText, save: 'gt' }, { op: 'decrypt', session: 'bob', payload: () => saved.gt }], saved);

  // Group receive rules, run by Bob on an empty group book.
  const g: Groups = new Map();
  const carol = identityFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel');
  const carolState = makeGroupState(carol, groupId, 2, [{ ownerPub: carol.ownerPub, idXPub: carol.idXPub, name: 'carol-3' }, members[1]], () => new Uint8Array(32));
  const state2 = makeGroupState(alice, groupId, 2, [members[0]], () => new Uint8Array(32));
  const rules: [string, string, Uint8Array, string][] = [
    ['group_state', 'alice', state, 'joined'], ['group_state', 'carol', state, 'reject: forwarded by a non-admin'],
    ['group_state', 'alice', state, 'reject: epoch not higher'], ['group_state', 'carol', carolState, 'reject: not the admin'],
    ['group_text', 'alice', gText, 'accepted'], ['group_text', 'carol', makeGroupText(groupId, 1, msgId, utf8('let me in')), 'reject: not a member'],
    ['group_text', 'alice', makeGroupText(groupId, 2, msgId, utf8('early')), 'pending: epoch not known yet'],
    ['group_state', 'alice', state2, 'removed'], ['group_text', 'alice', makeGroupText(groupId, 1, msgId, utf8('late, from before')), 'accepted, older epoch'],
  ];
  const owners: Record<string, Uint8Array> = { alice: alice.ownerPub, carol: carol.ownerPub };
  const ruleResults = rules.map(([op, from, c]) => {
    if (op === 'group_state') { const r = receiveGroupState(g, bob.ownerPub, owners[from], c); return r ? { event: r.event, epoch: r.epoch } : { reject: true }; }
    const r = receiveGroupText(g, bob.ownerPub, owners[from], c);
    return r === 'pending' ? { pending: true } : r ? { text: str(r.text), epoch: r.epoch, older_epoch: r.olderEpoch } : { reject: true };
  });
  push('group-receive-rules', 'groups', 'Bob applies group messages as delivered over pairwise sessions (from = the sender\'s owner key). Starts with no groups.',
    { me_owner_pub: hex(bob.ownerPub), senders: { alice: hex(alice.ownerPub), carol: hex(carol.ownerPub) },
      steps: rules.map(([op, from, c, why]) => ({ op, from, content: hex(c), note: why })) }, { results: ruleResults });

  // --- more ratchet and KEM scenarios on fresh sessions ---
  function fresh(label: string) {
    const r1 = new Recorder(detRand(`${label}-a`)), r2 = new Recorder(detRand(`${label}-b`));
    const f = buildFirstContact(alice, 'alice-21', parseBundle(bundleBytes, bob.ownerPub)!, utf8('0'), r1.rand, 0);
    r1.take(['ephemeral_x25519_sk', 'mlkem_encaps_m', 'ratchet_x25519_sk']);
    const o = openFirstContact(bob, [bobSpk], f.payload, lookup, r2.rand, 0)!;
    r2.take(['ratchet_x25519_sk']);
    return { alice: { s: f.session, rec: r1 }, bob: { s: o.session, rec: r2 } };
  }
  {
    const P = fresh('vec-ooo'), sv: Record<string, Uint8Array> = {};
    const sends: Op[] = ['1', '2', '3', '4'].map((t) => ({ op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8(t), save: t }));
    const d = (k: string): Op => ({ op: 'decrypt', session: 'bob', payload: () => sv[k] });
    sequence('ratchet-out-of-order', 'ratchet', 'Four messages delivered as 3, 1, 4, then 1 again (a replay, refused), then a reply, then the late message 2 from the previous chain (from its skipped key).',
      P, [...sends, d('3'), d('1'), d('4'), d('1'), { op: 'encrypt', session: 'bob', kind: KIND_TEXT, content: () => utf8('got 1 3 4'), save: 'r' },
        { op: 'decrypt', session: 'alice', payload: () => sv.r }, d('2')], sv);
  }
  {
    const P = fresh('vec-tamper'), sv: Record<string, Uint8Array> = {};
    sequence('ratchet-reject-tampered', 'ratchet', 'A message with one flipped body byte (offset 500) is refused and the session is unchanged; the untouched message then decrypts.', P,
      [{ op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('x'), save: 'p' },
        { op: 'decrypt', session: 'bob', payload: () => { const t = sv.p.slice(); t[500] ^= 1; return t; } }, { op: 'decrypt', session: 'bob', payload: () => sv.p }], sv);
  }
  {
    const P = fresh('vec-cross'), sv: Record<string, Uint8Array> = {};
    sequence('kem-step-crossing-offers', 'kem-step', "Both sides offer at once: the initiator (Alice) ignores Bob's offer; Bob drops his and answers Alice's; both end at pq_epoch 1.", P,
      [{ op: 'encrypt', session: 'bob', kind: KIND_TEXT, content: () => utf8('hey'), save: 'h' }, { op: 'decrypt', session: 'alice', payload: () => sv.h },
        { op: 'kem_offer', session: 'alice', save: 'oa' }, { op: 'encrypt', session: 'alice', kind: KIND_KEM_STEP, content: () => sv.oa, save: 'oaP' },
        { op: 'kem_offer', session: 'bob', save: 'ob' }, { op: 'encrypt', session: 'bob', kind: KIND_KEM_STEP, content: () => sv.ob, save: 'obP' },
        { op: 'decrypt', session: 'alice', payload: () => sv.obP }, { op: 'decrypt', session: 'bob', payload: () => sv.oaP, save: 'ans' },
        { op: 'encrypt', session: 'bob', kind: KIND_KEM_STEP, content: () => sv.ans, save: 'ansP' }, { op: 'decrypt', session: 'alice', payload: () => sv.ansP },
        ...['x0', 'y0', 'x1', 'y1'].flatMap((t, i): Op[] => { const [f, to] = i % 2 ? ['bob', 'alice'] : ['alice', 'bob'];
          return [{ op: 'encrypt', session: f, kind: KIND_TEXT, content: () => utf8(t), save: t }, { op: 'decrypt', session: to, payload: () => sv[t] }]; })], sv);
  }

  {
    const P = fresh('vec-skip'), sv: Record<string, Uint8Array> = {};
    sequence('ratchet-skipped-key-state', 'ratchet', "Alice sends two messages; Bob receives only the second, so his session keeps the first message's key in skipped (shows the skipped layout).", P,
      [{ op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('first'), save: 'a' }, { op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('second'), save: 'b' },
        { op: 'decrypt', session: 'bob', payload: () => sv.b }], sv);
  }
  {
    const P = fresh('vec-pending'), sv: Record<string, Uint8Array> = {};
    sequence('kem-step-offer-pending', 'kem-step', "Alice starts a KEM step and Bob answers, before any message mixes it in: shows Alice's pending pq_offer, and Bob's pq_secret and tag_key_in_next.", P,
      [{ op: 'encrypt', session: 'bob', kind: KIND_TEXT, content: () => utf8('hey'), save: 'h' }, { op: 'decrypt', session: 'alice', payload: () => sv.h },
        { op: 'kem_offer', session: 'alice', save: 'o' }, { op: 'encrypt', session: 'alice', kind: KIND_KEM_STEP, content: () => sv.o, save: 'oP' },
        { op: 'decrypt', session: 'bob', payload: () => sv.oP }], sv);
  }
  {
    const P = fresh('vec-badoffer'), sv: Record<string, Uint8Array> = {};
    const bad = new Uint8Array(1189).fill(0xff);
    bad.set([1, 0, 0, 0, 1], 0);
    sequence('kem-step-malformed-offer', 'kem-step', 'An offer whose ML-KEM public key fails the FIPS 203 modulus check: the message is received (kind 0x05, no answer), the step is ignored, the conversation continues.', P,
      [{ op: 'encrypt', session: 'bob', kind: KIND_TEXT, content: () => utf8('hey'), save: 'h' }, { op: 'decrypt', session: 'alice', payload: () => sv.h },
        { op: 'encrypt', session: 'alice', kind: KIND_KEM_STEP, content: () => bad, save: 'x' }, { op: 'decrypt', session: 'bob', payload: () => sv.x },
        { op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('still fine'), save: 'y' }, { op: 'decrypt', session: 'bob', payload: () => sv.y }], sv);
  }

  // --- edge cases a receiver must handle (run 2 of the second implementation asked for these) ---
  // Builds an ongoing message like encrypt(), but lets a vector bend the header or the body (test-only).
  function craft(s: Session, kind: number, content: Uint8Array, rand: (n: number) => Uint8Array, bend: { header?: (h: Uint8Array) => void; body?: (b: Uint8Array) => void }) {
    const [cks, mk] = kdfChain(s.cks!);
    s.cks = cks;
    const header = new Uint8Array(HEADER_PT_LEN);
    header.set(s.dhs.pub, 0); header.set(u32(s.pn), 32); header.set(u32(s.ns), 36); header.set(u32(s.pqEpoch), 41);
    bend.header?.(header);
    s.ns++;
    const i = s.tagOut++;
    const tag = chainTag(s.tks, i);
    const hct = seal(headerKey(s.tks, i), header, tag);
    const body = packBody(kind, content, BODY_PT_LEN);
    bend.body?.(body);
    return concat(new Uint8Array([VERSION]), tag, rand(FIELD_LEN), hct, seal(mk, body, concat(s.ad, hct)));
  }
  {
    const P = fresh('vec-edge'), sv: Record<string, Uint8Array> = {};
    const A = P.alice.s, r = P.alice.rec.rand;
    sv.pad = craft(A, KIND_TEXT, utf8('bad padding'), r, { body: (b) => { b[1000] = 1; } });
    sv.reserved = craft(A, KIND_TEXT, utf8('reserved header bytes set'), r, { header: (h) => { h[40] = 0xff; h[45] = 1; h[47] = 0xff; } });
    sv.k7 = encrypt(A, 0x07, utf8('a future kind'), r);
    sv.k2 = encrypt(A, 0x02, utf8('the reserved kind'), r);
    sv.ok = encrypt(A, KIND_TEXT, utf8('still fine'), r);
    P.alice.rec.take(['random_field', 'random_field', 'random_field', 'random_field', 'random_field']);
    sequence('ratchet-receiver-edge-cases', 'ratchet', "Bob receives, in order: a body with non-zero padding (rejected, session unchanged); a header whose reserved flags/trailing bytes are non-zero (received: they are ignored); kind 0x07, unknown (received); kind 0x02, reserved (received); then an ordinary message. Alice's side isn't part of this vector; the payloads are inputs.",
      { bob: P.bob }, ['pad', 'reserved', 'k7', 'k2', 'ok'].map((k): Op => ({ op: 'decrypt', session: 'bob', payload: () => sv[k] })), sv);
  }
  {
    const P = fresh('vec-loworder'), sv: Record<string, Uint8Array> = {};
    sv.p = craft(P.alice.s, KIND_TEXT, utf8('x'), P.alice.rec.rand, { header: (h) => { h.set(new Uint8Array(32), 0); } });
    P.alice.rec.take(['random_field']);
    sequence('ratchet-reject-low-order-ratchet-key', 'ratchet', "A header announcing an all-zero ratchet public key (a low-order point) starts a DH step whose X25519 result is all zero: rejected, session unchanged.",
      { bob: P.bob }, [{ op: 'decrypt', session: 'bob', payload: () => sv.p }], sv);
  }
  {
    const evil = { ...alice, idXPub: new Uint8Array(32) };
    const r1 = new Recorder(detRand('vec-loworder-fc'));
    const f = buildFirstContact(evil, 'alice-21', parseBundle(bundleBytes, bob.ownerPub)!, utf8('boom'), r1.rand, 0);
    r1.take(['ephemeral_x25519_sk', 'mlkem_encaps_m', 'ratchet_x25519_sk']);
    push('first-contact-reject-low-order', 'first-contact', "A first contact whose sender identity key is an all-zero (low-order) point, with the registry agreeing: every X25519 result with it is all zero, so it is rejected.",
      { recipient: bobIn, registry: { 'alice-21': { owner_pub: hex(alice.ownerPub), id_x25519_pub: hex(evil.idXPub) } }, payload: hex(f.payload), rand: {} }, { result: 'reject' });
  }
  {
    const dupMembers = [members[0], { ...members[1], idXPub: members[0].idXPub }];
    const st = makeGroupState(alice, groupId, 1, dupMembers, () => new Uint8Array(32));
    const g2: Groups = new Map();
    const res = receiveGroupState(g2, bob.ownerPub, alice.ownerPub, st);
    push('group-state-duplicate-identity-key', 'groups', 'A group state in which two members share an identity key is valid: only owner keys must be unique (WIRE_FORMAT §4.6).',
      { me_owner_pub: hex(bob.ownerPub), senders: { alice: hex(alice.ownerPub) }, steps: [{ op: 'group_state', from: 'alice', content: hex(st), note: 'duplicate id_x25519_pub, distinct owner keys' }] },
      { results: [res ? { event: res.event, epoch: res.epoch } : { reject: true }] });
  }
  {
    const rc = new Recorder(detRand('vec-cover-fc'));
    const c = coverFirstContact(inboxBucket(bob.idXPub), rc.rand);
    push('cover-first-contact', 'buckets', "A dummy first contact into Bob's inbox bucket (WIRE_FORMAT §4.4): random tag with the bucket's 12 bits, the public key of a random X25519 secret, random rest.",
      { bucket: inboxBucket(bob.idXPub), rand: rc.take(['random_tag', 'ephemeral_x25519_sk', 'random_rest']) }, { payload: hex(c) });
  }
  {
    const aliceSpk = signedPrekey(alice, 1);
    const aliceBundle = makeBundle(alice, aliceSpk, 1_780_000_000n, [], new Uint8Array(32));
    const rc = new Recorder(detRand('vec-crossing'));
    const b2a = buildFirstContact(bob, 'bob-22', parseBundle(aliceBundle, alice.ownerPub)!, utf8('Hello from Bob'), rc.rand, 0);
    const [ta, tb] = [fc.payload.subarray(1, 17), b2a.payload.subarray(1, 17)];
    push('first-contact-crossing', 'first-contact', "Alice and Bob each sent a first contact at the same time (Alice's is the one in first-contact-alice-to-bob). Both keep the session whose first-contact tag is lower, compared bytewise; the other is receive-only for 7 days (WIRE_FORMAT §4.2).",
      { alice_to_bob_tag: hex(ta), bob_to_alice_tag: hex(tb) },
      { keep: crossingKeeps(ta, tb) === 'sent' ? 'alice-to-bob' : 'bob-to-alice', alice_keeps: crossingKeeps(ta, tb), bob_keeps: crossingKeeps(tb, ta) });
    rc.take(['ephemeral_x25519_sk', 'mlkem_encaps_m', 'ratchet_x25519_sk']);
    // Re-contact: a peer that restored from its phrase sends a new first contact to someone who already holds a session.
    const find = (id: string) => V.find((x) => x.id === id)!.expected as any;
    const tagOf = (payload: Uint8Array) => payload.subarray(1, 17);
    const aNew = tagOf(buildFirstContact(alice, 'alice-21', parseBundle(bundleBytes, bob.ownerPub)!, utf8('Restored'), detRand('vec-recontact-a7'), 0).payload);
    const bNew = tagOf(buildFirstContact(bob, 'bob-22', parseBundle(aliceBundle, alice.ownerPub)!, utf8('Restored'), detRand('vec-recontact-b'), 0).payload);
    const cases = [
      { name: "crossing, Alice's view (her first contact still pending)", session: find('first-contact-alice-to-bob').session, current_first_contact_tag: hex(ta), received_tag: hex(tb) },
      { name: "crossing, Bob's view (his first contact still pending)", session: sessionToJson(b2a.session), current_first_contact_tag: hex(tb), received_tag: hex(ta) },
      { name: 'Bob was the responder; Alice restored and sends a new first contact', session: find('first-contact-bob-opens').session, current_first_contact_tag: hex(ta), received_tag: hex(aNew) },
      { name: 'Alice initiated and has received replies; Bob restored and sends a new first contact', session: find('ratchet-conversation').sessions_after.alice, current_first_contact_tag: hex(ta), received_tag: hex(bNew) },
    ];
    for (const c of cases.slice(2)) if (crossingKeeps(unhexU(c.current_first_contact_tag), unhexU(c.received_tag)) !== 'sent') throw new Error(`re-contact case not discriminating: ${c.name}`);
    push('first-contact-recontact', 'first-contact', "A first contact from a peer we already hold a session with (WIRE_FORMAT §4.2). The lower-tag rule applies only if our current session is a first contact we sent and have received nothing on (initiator, no receiving chain yet); any other first contact replaces our session (a peer that restored from its phrase). 'keep-current': the new session becomes receive-only; 'use-new': the current one does. In both re-contact cases the lower-tag rule alone would have kept the current session.",
      { cases }, { results: cases.map((c) => onFirstContactFromKnownPeer(sessionFromJson(c.session), unhexU(c.current_first_contact_tag), unhexU(c.received_tag))) });
  }
  {
    // Replays (WIRE_FORMAT §4.2): a forged payload copying the genuine tag is rejected and not remembered; the genuine
    // first contact opens; the same first contact re-posted is dropped.
    const forged = fc.payload.slice();
    forged[forged.length - 1] ^= 1;
    const bobRand = (V.find((x) => x.id === 'first-contact-bob-opens')!.input as any).rand;
    const seen: SeenFirstContacts = new Map();
    const steps = [{ payload: forged, rand: {} }, { payload: fc.payload, rand: bobRand }, { payload: fc.payload, rand: {} }];
    const results = steps.map((st) => {
      const got = receiveFirstContact(seen, bob, [bobSpk], st.payload, lookup, replay(Object.values(st.rand)), 0);
      if (got === 'replay') return { result: 'replay' };
      if (!got) return { result: 'reject' };
      return { result: 'accept', from: got.from, kind: got.kind, text: str(got.text), session: sessionToJson(got.session) };
    });
    push('first-contact-replay', 'first-contact', "Bob's inbox receives, in order: a forged payload that copies the genuine first contact's tag but fails to open (rejected, and its tag is not remembered); the genuine first contact (opened, as in first-contact-bob-opens); the same first contact re-posted (dropped as a replay, no state changes). seen_after lists the remembered tags with the prekey that opened each.",
      { recipient: bobIn, registry, steps: steps.map((st) => ({ payload: hex(st.payload), rand: st.rand })) },
      { results, seen_after: [...seen].map(([tag, spk_id]) => ({ tag, spk_id })) });
  }
  push('registry-default-names', 'registry', 'Free default names (PROTOCOL_SPEC §3.4): "kv" + base32 of the first 40 bits of BLAKE2b-256(ownerPub || n), n one byte, re-rolls 0-2.',
    { owner_pubs: [hex(alice.ownerPub), hex(bob.ownerPub)] }, { names: [alice.ownerPub, bob.ownerPub].map((o) => [0, 1, 2].map((n) => defaultName(o, n))) });

  {
    const P = fresh('vec-older-key'), sv: Record<string, Uint8Array> = {};
    sequence('ratchet-late-from-older-ratchet-key', 'ratchet', "Alice sends two messages on her first chain; Bob gets only the first and replies; Alice moves to a new ratchet key and sends again; Bob gets that (a DH step that stores the skipped key of her first chain), and only then the late second message from her OLDER ratchet key. It must decrypt from the stored skipped key, with no DH step: skipped keys are looked up first (WIRE_FORMAT §4.1).", P,
      [{ op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('a1'), save: 'a1' }, { op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('a2, late'), save: 'a2' },
        { op: 'decrypt', session: 'bob', payload: () => sv.a1 }, { op: 'encrypt', session: 'bob', kind: KIND_TEXT, content: () => utf8('b1'), save: 'b1' },
        { op: 'decrypt', session: 'alice', payload: () => sv.b1 }, { op: 'encrypt', session: 'alice', kind: KIND_TEXT, content: () => utf8('a3, new ratchet key'), save: 'a3' },
        { op: 'decrypt', session: 'bob', payload: () => sv.a3 }, { op: 'decrypt', session: 'bob', payload: () => sv.a2 }], sv);
  }
  {
    const P = fresh('vec-keep-offer'), sv: Record<string, Uint8Array> = {};
    const bad = new Uint8Array(1189).fill(0xff);
    bad.set([1, 0, 0, 0, 1], 0);
    sequence('kem-step-responder-keeps-offer-on-malformed', 'kem-step', "Bob (the responder) has a KEM offer pending when Alice's offer for the same epoch arrives malformed (its ML-KEM key fails the FIPS 203 check): the step is ignored and changes no state, so Bob's own pending offer is kept (mlkem_encaps_m is still consumed).", P,
      [{ op: 'encrypt', session: 'bob', kind: KIND_TEXT, content: () => utf8('hey'), save: 'h' }, { op: 'decrypt', session: 'alice', payload: () => sv.h },
        { op: 'kem_offer', session: 'bob', save: 'ob' }, { op: 'encrypt', session: 'alice', kind: KIND_KEM_STEP, content: () => bad, save: 'x' },
        { op: 'decrypt', session: 'bob', payload: () => sv.x }], sv);
  }
  {
    const fake = { ...bobSpk, kemPub: new Uint8Array(1184).fill(0xff) };
    const badBundle = makeBundle(bob, fake, 1_780_000_000n, [], new Uint8Array(32));
    push('bundle-reject-bad-mlkem-key', 'bundle', "A correctly signed bundle whose ML-KEM public key fails the FIPS 203 check is invalid (WIRE_FORMAT §3), so it can't become the owner's current bundle.",
      { bundle: hex(badBundle), expected_owner_pub: hex(bob.ownerPub) }, { result: 'reject' });
  }

  // --- conversation settings (kind 0x06) ---
  const prefs = [{ version: 1 as const, epoch: 7, groupId: null, timerOff: true, screenshotProtection: false }, { version: 1 as const, epoch: 0, groupId: null, timerOff: false, screenshotProtection: true }];
  push('settings-encode', 'conversation-settings', 'Preference bodies (kind 0x06 content).', { prefs: prefs.map((p) => ({ epoch: p.epoch, timer_off: p.timerOff, screenshot_protection: p.screenshotProtection })) },
    { contents: prefs.map((p) => hex(encodePrefs(p))) });
  const bad = ['020000000701', '010000000704', '0100000007'];
  push('settings-reject', 'conversation-settings', 'Refused preference bodies: 020000000701 is a version 0x02 body one byte too short for any context (version 0x02 is valid, WIRE_FORMAT §7.1); 010000000704 has an unknown flag bit; 0100000007 is too short for version 0x01.', { contents: bad },
    { results: bad.map((b) => (decodePrefs(new Uint8Array(Buffer.from(b, 'hex'))) ? 'accept' : 'reject')) });
  // Version 0x02 (WIRE_FORMAT §7.1): a context byte, 0x00 = the 1:1 session, 0x01 + 16-byte group ID = a group.
  const v2 = (epoch: number, gid: Uint8Array | null, flags: number) => encodePrefs({ version: 2, epoch, groupId: gid, timerOff: (flags & 1) === 1, screenshotProtection: (flags & 2) === 2 });
  const e2 = v2(1_780_000_000, null, 2);
  push('settings-encode-v2', 'conversation-settings', 'Version 0x02, 1:1 context. Encodes a single member\'s preferences (timer off = false, screenshot protection = on) with no group ID.',
    { version: 2, epoch: 1_780_000_000, context: 0, flags: 2 }, { bytes: hex(e2), length: e2.length });
  const sgid = unhexU((V.find((x) => x.id === 'group-state-encode')!.input as any).group_id);
  const eg = v2(1_780_000_000, sgid, 3);
  push('settings-encode-group', 'conversation-settings', 'Version 0x02, group context. Encodes a member\'s preferences for a specific group, carrying the 16-byte group ID (the one in group-state-encode).',
    { version: 2, epoch: 1_780_000_000, context: 1, group_id: hex(sgid), flags: 3 }, { bytes: hex(eg), length: eg.length });
  const badV2 = [{ context: 0, context_data: hex(sgid) }, { context: 1, context_data: '' }].map((c) => {
    const b = concat(new Uint8Array([2]), u32(1_780_000_000), new Uint8Array([c.context]), unhexU(c.context_data), new Uint8Array([0]));
    return { version: 2, epoch: 1_780_000_000, ...c, flags: 0, content: hex(b) };
  });
  push('settings-reject-v2', 'conversation-settings', 'Version 0x02, bad length for the context. A 1:1 context (0x00) carrying 16 bytes of contextData is rejected; a group context (0x01) with an empty contextData is rejected. content is the assembled body: version ‖ epoch ‖ context ‖ contextData ‖ flags.',
    { cases: badV2 }, { results: badV2.map((c) => (decodePrefs(unhexU(c.content)) ? 'accept' : 'reject')) });
  const P = (off: boolean, shot = false) => ({ version: 1 as const, epoch: 1, groupId: null, timerOff: off, screenshotProtection: shot });
  const cases: [string, { plus: boolean; prefs: ReturnType<typeof P> | null }[]][] = [
    ['all Plus, all want the timer off', [{ plus: true, prefs: P(true) }, { plus: true, prefs: P(true) }]],
    ['all Plus, one wants it on', [{ plus: true, prefs: P(true) }, { plus: true, prefs: P(false) }]],
    ['a free member present', [{ plus: true, prefs: P(true) }, { plus: false, prefs: P(true) }]],
    ["a Plus member's subscription lapsed (now free)", [{ plus: true, prefs: P(true) }, { plus: true, prefs: P(true) }, { plus: false, prefs: P(true, true) }]],
    ['no preferences received yet', [{ plus: true, prefs: null }, { plus: true, prefs: P(true) }]],
    ['screenshot protection from a Plus member', [{ plus: true, prefs: P(false, true) }, { plus: false, prefs: null }]],
    ['screenshot protection from a member who looks free (honoured, SC-0022)', [{ plus: false, prefs: P(false, true) }, { plus: true, prefs: P(false) }]],
  ];
  push('settings-effective', 'conversation-settings', 'Effective settings for a conversation from every member\'s tier (from the registry) and latest preferences.',
    { cases: cases.map(([name, ms]) => ({ name, members: ms.map((m) => ({ plus: m.plus, prefs: m.prefs && { timer_off: m.prefs.timerOff, screenshot_protection: m.prefs.screenshotProtection } })) })) },
    { results: cases.map(([, ms]) => { const e = effectiveSettings(ms); return { timer_seconds: e.timerSeconds, screenshot_protection: e.screenshotProtection }; }) });

  // --- transaction (§5), computed by rusty-kaspa 2.1.0 (tools/lanecheck tx-vector) ---
  const txVec = (id: string, file: string, extra: string, lead = 'A relay-paid transaction carrying the payload of ratchet-conversation step 0 (Kaspaveil-specific rules: WIRE_FORMAT §5).') => {
    const tx = JSON.parse(readFileSync(new URL(`./sources/${file}`, import.meta.url), 'utf8'));
    const { transaction_id, estimated_serialized_size, compute_mass, transient_mass, storage_mass, fee, ...fields } = tx;
    push(id, 'transaction', `${lead}${extra} The transaction ID, size and masses follow Kaspa consensus (rusty-kaspa 2.1.0, see WIRE_FORMAT §5), not this spec; they are included so a transaction builder can be checked. min_fee = 100 sompi × max(compute_mass, normalized transient mass = ⌈transient_mass × 0.5⌉); storage mass has its own block limit and does not enter the fee.`,
      fields, { transaction_id, estimated_serialized_size, compute_mass, transient_mass, storage_mass, min_fee: 100 * Math.max(compute_mass, Math.ceil(transient_mass / 2)), fee_paid: fee });
  };
  txVec('transaction-relay-paid-pot', 'tx-relay-paid-pot.json', ' The input is the treasury spending pot (contracts/treasury_hot.sil) carrying its covenant ID (utxo_covenant_id); the one output is the pot again, with its new state (a different script public key) and a covenant binding to the same covenant ID with authorizing input 0. In a v1 transaction ID an output is hashed as value, script version, script (length-prefixed), then one byte 1 if it has a covenant binding (0 if not), and if so authorizing_input (u16, little-endian) and the 32-byte covenant ID; a binding adds 34 bytes to the estimated serialized size, and to a UTXO\'s storage size 32 bytes for the covenant ID (rusty-kaspa consensus/core/src/hashing/tx.rs, mass/mod.rs).');

  return { description: 'Kaspaveil protocol v1 test vectors (draft). Self-describing: see "format".', format: FORMAT, vectors: V };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL('../vectors/v1.json', import.meta.url), JSON.stringify(buildVectors(), null, 1) + '\n');
  console.log('wrote vectors/v1.json');
}
