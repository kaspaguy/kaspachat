import { test } from 'node:test';
import assert from 'node:assert/strict';
import { utf8 } from '../src/crypto.ts';
import type { Rand } from '../src/crypto.ts';
import { detRand } from '../src/detrand.ts';
import {
  GROUP_CAP, KIND_GROUP_STATE, KIND_GROUP_TEXT, MAX_TEXT, MAX_TEXT_FIRST_CONTACT, PAYLOAD_LEN, buildFirstContact, decrypt, identityFromSeed, makeBundle,
  KIND_TEXT, makeGroupState, makeGroupText, openFirstContact, parseBundle, reachByFirstContact, receiveGroupState, receiveGroupText,
  sendToGroup, signedPrekey,
} from '../src/index.ts';
import type { GroupMember, Groups, Identity, Session } from '../src/index.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const str = (b: Uint8Array) => new TextDecoder().decode(b);

type User = { id: Identity; name: string; rand: Rand; spk: ReturnType<typeof signedPrekey>; sessions: Map<string, Session>; groups: Groups };
const users = new Map<string, User>();
const registry = new Map<string, { ownerPub: Uint8Array; idXPub: Uint8Array }>();

function user(name: string): User {
  const id = identityFromSeed(detRand(`${name}-seed`)(64));
  const u = { id, name, rand: detRand(`${name}-rand`), spk: signedPrekey(id, 1), sessions: new Map(), groups: new Map() };
  users.set(hex(id.ownerPub), u);
  registry.set(name, { ownerPub: id.ownerPub, idXPub: id.idXPub });
  return u;
}
const member = (u: User): GroupMember => ({ ownerPub: u.id.ownerPub, idXPub: u.id.idXPub, name: u.name });
const lookup = (n: string) => registry.get(n) ?? null;

// Delivers a payload from `from` to `to` and routes the result the way an app would.
function deliver(from: User, to: User, payload: Uint8Array) {
  assert.equal(payload.length, PAYLOAD_LEN);
  let kind: number, content: Uint8Array;
  const s = to.sessions.get(hex(from.id.ownerPub));
  if (s) {
    const d = decrypt(s, payload, to.rand, 0);
    if (!d) return null;
    [kind, content] = [d.kind, d.content];
  } else {
    const fc = openFirstContact(to.id, [to.spk], payload, lookup, to.rand, 0);
    if (!fc) return null;
    to.sessions.set(hex(from.id.ownerPub), fc.session);
    [kind, content] = [fc.kind, fc.text];
    if (kind === KIND_TEXT && content.length === 0) return { opener: true };
  }
  if (kind === KIND_GROUP_STATE) return receiveGroupState(to.groups, to.id.ownerPub, from.id.ownerPub, content);
  if (kind === KIND_GROUP_TEXT) return receiveGroupText(to.groups, to.id.ownerPub, from.id.ownerPub, content);
  return { kind, text: str(content) };
}

// Sends group content from `u` to every current member: pairwise where a session exists, first contact otherwise
// (an opener plus the content when it doesn't fit one first contact).
function groupSend(u: User, groupId: Uint8Array, kind: typeof KIND_GROUP_STATE | typeof KIND_GROUP_TEXT, content: Uint8Array) {
  const g = u.groups.get(hex(groupId))!;
  const { sent, missing } = sendToGroup(g, u.id.ownerPub, u.sessions, kind, content, u.rand);
  const out = sent.map((x) => ({ to: users.get(hex(x.to.ownerPub))!, payload: x.payload }));
  for (const m of missing) {
    const peer = users.get(hex(m.ownerPub))!;
    const bundle = parseBundle(makeBundle(peer.id, peer.spk, 1n), peer.id.ownerPub)!;
    const r = reachByFirstContact(u.id, u.name, bundle, kind, content, u.rand, 0);
    u.sessions.set(hex(m.ownerPub), r.session);
    for (const payload of r.payloads) out.push({ to: peer, payload });
  }
  return out;
}

const text = (g: Uint8Array, epoch: number, id: string, t: string) => makeGroupText(g, epoch, utf8(id.padEnd(16, '.')), utf8(t));

test('a group of 4 strangers: state and text reach everyone, members reach each other by first contact', () => {
  const [alice, bob, carol, dave] = ['g1-alice', 'g1-bob', 'g1-carol', 'g1-dave'].map(user);
  const gid = detRand('g1-id')(16);
  const st = makeGroupState(alice.id, gid, 1, [alice, bob, carol, dave].map(member), alice.rand);
  assert.equal(receiveGroupState(alice.groups, alice.id.ownerPub, alice.id.ownerPub, st)!.event, 'joined', 'admin applies its own state');
  const first = groupSend(alice, gid, KIND_GROUP_STATE, st);
  assert.equal(first.length, 6, 'a group state reaches each stranger as an opener plus the state');
  const events = first.map((x) => deliver(alice, x.to, x.payload) as { event?: string; opener?: boolean });
  assert.deepEqual(events.map((e) => (e.opener ? 'opener' : e.event)), ['opener', 'joined', 'opener', 'joined', 'opener', 'joined']);

  // Bob has never talked to Carol or Dave: his short group text reaches them inside a first contact (one payload each).
  const out = groupSend(bob, gid, KIND_GROUP_TEXT, text(gid, 1, 'b1', 'hello all'));
  assert.equal(out.length, 3);
  for (const x of out) {
    const r = deliver(bob, x.to, x.payload);
    assert.ok(r && r !== 'pending' && 'text' in r && str(r.text as Uint8Array) === 'hello all', `to ${x.to.name}`);
  }
  // Now pairwise sessions exist all round; Carol replies over them.
  for (const x of groupSend(carol, gid, KIND_GROUP_TEXT, text(gid, 1, 'c1', 'hi bob'))) {
    const r = deliver(carol, x.to, x.payload) as { text: Uint8Array; olderEpoch: boolean };
    assert.equal(str(r.text), 'hi bob');
    assert.equal(r.olderEpoch, false);
  }
  assert.ok(carol.sessions.has(hex(bob.id.ownerPub)) && carol.sessions.has(hex(dave.id.ownerPub)));
});

test('removal and re-adding: no re-keying, removed member gets nothing new, late old-epoch messages carry a notice', () => {
  const [alice, bob, carol] = ['g2-alice', 'g2-bob', 'g2-carol'].map(user);
  const gid = detRand('g2-id')(16);
  const st1 = makeGroupState(alice.id, gid, 1, [alice, bob, carol].map(member), alice.rand);
  receiveGroupState(alice.groups, alice.id.ownerPub, alice.id.ownerPub, st1);
  for (const x of groupSend(alice, gid, KIND_GROUP_STATE, st1)) deliver(alice, x.to, x.payload);
  for (const x of groupSend(bob, gid, KIND_GROUP_TEXT, text(gid, 1, 'b0', 'setup'))) deliver(bob, x.to, x.payload);
  const late = groupSend(carol, gid, KIND_GROUP_TEXT, text(gid, 1, 'c1', 'sent before my removal')).find((x) => x.to === bob)!;

  // Epoch 2: Carol removed. The state goes to everyone in epoch 1, so Carol learns she's out.
  const st2 = makeGroupState(alice.id, gid, 2, [alice, bob].map(member), alice.rand);
  const oldRecipients = groupSend(alice, gid, KIND_GROUP_STATE, st2);
  receiveGroupState(alice.groups, alice.id.ownerPub, alice.id.ownerPub, st2);
  const events = oldRecipients.map((x) => [x.to.name, (deliver(alice, x.to, x.payload) as { event: string }).event]);
  assert.deepEqual(events, [['g2-bob', 'updated'], ['g2-carol', 'removed']]);

  const next = groupSend(alice, gid, KIND_GROUP_TEXT, text(gid, 2, 'a2', 'carol is out'));
  assert.deepEqual(next.map((x) => x.to.name), ['g2-bob'], 'nothing is produced for a removed member');
  assert.throws(() => groupSend(carol, gid, KIND_GROUP_TEXT, text(gid, 2, 'c2', 'still here?')), /not a member/);

  const r = deliver(carol, bob, late.payload) as { text: Uint8Array; olderEpoch: boolean };
  assert.equal(str(r.text), 'sent before my removal');
  assert.equal(r.olderEpoch, true, 'shown with a notice');

  // Epoch 3: Carol re-added. She receives only from epoch 3 on.
  const st3 = makeGroupState(alice.id, gid, 3, [alice, bob, carol].map(member), alice.rand);
  receiveGroupState(alice.groups, alice.id.ownerPub, alice.id.ownerPub, st3);
  for (const x of groupSend(alice, gid, KIND_GROUP_STATE, st3)) assert.ok(deliver(alice, x.to, x.payload));
  assert.equal(carol.groups.get(hex(gid))!.left, false);
  const back = groupSend(bob, gid, KIND_GROUP_TEXT, text(gid, 3, 'b3', 'welcome back')).find((x) => x.to === carol)!;
  assert.equal(str((deliver(bob, carol, back.payload) as { text: Uint8Array }).text), 'welcome back');
});

test('forgeries and ordering: only the admin moves the group, epochs only go forward, non-members are refused', () => {
  const [alice, bob, carol, eve] = ['g3-alice', 'g3-bob', 'g3-carol', 'g3-eve'].map(user);
  const gid = detRand('g3-id')(16);
  const st1 = makeGroupState(alice.id, gid, 1, [alice, bob, carol].map(member), alice.rand);
  receiveGroupState(alice.groups, alice.id.ownerPub, alice.id.ownerPub, st1);
  assert.ok(receiveGroupState(bob.groups, bob.id.ownerPub, alice.id.ownerPub, st1));

  assert.equal(receiveGroupState(bob.groups, bob.id.ownerPub, carol.id.ownerPub, st1), null, 'state forwarded by a non-admin');
  const byCarol = makeGroupState(carol.id, gid, 2, [carol, bob].map(member), carol.rand);
  assert.equal(receiveGroupState(bob.groups, bob.id.ownerPub, carol.id.ownerPub, byCarol), null, 'a member claiming the group');
  const tampered = makeGroupState(alice.id, gid, 2, [alice, bob, eve].map(member), alice.rand);
  tampered[30] ^= 1;
  assert.equal(receiveGroupState(bob.groups, bob.id.ownerPub, alice.id.ownerPub, tampered), null, 'bad signature');
  assert.equal(receiveGroupState(bob.groups, bob.id.ownerPub, alice.id.ownerPub, st1), null, 'replayed epoch');
  assert.equal(receiveGroupState(eve.groups, eve.id.ownerPub, alice.id.ownerPub, st1), null, 'a state that does not list me');
  const five = ['g3-f1', 'g3-f2'].map(user);
  assert.throws(() => makeGroupState(alice.id, gid, 2, [alice, bob, carol, ...five].map(member), alice.rand), /bad group state/);
  assert.equal(GROUP_CAP, 4);

  assert.equal(receiveGroupText(bob.groups, bob.id.ownerPub, eve.id.ownerPub, text(gid, 1, 'e', 'let me in')), null, 'non-member text');
  assert.equal(receiveGroupText(bob.groups, bob.id.ownerPub, carol.id.ownerPub, text(gid, 2, 'c', 'from the future')), 'pending', 'state not here yet');
  assert.equal(receiveGroupText(carol.groups, carol.id.ownerPub, alice.id.ownerPub, text(gid, 1, 'a', 'group unknown yet')), 'pending');
  const st2 = makeGroupState(alice.id, gid, 2, [alice, bob, carol].map(member), alice.rand);
  receiveGroupState(bob.groups, bob.id.ownerPub, alice.id.ownerPub, st2);
  assert.ok(receiveGroupText(bob.groups, bob.id.ownerPub, carol.id.ownerPub, text(gid, 2, 'c', 'from the future')), 'retry after the state succeeds');
});

test('sizes: a group state needs an opener plus one message; group text limits', () => {
  const [a, b, c, d] = ['g4-aaaaaaaaaaaaaaaaa', 'g4-b', 'g4-c', 'g4-d'].map(user);
  const st = makeGroupState(a.id, new Uint8Array(16), 1, [a, b, c, d].map(member), a.rand);
  assert.equal(st.length, 458);
  assert.ok(makeGroupState(a.id, new Uint8Array(16), 1, [a, b].map(member), a.rand).length > MAX_TEXT_FIRST_CONTACT, 'even a 2-member state');
  const bundle = parseBundle(makeBundle(b.id, b.spk, 1n), b.id.ownerPub)!;
  assert.throws(() => buildFirstContact(a.id, a.name, bundle, st, a.rand, 0, KIND_GROUP_STATE), /too long/);
  const r = reachByFirstContact(a.id, a.name, bundle, KIND_GROUP_STATE, st, a.rand, 0);
  assert.deepEqual(r.payloads.map((p) => p.length), [PAYLOAD_LEN, PAYLOAD_LEN]);
  const short = makeGroupText(new Uint8Array(16), 1, new Uint8Array(16), new Uint8Array(MAX_TEXT_FIRST_CONTACT - 37));
  assert.equal(reachByFirstContact(a.id, a.name, bundle, KIND_GROUP_TEXT, short, a.rand, 0).payloads.length, 1, 'a short group text fits one first contact');
  assert.throws(() => buildFirstContact(a.id, a.name, bundle, st, a.rand, 0, 0x05), /not allowed/);
  assert.equal(makeGroupText(new Uint8Array(16), 1, new Uint8Array(16), new Uint8Array(1367)).length, MAX_TEXT, 'group text: up to 1,367 bytes');
  assert.equal(MAX_TEXT_FIRST_CONTACT - 37, 205, 'group text in a first contact: up to 205 bytes');
});
