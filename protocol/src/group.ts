import { schnorr } from '@noble/curves/secp256k1.js';
import { KIND_GROUP_STATE, KIND_GROUP_TEXT, KIND_TEXT, MAX_TEXT_FIRST_CONTACT, NAME_FIELD_LEN } from './constants.ts';
import { b2, concat, equal, hex, readU32, systemRand, u32, utf8 } from './crypto.ts';
import type { Rand } from './crypto.ts';
import type { Bundle } from './bundle.ts';
import { buildFirstContact, nameField } from './firstContact.ts';
import type { Identity } from './keys.ts';
import { encrypt } from './ratchet.ts';
import type { Session } from './ratchet.ts';

// Groups (cap 4). There is no group key: every group message is sent over each member's own pairwise
// ratchet (one payload per recipient), so forward secrecy, healing and the KEM step all come from the
// pairwise sessions and membership changes need no re-keying. The admin's signed group state
// (kind 0x03) fixes who is in the group at each epoch; group text (kind 0x04) carries its epoch.
export const GROUP_CAP = 4;
export const GROUP_ID_LEN = 16;
export const MSG_ID_LEN = 16;
const MEMBER_LEN = 32 + 32 + NAME_FIELD_LEN; // ownerPub | idXPub | name field
const STATE_FIXED = 1 + GROUP_ID_LEN + 4 + 32 + 1;
const TEXT_HEAD = 1 + GROUP_ID_LEN + 4 + MSG_ID_LEN;

export type GroupMember = { ownerPub: Uint8Array; idXPub: Uint8Array; name: string };
export type GroupState = { groupId: Uint8Array; epoch: number; admin: Uint8Array; members: GroupMember[] };
export type Group = { state: GroupState; epochs: Map<number, string[]>; left: boolean };
export type Groups = Map<string, Group>;

const digest = (bytes: Uint8Array) => b2(concat(utf8('kasveil/v1/group-state'), bytes));


function validMembers(admin: Uint8Array, members: GroupMember[]): boolean {
  const keys = members.map((m) => hex(m.ownerPub));
  return members.length >= 1 && members.length <= GROUP_CAP && new Set(keys).size === keys.length && keys.includes(hex(admin));
}

// ver=1 | groupId | epoch u32 | adminOwnerPub | n u8 | n × (ownerPub | idXPub | name field) | Schnorr signature
export function makeGroupState(admin: Identity, groupId: Uint8Array, epoch: number, members: GroupMember[], rand: Rand = systemRand): Uint8Array {
  if (groupId.length !== GROUP_ID_LEN || epoch < 1 || !validMembers(admin.ownerPub, members)) throw new Error('bad group state');
  const body = concat(
    new Uint8Array([1]), groupId, u32(epoch), admin.ownerPub, new Uint8Array([members.length]),
    ...members.map((m) => concat(m.ownerPub, m.idXPub, nameField(m.name))),
  );
  return concat(body, schnorr.sign(digest(body), admin.ownerSk, rand(32)));
}

export function parseGroupState(c: Uint8Array): GroupState | null {
  if (c.length < STATE_FIXED + 64 || c[0] !== 1) return null;
  const n = c[STATE_FIXED - 1];
  if (c.length !== STATE_FIXED + n * MEMBER_LEN + 64) return null;
  const body = c.subarray(0, c.length - 64);
  const admin = c.slice(1 + GROUP_ID_LEN + 4, 1 + GROUP_ID_LEN + 4 + 32);
  if (!schnorr.verify(c.subarray(c.length - 64), digest(body), admin)) return null;
  const members: GroupMember[] = [];
  for (let i = 0, o = STATE_FIXED; i < n; i++, o += MEMBER_LEN) {
    const len = c[o + 64];
    if (len < 1 || len > NAME_FIELD_LEN - 1) return null;
    members.push({ ownerPub: c.slice(o, o + 32), idXPub: c.slice(o + 32, o + 64), name: new TextDecoder().decode(c.subarray(o + 65, o + 65 + len)) });
  }
  if (!validMembers(admin, members)) return null;
  return { groupId: c.slice(1, 1 + GROUP_ID_LEN), epoch: readU32(c, 1 + GROUP_ID_LEN), admin, members };
}

// Applies a group state received over the pairwise session with `from` (the sender's owner key).
// Only the admin may send it, epochs only move forward, and a group is joined only if it lists `me`.
export function receiveGroupState(groups: Groups, me: Uint8Array, from: Uint8Array, content: Uint8Array):
  { groupId: Uint8Array; epoch: number; event: 'joined' | 'updated' | 'removed' } | null {
  const st = parseGroupState(content);
  if (!st || !equal(from, st.admin)) return null;
  const id = hex(st.groupId);
  const g = groups.get(id);
  const inIt = st.members.some((m) => equal(m.ownerPub, me));
  if (g) {
    if (!equal(g.state.admin, st.admin) || st.epoch <= g.state.epoch) return null;
  } else if (!inIt) return null;
  const group = g ?? { state: st, epochs: new Map(), left: false };
  group.state = st;
  group.epochs.set(st.epoch, st.members.map((m) => hex(m.ownerPub)));
  group.left = !inIt;
  groups.set(id, group);
  return { groupId: st.groupId, epoch: st.epoch, event: !g ? 'joined' : inIt ? 'updated' : 'removed' };
}

// ver=1 | groupId | epoch u32 | msgId (16, the same in every copy of one message) | UTF-8 text
export function makeGroupText(groupId: Uint8Array, epoch: number, msgId: Uint8Array, text: Uint8Array): Uint8Array {
  return concat(new Uint8Array([1]), groupId, u32(epoch), msgId, text);
}

export type GroupText = { groupId: Uint8Array; epoch: number; msgId: Uint8Array; text: Uint8Array; olderEpoch: boolean };

// A group text from `from` to `me`. Returns 'pending' when its group state hasn't arrived yet (different pairwise
// sessions don't keep order between them): the app keeps it and retries after the next group state. Accepted only if
// the state of the text's epoch was seen and lists both the sender and the receiver.
export function receiveGroupText(groups: Groups, me: Uint8Array, from: Uint8Array, c: Uint8Array): GroupText | 'pending' | null {
  if (c.length < TEXT_HEAD || c[0] !== 1) return null;
  const groupId = c.slice(1, 1 + GROUP_ID_LEN);
  const epoch = readU32(c, 1 + GROUP_ID_LEN);
  const g = groups.get(hex(groupId));
  if (!g || epoch > g.state.epoch) return g?.left ? null : 'pending';
  const members = g.epochs.get(epoch);
  if (!members || !members.includes(hex(from)) || !members.includes(hex(me))) return null; // not both members then, or unseen epoch
  return { groupId, epoch, msgId: c.slice(1 + GROUP_ID_LEN + 4, TEXT_HEAD), text: c.slice(TEXT_HEAD), olderEpoch: epoch < g.state.epoch };
}

export const groupRecipients = (g: Group, me: Uint8Array) => g.state.members.filter((m) => !equal(m.ownerPub, me));

// Encrypts one group message for every other current member that has a pairwise session. Members without
// one are returned in `missing`: the app reaches them with `reachByFirstContact`.
export function sendToGroup(
  g: Group, me: Uint8Array, sessions: Map<string, Session>, kind: typeof KIND_GROUP_STATE | typeof KIND_GROUP_TEXT,
  content: Uint8Array, rand: Rand = systemRand,
): { sent: { to: GroupMember; payload: Uint8Array }[]; missing: GroupMember[] } {
  if (g.left) throw new Error('not a member');
  const sent = [], missing = [];
  for (const m of groupRecipients(g, me)) {
    const s = sessions.get(hex(m.ownerPub));
    if (s) sent.push({ to: m, payload: encrypt(s, kind, content, rand) });
    else missing.push(m);
  }
  return { sent, missing };
}

// Reaches a member with no pairwise session. Content that fits a first contact travels in it (one payload). A group
// state never fits (288 bytes for 2 members, more than the 242 a first contact holds), and neither does a long group
// text: then the first contact opens the session with an empty text (kind 0x01, length 0; apps don't show it) and the
// content follows as the first ratchet message on the new session (two payloads, sent in this order).
export function reachByFirstContact(
  me: Identity, myName: string, peer: Bundle, kind: typeof KIND_GROUP_STATE | typeof KIND_GROUP_TEXT, content: Uint8Array,
  rand: Rand = systemRand, now = Date.now(),
): { payloads: Uint8Array[]; session: Session } {
  if (content.length <= MAX_TEXT_FIRST_CONTACT) {
    const fc = buildFirstContact(me, myName, peer, content, rand, now, kind);
    return { payloads: [fc.payload], session: fc.session };
  }
  const fc = buildFirstContact(me, myName, peer, new Uint8Array(0), rand, now, KIND_TEXT);
  return { payloads: [fc.payload, encrypt(fc.session, kind, content, rand)], session: fc.session };
}
