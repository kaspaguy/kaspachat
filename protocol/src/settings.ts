import { KIND_SETTINGS } from './constants.ts';
import { GROUP_ID_LEN } from './group.ts';

// Conversation settings (body kind 0x06). Each member sends their own preferences; every app
// computes the same effective settings from all members' latest preferences plus their tiers,
// which apps read from the registry directory (never from the message itself).
// Version 1: the 1:1 session only. Version 2 adds a context: groupId null = the 1:1 session (context 0x00),
// otherwise the group's 16-byte ID (context 0x01). Version 1 is read as version 2 with context 0x00.
export type Prefs = { version: 1 | 2; epoch: number; groupId: Uint8Array | null; timerOff: boolean; screenshotProtection: boolean };
export const TIMER_SECONDS = 30 * 3600;

const flagsOf = (p: Prefs) => (p.timerOff ? 1 : 0) | (p.screenshotProtection ? 2 : 0);

// v1: version u8 | epoch u32 | flags u8
// v2: version u8 | epoch u32 | context u8 | contextData (0 or 16 bytes) | flags u8
// (flags bit 0 = wants timer off, bit 1 = screenshot protection on)
export function encodePrefs(p: Prefs): Uint8Array {
  if (p.version === 1 && p.groupId) throw new Error('version 1 settings have no group context');
  const n = p.groupId ? GROUP_ID_LEN : 0;
  const b = new Uint8Array(p.version === 1 ? 6 : 7 + n);
  b[0] = p.version;
  new DataView(b.buffer).setUint32(1, p.epoch, false);
  if (p.version === 2) {
    b[5] = p.groupId ? 1 : 0;
    if (p.groupId) b.set(p.groupId, 6);
  }
  b[b.length - 1] = flagsOf(p);
  return b;
}

export function decodePrefs(b: Uint8Array): Prefs | null {
  let groupId: Uint8Array | null = null;
  if (b[0] === 1) {
    if (b.length !== 6) return null;
  } else if (b[0] === 2) {
    if (b.length < 7 || b[5] > 1 || b.length !== 7 + (b[5] === 1 ? GROUP_ID_LEN : 0)) return null;
    if (b[5] === 1) groupId = b.slice(6, 6 + GROUP_ID_LEN);
  } else return null;
  const f = b[b.length - 1];
  if ((f & ~3) !== 0) return null;
  return { version: b[0], epoch: new DataView(b.buffer, b.byteOffset).getUint32(1, false), groupId, timerOff: (f & 1) === 1, screenshotProtection: (f & 2) === 2 };
}

export type Member = { plus: boolean; prefs: Prefs | null };

// Timer: on at 30 hours unless every current member is Plus AND every member has chosen it off.
// A preference to turn it off only counts from a Plus member. Screenshot protection: on if any member
// has switched it on (SC-0022). Apps offer the switch to Plus members only, but receivers honour it from
// anyone, so a stale or wrong view of someone's tier can never leave a protected chat unprotected.
export function effectiveSettings(members: Member[]): { timerSeconds: number; screenshotProtection: boolean } {
  const allPlusOff = members.length > 0 && members.every((m) => m.plus && m.prefs?.timerOff === true);
  return {
    timerSeconds: allPlusOff ? 0 : TIMER_SECONDS,
    screenshotProtection: members.some((m) => m.prefs?.screenshotProtection === true),
  };
}

export { KIND_SETTINGS };
