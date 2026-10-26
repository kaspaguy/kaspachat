import { test } from 'node:test';
import assert from 'node:assert/strict';
import { utf8 } from '../src/crypto.ts';
import { detRand } from '../src/detrand.ts';
import {
  KIND_SETTINGS, TIMER_SECONDS, buildFirstContact, decodePrefs, decrypt, effectiveSettings, encodePrefs, encrypt,
  identityFromSeed, makeBundle, openFirstContact, parseBundle, signedPrekey,
} from '../src/index.ts';
import type { Prefs } from '../src/index.ts';

const p = (timerOff: boolean, screenshotProtection = false): Prefs => ({ version: 1, epoch: 1, groupId: null, timerOff, screenshotProtection });

test('timer: off only when every member is Plus and every member chose off', () => {
  assert.equal(effectiveSettings([{ plus: true, prefs: p(true) }, { plus: true, prefs: p(true) }]).timerSeconds, 0);
  assert.equal(effectiveSettings([{ plus: true, prefs: p(true) }, { plus: true, prefs: p(false) }]).timerSeconds, TIMER_SECONDS, 'one Plus member keeps it on');
  assert.equal(effectiveSettings([{ plus: true, prefs: p(true) }, { plus: false, prefs: p(true) }]).timerSeconds, TIMER_SECONDS, 'a free member keeps it on, whatever they send');
  assert.equal(effectiveSettings([{ plus: true, prefs: p(true) }, { plus: true, prefs: null }]).timerSeconds, TIMER_SECONDS, 'no preference yet = on');
  assert.equal(effectiveSettings([{ plus: true, prefs: p(true) }, { plus: true, prefs: p(true) }, { plus: false, prefs: null }]).timerSeconds, TIMER_SECONDS, 'adding a free member turns it back on');
});

test('screenshot protection: on if any member switches it on, whatever their tier (SC-0022)', () => {
  assert.equal(effectiveSettings([{ plus: true, prefs: p(false, true) }, { plus: false, prefs: null }]).screenshotProtection, true);
  assert.equal(effectiveSettings([{ plus: false, prefs: p(false, true) }, { plus: true, prefs: p(false) }]).screenshotProtection, true, 'honoured from a member whose tier looks free');
  assert.equal(effectiveSettings([{ plus: true, prefs: p(false) }, { plus: false, prefs: null }]).screenshotProtection, false, 'off when nobody switched it on');
});

test('preferences travel encrypted as a kind 0x06 message and round-trip exactly', () => {
  const alice = identityFromSeed(detRand('s-alice')(64));
  const bob = identityFromSeed(detRand('s-bob')(64));
  const spk = signedPrekey(bob, 1);
  const bundle = parseBundle(makeBundle(bob, spk, 1n), bob.ownerPub)!;
  const ra = detRand('s-a'), rb = detRand('s-b');
  const fc = buildFirstContact(alice, 'alice-21', bundle, utf8('hi'), ra);
  const B = openFirstContact(bob, [spk], fc.payload, () => ({ ownerPub: alice.ownerPub, idXPub: alice.idXPub }), rb)!.session;
  const prefs: Prefs = { version: 1, epoch: 7, groupId: null, timerOff: true, screenshotProtection: true };
  const got = decrypt(B, encrypt(fc.session, KIND_SETTINGS, encodePrefs(prefs), ra), rb)!;
  assert.equal(got.kind, KIND_SETTINGS);
  assert.deepEqual(decodePrefs(got.content), prefs);
  const group: Prefs = { version: 2, epoch: 1_780_000_000, groupId: new Uint8Array(16).fill(9), timerOff: false, screenshotProtection: true };
  assert.equal(encodePrefs(group).length, 23);
  assert.deepEqual(decodePrefs(encodePrefs(group)), group, 'group context round trip');
  assert.equal(decodePrefs(new Uint8Array([1, 0, 0, 0, 1, 4])), null, 'unknown flag bits rejected');
  assert.equal(decodePrefs(new Uint8Array([2, 0, 0, 0, 1, 2, 0])), null, 'unknown context rejected');
  assert.equal(decodePrefs(new Uint8Array([3, 0, 0, 0, 1, 0])), null, 'unknown version rejected');
});
