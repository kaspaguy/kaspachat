import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TIMER_SECONDS, openVault, purgeExpired, sealVault, vaultKey } from '../src/index.ts';

const H = 3600_000;

test('retention: messages are deleted 30 hours after arrival', () => {
  assert.equal(TIMER_SECONDS, 30 * 3600);
  const now = 100 * H;
  const msgs = [{ arrived: now - 30 * H - 1 }, { arrived: now - 30 * H }, { arrived: now - 30 * H + 1 }, { arrived: now }];
  assert.deepEqual(purgeExpired(msgs, TIMER_SECONDS, now), [{ arrived: now - 30 * H + 1 }, { arrived: now }]);
});

test('retention: nothing is deleted only when the conversation timer is off', () => {
  const msgs = [{ arrived: 0 }];
  assert.deepEqual(purgeExpired(msgs, 0, 1000 * H), msgs);
});

test('vault: round trip, and a wrong passcode or altered blob does not open', () => {
  const salt = new Uint8Array(16).fill(7);
  const key = vaultKey('correct horse', salt);
  const data = { b: new Uint8Array([1, 2, 3]), m: new Map([['k', 5n]]), s: 'hi' };
  const rec = sealVault(key, salt, data);
  assert.notDeepEqual(rec.ct.slice(0, 3), new Uint8Array([1, 2, 3]));
  assert.deepEqual(openVault(key, rec), data);
  assert.throws(() => openVault(vaultKey('wrong', salt), rec));
  const bad = { ...rec, ct: rec.ct.slice() };
  bad.ct[0] ^= 1;
  assert.throws(() => openVault(key, bad));
});
