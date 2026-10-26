import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KIND_NOTICE, NOTICE_POSSIBLE_SCREENSHOT, NOTICE_RECORDING, NOTICE_SCREENSHOT, decodeNotice, encodeNotice } from '../src/index.ts';

test('notice kind is 0x07 and round-trips for 1:1 and group context', () => {
  assert.equal(KIND_NOTICE, 0x07);
  const one = encodeNotice({ groupId: null, event: NOTICE_SCREENSHOT, time: 1_760_000_000 });
  assert.deepEqual([...one], [1, 0, 1, 104, 231, 120, 0]);
  assert.deepEqual(decodeNotice(one), { groupId: null, event: NOTICE_SCREENSHOT, time: 1_760_000_000 });
  const gid = Uint8Array.from({ length: 16 }, (_, i) => i);
  const g = encodeNotice({ groupId: gid, event: NOTICE_RECORDING, time: 5 });
  assert.equal(g.length, 23);
  assert.deepEqual(decodeNotice(g), { groupId: gid, event: NOTICE_RECORDING, time: 5 });
  assert.equal(decodeNotice(encodeNotice({ groupId: null, event: NOTICE_POSSIBLE_SCREENSHOT, time: 0 }))?.event, 2);
});

test('malformed or unknown notices are dropped', () => {
  const ok = encodeNotice({ groupId: null, event: 1, time: 1 });
  assert.equal(decodeNotice(ok.subarray(0, 6)), null, 'short');
  assert.equal(decodeNotice(Uint8Array.of(2, 0, 1, 0, 0, 0, 1)), null, 'version');
  assert.equal(decodeNotice(Uint8Array.of(1, 2, 1, 0, 0, 0, 1)), null, 'context');
  assert.equal(decodeNotice(Uint8Array.of(1, 0, 9, 0, 0, 0, 1)), null, 'unknown event');
  assert.equal(decodeNotice(Uint8Array.of(1, 1, 1, 0, 0, 0, 1)), null, 'group context without id');
  assert.throws(() => encodeNotice({ groupId: null, event: 4, time: 0 }));
});
