import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KIND_NAME, decodeNameUse, encodeNameUse } from '../src/index.ts';

test('name-in-use kind is 0x08 and round-trips', () => {
  assert.equal(KIND_NAME, 0x08);
  const b = encodeNameUse('dog-cat-21');
  assert.deepEqual([...b.subarray(0, 3)], [1, 10, 100]);
  assert.equal(decodeNameUse(b), 'dog-cat-21');
  assert.equal(decodeNameUse(encodeNameUse('a'.repeat(20))), 'a'.repeat(20));
});

test('malformed names are dropped', () => {
  assert.equal(decodeNameUse(Uint8Array.of(1, 0)), null, 'empty');
  assert.equal(decodeNameUse(Uint8Array.of(2, 1, 97)), null, 'version');
  assert.equal(decodeNameUse(Uint8Array.of(1, 2, 97)), null, 'length overruns');
  assert.equal(decodeNameUse(Uint8Array.of(1, 1, 65)), null, 'uppercase');
  assert.equal(decodeNameUse(Uint8Array.of(1, 1, 64)), null, 'not a name character');
  assert.equal(decodeNameUse(new Uint8Array([1, 21, ...new Array(21).fill(97)])), null, 'longer than 20');
  assert.throws(() => encodeNameUse('Bad Name'));
});
