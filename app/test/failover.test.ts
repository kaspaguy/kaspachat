import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanIndexerUrl, firstAnswer } from '../src/lib/failover.ts';

const down = (e: unknown) => e instanceof Error && e.message === 'down';

test('moves to the next indexer when one is unreachable', async () => {
  const seen: string[] = [];
  const r = await firstAnswer(['a', 'b', 'c'], async (b) => { seen.push(b); if (b !== 'b') throw new Error('down'); return b; }, down);
  assert.equal(r, 'b');
  assert.deepEqual(seen, ['a', 'b']);
});

test('a definite answer from the first indexer is final', async () => {
  const seen: string[] = [];
  await assert.rejects(firstAnswer(['a', 'b'], async (b) => { seen.push(b); throw new Error('not found'); }, down), /not found/);
  assert.deepEqual(seen, ['a']);
});

test('all unreachable: the last error is thrown', async () => {
  await assert.rejects(firstAnswer(['a', 'b'], async () => { throw new Error('down'); }, down), /down/);
});

test('indexer addresses: https or onion only, nothing hidden in them', () => {
  assert.equal(cleanIndexerUrl('https://idx.example.org/api/index/'), 'https://idx.example.org/api/index');
  assert.equal(cleanIndexerUrl('http://abcdefghij.onion/api/index'), 'http://abcdefghij.onion/api/index');
  for (const bad of ['http://idx.example.org', 'ftp://x.org', 'https://u:p@x.org', 'https://x.org/?a=1', 'https://x.org/#f', 'not a url', '']) assert.equal(cleanIndexerUrl(bad), null, bad);
});
