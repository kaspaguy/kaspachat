import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildVectors } from '../scripts/gen-vectors.ts';

test('implementation reproduces the published v1 vectors byte for byte', () => {
  const published = JSON.parse(readFileSync(new URL('../vectors/v1.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildVectors(), published);
});
