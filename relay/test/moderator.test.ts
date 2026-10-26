import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyModel, features, learn, suggest } from '../scripts/moderator.ts';

const rep = (reason: string, text: string, note = '') => ({ reason, note, group: false, messages: [{ from: 'reported', text }, { from: 'reporter', text: 'who is this' }] });

test('no suggestion before the first decision, then it follows what it was taught', () => {
  const m = emptyModel();
  assert.equal(suggest(m, rep('spam', 'buy cheap coins at www.x.io')), null);
  learn(m, rep('spam', 'buy cheap coins at www.x.io'), 'valid');
  assert.equal(suggest(m, rep('spam', 'cheap coins here https://y.io'))?.verdict, 'valid', 'day 1: one decision is enough to lean');
  learn(m, rep('other', 'you forgot to reply to me yesterday'), 'dismiss');
  learn(m, rep('harassment', 'I know where you live'), 'valid');
  learn(m, rep('other', 'sorry I replied late yesterday'), 'dismiss');
  const s = suggest(m, rep('other', 'you replied late again'))!;
  assert.equal(s.verdict, 'dismiss');
  assert.equal(s.decisions, 4);
  assert.ok(s.confidence > 0.5 && s.confidence < 1);
  assert.ok(s.because.includes('reason:other'));
  assert.equal(suggest(m, rep('spam', 'cheap coins www.z.io'))?.verdict, 'valid');
});

test('features: reporter lines are ignored, each word counts once, links are flagged', () => {
  const f = features(rep('spam', 'Coins coins COINS www.x.io'));
  assert.equal(f.filter((x) => x === 'coins').length, 1);
  assert.ok(f.includes('has:link') && f.includes('reason:spam') && !f.includes('who'));
});

test('words that name Object.prototype members are counted like any other word', () => {
  const m = emptyModel();
  learn(m, rep('spam', 'the constructor of this scam'), 'valid');
  learn(m, rep('spam', 'constructor again'), 'valid');
  assert.equal(m.feats.valid['constructor'], 2);
  assert.ok(Number.isFinite(suggest(m, rep('other', 'constructor'))!.confidence));
});
