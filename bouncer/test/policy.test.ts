import { test } from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { checkName, checkPlusName, doorman, loadPatterns, loadReserved } from '../src/policy.ts';

const reserved = loadReserved(new URL('../../registry/reserved/reserved.csv', import.meta.url).pathname);
const patterns = loadPatterns(new URL('../../registry/reserved/patterns.json', import.meta.url).pathname);
const ok = (n: string) => assert.equal(checkName(n, reserved, patterns).allowed, true, `${n} should be allowed`);
const no = (n: string, disposition?: string) => {
  const v = checkName(n, reserved, patterns);
  assert.equal(v.allowed, false, `${n} should be refused`);
  if (disposition && !v.allowed) assert.equal(v.disposition, disposition, `${n}: ${v.reason}`);
};

test('ordinary Plus names go through: the list is not over-broad', () => {
  for (const n of ['dog-cat-21', 'catch22', 'fat-32', 'bob-123', 'badminton-club', 'football-supporter',
    'love-bangkok', 'moon-cat', 'dog-walker', 'paris-nights', 'crypto-bob', 'admiral-9', 'securely-yours',
    'asterisk-fan', 'ethan-21', 'solomon-21', 'solanaceae', 'moneron-lab', 'kasey-21', 'kashmir-tea', 'tethered-kite', 'solid-rock', 'buy-cheap-socks']) ok(n);
});

test('reserved names are refused with the right disposition', () => {
  no('dog', 'auction');
  no('bitcoin', 'protected');
  no('emma', 'auction');
  no('paris', 'auction');
  no('binance', 'protected');
  no('ethereum', 'protected');
  no('kaspa', 'protected');
  no('apple', 'protected');
  no('abc', 'auction');
  no('a', 'blocked');
  no('x7', 'blocked');
  no('-ab');
  no('ab-');
  no('2024', 'auction');
});

test('impersonation is refused, including disguised forms', () => {
  no('kaspaguy-help', 'protected');
  no('realkasveil', 'protected');
  no('realkaspaveil', 'protected');
  no('kaspachat-help', 'protected');
  no('binance-support', 'protected');
  no('binancesupport', 'protected');
  no('official-kaspa', 'protected');
  no('admin', 'protected');
  no('adminbob', 'protected');
  no('verified-trader', 'protected');
});

test('Kaspa and every cryptocurrency name with any suffix are protected (Kaspaguy, 2026-09-29)', () => {
  for (const n of ['kaspa', 'kaspachat', 'kachat', 'kaspa-fan', 'mykaspa', 'kaspa21', 'the-kaspa-army', 'kaschat', 'kas-wallet', 'kaspay',
    'bitcoin-fan', 'bitcoinchat', 'bitcoin21', 'ethereum-news', 'monero-talk', 'solana-dev', 'dogecoin-army', 'cardano4life',
    'btc-pay', 'ethwallet', 'xmr-swap', 'sol-chat', 'doge-army', 'kasia-app',
    // Kaspaguy's list: Kaspa names anywhere, exchanges and tokens with a service suffix
    'kasplex-fan', 'kbeam21', 'binance-hq', 'kraken-team', 'gate-support', 'htx-wallet', 'bitfinex-help', 'ton-app',
    'usdt-verified', 'ada-security', 'okx-admin', 'kasware-team']) no(n, 'protected');
});

test('offensive names and parts are blocked; bad charset refused', () => {
  no('fuck', 'blocked');
  no('fuck-you', 'blocked');
  no('Bob-123');
  no('-bob');
  no('bob_123');
  no('a'.repeat(21));
});

test('Plus names at launch are letters-digits, 2-4 digits, at most 10 characters (Kaspaguy, 2026-10-10)', () => {
  const plus = (n: string) => checkPlusName(n, reserved, patterns);
  for (const n of ['bob-123', 'fat-32', 'ethan-21', 'kasey-21', 'solomon-21', 'a-12', 'moon-9999']) assert.equal(plus(n).allowed, true, `${n} should be allowed`);
  for (const n of ['catch22', 'dog-cat-21', 'badminton-club', 'bob-1', 'bob-12345', 'abcdefgh-12', 'bob12', '12-bob', 'bob-12a', 'solomons-21']) {
    const v = plus(n);
    assert.equal(v.allowed, false, `${n} should be withheld`);
    if (!v.allowed) assert.equal(v.disposition, 'withheld', `${n}: ${v.reason}`);
  }
  for (const [n, d] of [['kaspa-12', 'protected'], ['bitcoin-21', 'protected'], ['admin-12', 'protected'], ['fuck-12', 'blocked']] as const) {
    const v = plus(n);
    assert.equal(v.allowed, false, `${n} should be refused`);
    if (!v.allowed) assert.equal(v.disposition, d, `${n}: ${v.reason}`);
  }
});

test('with Plus on, single names and transfers stay withheld until activated (Kaspaguy, 2026-10-11)', () => {
  const launch = { auctions: true, singleNames: false, transfers: false };
  const d = (a: Parameters<typeof doorman>[0], n: string, active = launch) => doorman(a, n, reserved, patterns, active);
  for (const a of ['register', 'claim-released', 'auction'] as const) {
    assert.equal(d(a, 'bob-123').allowed, true, `${a} bob-123`);
    for (const n of ['bob', 'catch22', 'moon-cat', 'dog']) {
      const v = d(a, n);
      assert.equal(v.allowed, false, `${a} ${n} should be withheld`);
      if (!v.allowed) assert.equal(v.disposition, 'withheld');
    }
  }
  for (const a of ['transfer', 'sell'] as const) {
    const v = d(a, 'bob-123');
    assert.equal(v.allowed, false, `${a} should be withheld`);
    if (!v.allowed) assert.equal(v.disposition, 'withheld');
  }
  const on = { auctions: true, singleNames: true, transfers: true };
  assert.equal(d('register', 'catch22', on).allowed, true);
  assert.equal(d('transfer', 'bob-123', on).allowed, true);
  assert.equal(d('register', 'dog', on).allowed, false);
});

test('the doorman\'s private held names are protected outright and as a part', () => {
  const f = join(mkdtempSync(join(tmpdir(), 'kv-')), 'held.txt');
  writeFileSync(f, 'Zorblax\nquimby\n\n');
  const r = loadReserved(new URL('../../registry/reserved/reserved.csv', import.meta.url).pathname, f);
  for (const n of ['zorblax', 'quimby', 'zorblax-21', 'quimby-123', 'my-quimby']) {
    const v = checkName(n, r, patterns);
    assert.equal(v.allowed, false, `${n} should be refused`);
    if (!v.allowed) assert.deepEqual([v.disposition, v.reason], ['protected', 'reserved'], n);
  }
  assert.equal(checkName('quimbys-21', r, patterns).allowed, true);
  const plusOn = { auctions: false, singleNames: false, transfers: false };
  assert.equal(doorman('register', 'quimby-21', r, patterns, plusOn).allowed, false);
  assert.equal(doorman('register', 'quimby-21', reserved, patterns, plusOn).allowed, true);
});

test('Plus sells launch-shape names; auctions, transfers and sales stay withheld (Kaspaguy, 2026-10-11)', () => {
  for (const a of ['register', 'claim-released'] as const) assert.equal(doorman(a, 'bob-123', reserved, patterns).allowed, true, a);
  for (const a of ['auction', 'transfer', 'sell'] as const) {
    const v = doorman(a, 'bob-123', reserved, patterns);
    assert.equal(v.allowed, false, a);
    if (!v.allowed) assert.equal(v.disposition, 'withheld', a);
  }
  const v = doorman('register', 'catch22', reserved, patterns);
  assert.equal(v.allowed, false);
  if (!v.allowed) assert.equal(v.disposition, 'withheld');
});
