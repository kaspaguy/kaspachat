import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SwapRelay } from '../src/relay.ts';
import { exolix } from '../src/exolix.ts';
import { changenow } from '../src/changenow.ts';
import type { Fetch } from '../src/types.ts';

const PAYOUT = 'kaspa:qpxn8v5y5j802c886l99gmfttqmlzl2dmlkgn2y6ap5f4vwpekddxq7ej6s94';
const BTC = { ticker: 'btc', network: 'btc' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

const EXOLIX_PAGES: Record<string, unknown> = {
  '1': { count: 4, data: [
    { code: 'BTC', name: 'Bitcoin', networks: [{ network: 'BTC' }, { network: 'LIGHTNING' }] },
    { code: 'XMR', name: 'Monero', networks: [{ network: 'XMR' }] },
  ] },
  '2': { count: 4, data: [
    { code: 'LTC', name: 'Litecoin', networks: [{ network: 'LTC' }] },
    { code: 'KAS', name: 'Kaspa', networks: [{ network: 'KAS' }] },
  ] },
};
const CHANGENOW_LIST = [
  { ticker: 'btc', network: 'btc', name: 'Bitcoin', sell: true, isFiat: false },
  { ticker: 'usdt', network: 'trx', name: 'Tether (TRC20)', sell: true, isFiat: false },
  { ticker: 'sol', network: 'sol', name: 'Solana', sell: true, isFiat: false },
  { ticker: 'kas', network: 'kas', name: 'Kaspa', sell: true, isFiat: false },
  { ticker: 'eur', network: 'eur', name: 'Euro', sell: true, isFiat: true },
  { ticker: 'abc', network: 'abc', name: 'Buy-only', sell: false, isFiat: false },
];

/** Fake of both providers' HTTP APIs, recording each request. */
function fakeFetch() {
  const calls: { url: string; init?: RequestInit }[] = [];
  const f: Fetch = async (input, init) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.includes('exolix.com/api/v2/currencies')) return json(EXOLIX_PAGES[new URL(url).searchParams.get('page')!] ?? { count: 4, data: [] });
    if (url.includes('exolix.com/api/v2/rate')) return json({ fromAmount: 1, toAmount: 11558.67, minAmount: 0.09, maxAmount: 185, message: null });
    if (url.includes('exolix.com/api/v2/transactions') && init?.method === 'POST') {
      const b = JSON.parse(String(init.body));
      return json({ id: 'exo123', depositAddress: '4AdUndXHHZ…', depositExtraId: '', amountTo: 11500, withdrawalAddress: b.withdrawalAddress });
    }
    if (url.includes('exolix.com/api/v2/transactions/exo123')) return json({ status: 'success', amountTo: 11498.2, hashIn: { hash: 'in1' }, hashOut: { hash: 'out1' } });
    if (url.includes('changenow.io/v2/exchange/currencies')) return json(CHANGENOW_LIST);
    if (url.includes('changenow.io/v2/exchange/estimated-amount')) return json({ toAmount: 11601.4 });
    if (url.includes('changenow.io/v2/exchange/range')) return json({ minAmount: 0.05, maxAmount: null });
    if (url.includes('changenow.io/v2/exchange/by-id')) return json({ status: 'sending', payinHash: 'p', payoutHash: null, amountTo: null });
    if (url.includes('changenow.io/v2/exchange') && init?.method === 'POST') return json({ id: 'cn9', payinAddress: '8Bxyz…', payinExtraId: null, toAmount: 11600 });
    return json({ message: 'not found' }, 404);
  };
  return { f, calls, quotes: () => calls.filter((c) => c.url.includes('/rate') || c.url.includes('estimated-amount')).length };
}

test('every coin any keyed provider swaps into KAS is offered, XMR and LTC included; KAS, fiat and buy-only coins are not', async () => {
  const { f } = fakeFetch();
  const list = await new SwapRelay([exolix('k', f), changenow('k', f)]).currencies();
  assert.deepEqual(list.map((c) => [c.ticker, c.network, c.providers.join('+')]), [
    ['btc', 'btc', 'Exolix+ChangeNOW'], ['btc', 'lightning', 'Exolix'], ['ltc', 'ltc', 'Exolix'], ['xmr', 'xmr', 'Exolix'],
    ['sol', 'sol', 'ChangeNOW'], ['usdt', 'trx', 'ChangeNOW'],
  ]);
});

test('offers from every keyed provider that lists the coin, best first; a provider without a key is left out', async () => {
  const { f, calls } = fakeFetch();
  const both = new SwapRelay([exolix('exo-key', f), changenow('cn-key', f)]);
  const r = await both.offers(BTC, 1);
  assert.deepEqual(r.offers.map((o) => [o.provider, o.toAmount]), [['ChangeNOW', 11601.4], ['Exolix', 11558.67]]);
  const x = await both.offers({ ticker: 'xmr', network: 'xmr' }, 1);
  assert.deepEqual(x.offers.map((o) => o.provider), ['Exolix'], 'ChangeNOW does not list XMR here, so it is not asked');
  assert.ok(calls.some((c) => c.url.includes('coinFrom=XMR&networkFrom=XMR&coinTo=KAS&networkTo=KAS')));
  const one = new SwapRelay([exolix('exo-key', f), changenow(undefined, f)]);
  assert.deepEqual((await one.offers(BTC, 1)).offers.map((o) => o.provider), ['Exolix']);
  await assert.rejects(both.offers({ ticker: 'doge', network: 'doge' }, 1), /unsupported coin doge on doge/);
});

test('limits and failures show as unavailable, not as errors', async () => {
  const { f } = fakeFetch();
  const broken: Fetch = async (u, i) => (String(u).includes('changenow.io/v2/exchange/estimated-amount') ? json({ message: 'pair is inactive' }, 400) : f(u, i));
  const r = await new SwapRelay([exolix('k', f), changenow('k', broken)]).offers(BTC, 500);
  assert.equal(r.offers.length, 0);
  assert.deepEqual(r.unavailable.map((u) => u.provider), ['Exolix', 'ChangeNOW']);
  assert.match(r.unavailable[0].reason, /maximum 185 BTC/);
  assert.match(r.unavailable[1].reason, /pair is inactive/);
});

test('quotes are cached briefly per coin and amount; the currency list hourly', async () => {
  const { f, calls, quotes } = fakeFetch();
  let t = 0;
  const relay = new SwapRelay([exolix('k', f)], 20_000, () => t);
  await relay.offers(BTC, 0.01);
  await relay.offers(BTC, 0.01);
  assert.equal(quotes(), 1);
  t = 20_001;
  await relay.offers(BTC, 0.01);
  assert.equal(quotes(), 2);
  assert.equal(calls.filter((c) => c.url.includes('/currencies')).length, 2, 'two pages, fetched once');
});

test('a swap always pays the user’s own Kaspa address; anything else is refused', async () => {
  const { f, calls } = fakeFetch();
  const relay = new SwapRelay([exolix('exo-key', f), changenow('cn-key', f)]);
  await assert.rejects(relay.create('Exolix', BTC, 1, 'bc1qsomethingelse'), /kaspa: address/);
  await assert.rejects(relay.create('Exolix', BTC, 1, PAYOUT.slice(0, -5)), /kaspa: address/);
  const s = await relay.create('Exolix', BTC, 1, PAYOUT);
  assert.deepEqual([s.id, s.depositExtraId, s.payout], ['exo123', null, PAYOUT]);
  const sent = JSON.parse(String(calls.at(-1)!.init!.body));
  assert.deepEqual([sent.withdrawalAddress, sent.coinTo, sent.networkFrom], [PAYOUT, 'KAS', 'BTC']);
  assert.equal((calls.at(-1)!.init!.headers as Record<string, string>).Authorization, 'exo-key');
  const c = await relay.create('ChangeNOW', { ticker: 'usdt', network: 'trx' }, 30, PAYOUT, 'TRefund');
  assert.equal(c.depositAddress, '8Bxyz…');
  const body = JSON.parse(String(calls.at(-1)!.init!.body));
  assert.deepEqual([body.address, body.fromCurrency, body.fromNetwork, body.refundAddress], [PAYOUT, 'usdt', 'trx', 'TRefund']);
});

test('status is normalised across providers', async () => {
  const { f } = fakeFetch();
  const relay = new SwapRelay([exolix('k', f), changenow('k', f)]);
  assert.deepEqual(await relay.status('Exolix', 'exo123'), { status: 'finished', payinTx: 'in1', payoutTx: 'out1', kas: 11498.2 });
  assert.deepEqual(await relay.status('ChangeNOW', 'cn9'), { status: 'sending', payinTx: 'p', payoutTx: null, kas: null });
});

test('the quote cache stays bounded whatever amounts callers ask for', async () => {
  const { f, quotes } = fakeFetch();
  let t = 0;
  const relay = new SwapRelay([exolix('exo-key', f)], 20_000, () => t, 3);
  for (const a of [1, 2, 3, 4, 5]) await relay.offers(BTC, a);
  const before = quotes();
  await relay.offers(BTC, 5);
  assert.equal(quotes(), before, 'the newest quote is still cached');
  await relay.offers(BTC, 1);
  assert.ok(quotes() > before, 'the oldest quote was evicted, not kept forever');
  t = 30_000;
  await relay.offers(BTC, 6);
  assert.equal((relay as unknown as { cache: Map<string, unknown> }).cache.size, 1, 'expired quotes are dropped first');
});

test('a swap is only opened for a coin that provider lists, and a positive amount', async () => {
  const { f } = fakeFetch();
  const relay = new SwapRelay([exolix('ex-key', f), changenow('cn-key', f)]);
  await assert.rejects(relay.create('Exolix', { ticker: 'usdt', network: 'trx' }, 30, PAYOUT), /doesn't swap usdt/);
  await assert.rejects(relay.create('Exolix', { ticker: 'nope', network: 'x' }, 1, PAYOUT), /doesn't swap/);
  for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) await assert.rejects(relay.create('Exolix', BTC, bad, PAYOUT), /amount must be positive/);
  await assert.rejects(relay.offers(BTC, Number.POSITIVE_INFINITY), /amount must be positive/);
});
