// Relay against a fake chain daemon and a throwaway MongoDB. Set TEST_MONGO_URL (e.g. mongodb://127.0.0.1:27999);
// without it the suite is skipped. Every call the relay makes to the chain daemon is recorded, so the tests can prove
// that a name is registered once, a bad payload costs no token, and so on.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MongoClient } from 'mongodb';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { bundlePayload, bundleTag, identityFromSeed, makeBundle, signedPrekey } from '../../protocol/src/index.ts';

const MONGO = process.env.TEST_MONGO_URL;
const skip = !MONGO && 'TEST_MONGO_URL not set';
const DB = `kv_relay_test_${randomBytes(4).toString('hex')}`;
const PRICE = 100 * 1e8;

// ---------- fake chain daemon ----------
const calls: string[] = [];
let renewDelayMs = 0;
let received = 0; // what every deposit address has received, unless the test paid it coin by coin (paid)
const paid = new Map<string, { id: string; sompi: number; late: boolean }[]>(); // deposit id -> coins not yet settled
const depositOf = new Map<string, string>(); // address -> deposit id
const coinsOf = (id: string) => paid.get(id) ?? (received > 0 ? [{ id: `${id}:0`, sompi: received, late: false }] : []);
const names = new Map<string, { owner: string; expiry: number }>();
let fake: http.Server;
let chaindUrl = '';
function startFake() {
  fake = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    const path = req.url!;
    calls.push(`${req.method} ${path}`);
    const ok = (o: unknown) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    const body = raw ? JSON.parse(raw) : {};
    if (path.startsWith('/registry/name/')) {
      const e = names.get(decodeURIComponent(path.slice(15)));
      return ok(e ? { taken: true, entry: e } : { taken: false });
    }
    if (path === '/status') return ok({ daa: 1_000 });
    if (path === '/registry/meta') return ok({ shards: [{ state: { price: PRICE } }] });
    if (path === '/deposit') {
      const id = randomBytes(8).toString('hex');
      depositOf.set(`kaspatest:q${id}`, id);
      return ok({ id, address: `kaspatest:q${id}` });
    }
    const fw = /^\/deposit\/([0-9a-f]+)\/forward$/.exec(path);
    if (fw) {
      const coins = paid.get(fw[1]);
      if (coins) paid.set(fw[1], coins.reduce((n, c) => n + c.sompi, 0) >= PRICE ? [] : coins.filter((c) => !c.late)); // settle() takes all, settleLate the old ones
      return ok({ txid: 'fwd' });
    }
    const dg = /^\/deposit\/([0-9a-f]+)$/.exec(path);
    if (dg) {
      const coins = coinsOf(dg[1]);
      return ok({ received: coins.reduce((n, c) => n + c.sompi, 0), coins });
    }
    if (path === '/registry/default' || path === '/registry/prepaid' || path === '/registry/claim') {
      names.set(body.name, { owner: body.owner, expiry: path === '/registry/default' ? 0 : 5_000_000 });
      return ok(path === '/registry/claim' ? { txids: ['c1', 'c2'] } : { txid: `tx-${path.split('/')[2]}` });
    }
    if (path === '/registry/renew') {
      await new Promise((r) => setTimeout(r, renewDelayMs));
      return ok({ txid: 'tx-renew' });
    }
    if (path === '/relay') return ok({ txid: randomBytes(32).toString('hex'), index: 0 });
    if (path.startsWith('/registry/owner/')) return ok({ entries: [...names.values()].filter((e) => path.endsWith(e.owner)) });
    if (path === '/faucet') return ok({ txid: 'faucet' });
    res.writeHead(404).end('{}');
  });
  return new Promise<void>((r) => fake.listen(0, '127.0.0.1', () => { chaindUrl = `http://127.0.0.1:${(fake.address() as any).port}`; r(); }));
}
const count = (prefix: string) => calls.filter((c) => c.startsWith(prefix)).length;

// ---------- relay process ----------
let relay: ChildProcess;
let base = '';
let mongo: MongoClient;
let dataDir = '';
before(async () => {
  if (skip) return;
  await startFake();
  dataDir = mkdtempSync(join(tmpdir(), 'kv-relay-test-'));
  const port = 20_000 + Math.floor(Math.random() * 20_000);
  base = `http://127.0.0.1:${port}`;
  relay = spawn(process.execPath, [new URL('../src/index.ts', import.meta.url).pathname], {
    env: { ...process.env, PORT: String(port), KASPAVEIL_CHAIND: chaindUrl, KASPAVEIL_RELAY_DATA: dataDir, MONGO_URL: MONGO, MONGO_DB: DB, KASPAVEIL_NAME_POW_BITS: '8', KASPAVEIL_PRIVATE_NAMES: '',
      KASPAVEIL_ORDER_TTL_MS: '6000', KASPAVEIL_WATCH_EVERY_MS: '500' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise<void>((resolve, reject) => {
    relay.stdout!.on('data', (d) => String(d).includes('kaspaveil-relay on') && resolve());
    relay.on('exit', (c) => reject(new Error(`relay exited ${c}`)));
  });
  mongo = new MongoClient(MONGO!);
  await mongo.connect();
});
after(async () => {
  if (skip) return;
  relay.kill();
  fake.close();
  await mongo.db(DB).dropDatabase();
  await mongo.close();
  rmSync(dataDir, { recursive: true, force: true });
});

async function api(path: string, body?: unknown) {
  const r = await fetch(base + path, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, json: (await r.json()) as any };
}
function solve(challenge: string, bits: number) {
  const c = Buffer.from(challenge, 'hex');
  for (let n = 0; ; n++) {
    const h = createHash('sha256').update(c).update(n.toString(16)).digest();
    let ok = true;
    for (let i = 0; i < bits && ok; i++) if ((h[i >> 3] >> (7 - (i & 7))) & 1) ok = false;
    if (ok) return n.toString(16);
  }
}
async function pow(kind = '') {
  const ch = (await api(`/v1/pow${kind}`)).json;
  return { challenge: ch.challenge, nonce: solve(ch.challenge, ch.bits) };
}
const owner = () => randomBytes(32).toString('hex');
const claim = () => randomBytes(32).toString('hex');
const until = async (f: () => Promise<boolean>, ms = 15_000) => {
  for (const t0 = Date.now(); Date.now() - t0 < ms; ) {
    if (await f()) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('timed out');
};
const orderStatus = async (id: string) => (await api(`/v1/order/${id}`)).json.status;

test('a proof of work is accepted once', { skip }, async () => {
  const p = await pow();
  assert.equal((await api('/v1/names/default', { owner: owner(), n: 0, pow: p, claim: claim() })).status, 200);
  const again = await api('/v1/names/default', { owner: owner(), n: 0, pow: p, claim: claim() });
  assert.equal(again.status, 400);
  assert.equal(again.json.error, 'challenge used');
});

test('a free name with a used account secret is refused before anything goes on-chain', { skip }, async () => {
  const c = claim();
  assert.equal((await api('/v1/names/default', { owner: owner(), n: 0, pow: await pow(), claim: c })).status, 200);
  const before = count('POST /registry/default');
  const r = await api('/v1/names/default', { owner: owner(), n: 0, pow: await pow(), claim: c });
  assert.equal(r.status, 409);
  assert.equal(count('POST /registry/default'), before);
});

test('a malformed payload costs no token; a token pays once', { skip }, async () => {
  const c = claim();
  await api('/v1/names/default', { owner: owner(), n: 0, pow: await pow(), claim: c });
  const cfg = (await api('/v1/config')).json;
  const acct = (await api('/v1/account', { account: c })).json;
  const P = ristretto255_oprf.poprf(new TextEncoder().encode(acct.info));
  const input = randomBytes(32);
  const b = P.blind(input, Buffer.from(cfg.tokenPublicKey, 'hex'));
  const ev = (await api('/v1/tokens', { account: c, blinded: [Buffer.from(b.blinded).toString('hex')] })).json;
  const [out] = P.finalizeBatch([{ input, blind: b.blind, evaluated: Buffer.from(ev.evaluated[0], 'hex'), blinded: b.blinded }], Buffer.from(ev.proof, 'hex'), b.tweakedKey);
  const token = { info: ev.info, input: input.toString('hex'), output: Buffer.from(out).toString('hex') };
  assert.equal((await api('/v1/send', { token, payload: 'ff' })).status, 400);
  const payload = `01${randomBytes(1535).toString('hex')}`;
  assert.equal((await api('/v1/send', { token, payload })).status, 200);
  assert.equal((await api('/v1/send', { token, payload })).status, 409);
});

test('a paid Plus order registers the name exactly once and creates the account', { skip }, async () => {
  received = PRICE;
  const c = claim();
  const o = (await api('/v1/plus/order', { name: 'zed-42', owner: owner(), months: 1, claim: c })).json;
  await until(async () => (await orderStatus(o.order)) === 'done');
  await new Promise((r) => setTimeout(r, 5_000)); // another processing round must not register again
  assert.equal(count('POST /registry/prepaid'), 1);
  assert.equal((await api('/v1/account', { account: c })).json.kind, 'plus');
  const stored = await mongo.db(DB).collection('orders').findOne({ _id: o.order as any });
  assert.equal(stored!.claim, undefined, 'the order never stores the account secret');
  assert.equal(stored!.claimHash, createHash('sha256').update(c).digest('hex'));
});

test('an account secret already used by an open order is refused', { skip }, async () => {
  received = 0;
  const c = claim();
  assert.equal((await api('/v1/topup/order', { kas: 20, claim: c })).status, 200);
  assert.equal((await api('/v1/topup/order', { kas: 101, claim: claim() })).status, 400); // cap: one order is at most 100 KAS
  assert.equal((await api('/v1/topup/order', { kas: 20, claim: c })).status, 409);
});

test('a slow renewal is sent once, not once per 4-second round', { skip }, async () => {
  names.set('amy-77', { owner: owner(), expiry: 5_000_000 });
  renewDelayMs = 9_000;
  received = 0;
  const o = (await api('/v1/plus/renew', { name: 'amy-77', months: 1, claim: claim() })).json;
  received = PRICE;
  await until(async () => (await orderStatus(o.order)) === 'done', 25_000);
  assert.equal(count('POST /registry/renew'), 1);
  renewDelayMs = 0;
});

test('a paid order whose account secret is taken stops, instead of re-registering forever', { skip }, async () => {
  received = 0;
  const c = claim();
  const o = (await api('/v1/plus/order', { name: 'kim-55', owner: owner(), months: 1, claim: c })).json;
  // Another account appears under the same secret before this order is processed.
  await mongo.db(DB).collection('accounts').insertOne({ _id: createHash('sha256').update(c).digest('hex') as any, kind: 'topup', credits: 1, order: 'someone-else' });
  const before = count('POST /registry/prepaid');
  received = PRICE;
  await until(async () => (await orderStatus(o.order)) === 'failed');
  await new Promise((r) => setTimeout(r, 9_000));
  assert.equal(count('POST /registry/prepaid'), before + 1);
  assert.match((await api(`/v1/order/${o.order}`)).json.error, /account secret already in use/);
});

test('the test faucet is off unless KASPAVEIL_TESTPAY=1', { skip }, async () => {
  assert.equal((await api('/v1/order/testpay/abc', {})).status, 404);
});

test('a malformed %-escape in the path is a 400, not a 500', { skip }, async () => {
  assert.equal((await api('/v1/names/check/%E0%A4%A')).status, 400);
});

test('bundles: own valid bundle relayed; a validly signed bundle under someone else\'s tag or in milliseconds is refused', { skip }, async () => {
  const hx = (b: Uint8Array) => Buffer.from(b).toString('hex');
  const victim = identityFromSeed(randomBytes(64));
  const mallory = identityFromSeed(randomBytes(64));
  for (const id of [victim, mallory]) await api('/v1/names/default', { owner: hx(id.ownerPub), n: 0, pow: await pow(), claim: claim() });
  const sec = BigInt(Math.floor(Date.now() / 1000));
  const forged = bundlePayload(makeBundle(mallory, signedPrekey(mallory, 1), sec));
  forged.set(bundleTag(victim.ownerPub), 1);
  const relayed = count('POST /relay');
  assert.equal((await api('/v1/bundle', { payload: hx(forged) })).status, 400);
  assert.equal((await api('/v1/bundle', { payload: hx(bundlePayload(makeBundle(mallory, signedPrekey(mallory, 1), sec * 1000n))) })).status, 400);
  assert.equal(count('POST /relay'), relayed, 'nothing refused reached the chain');
  assert.equal((await api('/v1/bundle', { payload: hx(bundlePayload(makeBundle(victim, signedPrekey(victim, 1), sec))) })).status, 200);
});

// SC-0024: no payment is lost. The app derives the extras account the same way (engine.ts extraSecret).
const extra = (claim: string) => createHmac('sha256', Buffer.from(claim, 'hex')).update('kaspachat/v1/extra').digest('hex');
const pay = (address: string, sompi: number, late = false) => {
  const id = depositOf.get(address)!;
  const coins = paid.get(id) ?? [];
  coins.push({ id: `${id}:${coins.length}:${randomBytes(2).toString('hex')}`, sompi, late });
  paid.set(id, coins);
};
const perKas = (kas: number) => Math.floor((kas * 1e8 * 0.75) / 421_000);

test('an underpaid order becomes message credits when it expires', { skip }, async () => {
  received = 0;
  const c = claim();
  const o = (await api('/v1/topup/order', { kas: 100, claim: c })).json;
  pay(o.address, 50 * 1e8);
  await until(async () => (await orderStatus(o.order)) === 'credited', 20_000);
  const a = (await api('/v1/account', { account: extra(c) })).json;
  assert.equal(a.kind, 'topup');
  assert.equal(a.credits, perKas(50));
  assert.equal((await api(`/v1/order/${o.order}`)).json.extraSompi, 50 * 1e8);
  assert.equal((await api('/v1/account', { account: c })).status, 404, 'the order itself made no account');
});

test('paying twice: the order completes and the second payment becomes credits, once', { skip }, async () => {
  received = 0;
  const c = claim();
  const o = (await api('/v1/topup/order', { kas: 20, claim: c })).json;
  pay(o.address, 20 * 1e8);
  await until(async () => (await orderStatus(o.order)) === 'done');
  pay(o.address, 20 * 1e8);
  await until(async () => (await api('/v1/account', { account: extra(c) })).status === 200);
  await new Promise((r) => setTimeout(r, 2_000)); // more watch rounds must not credit it again
  assert.equal((await api('/v1/account', { account: extra(c) })).json.credits, perKas(20));
  assert.equal((await api('/v1/account', { account: c })).json.credits, perKas(20), 'the order got exactly its own payment');
});

test('a leftover 3 days old is settled on-chain, and still credited only once', { skip }, async () => {
  received = 0;
  const c = claim();
  const o = (await api('/v1/topup/order', { kas: 100, claim: c })).json;
  pay(o.address, 30 * 1e8, true);
  await until(async () => (await orderStatus(o.order)) === 'credited', 20_000);
  await until(async () => paid.get(depositOf.get(o.address)!)!.length === 0); // settled with settleLate
  assert.ok(count(`POST /deposit/${depositOf.get(o.address)}/forward`) >= 1);
  assert.equal((await api('/v1/account', { account: extra(c) })).json.credits, perKas(30));
});

test('reports: deleted 90 days after arrival, and their message text goes when they are decided', { skip }, async () => {
  const r = await api('/v1/report', { name: 'someone', reason: 'spam', note: 'buy now', messages: [{ from: 'reported', text: 'cheap pills', t: Date.now() }] });
  assert.equal(r.status, 200);
  const reports = mongo.db(DB).collection<any>('reports');
  const ttl = (await reports.indexes()).find((i) => i.key.at === 1);
  assert.equal(ttl?.expireAfterSeconds, 90 * 24 * 3600);
  assert.equal((await reports.findOne({ _id: r.json.id })).messages.length, 1);
  const tool = spawn(process.execPath, [new URL('../scripts/reports.ts', import.meta.url).pathname, 'dismiss', r.json.id, 'test'], {
    env: { ...process.env, MONGO_URL: MONGO, MONGO_DB: DB }, stdio: 'ignore',
  });
  assert.equal(await new Promise((res) => tool.on('exit', res)), 0);
  const done = await reports.findOne({ _id: r.json.id });
  assert.equal(done.status, 'done');
  assert.deepEqual(done.messages, []);
  assert.equal(done.note, '');
  assert.ok(!JSON.stringify(await mongo.db(DB).collection('report_decisions').findOne({ report: r.json.id })).includes('cheap pills'));
});
