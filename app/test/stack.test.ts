// The whole stack on one machine: the real app engine (loaded through Vite, as the app bundles it), the real relay and
// indexer, a throwaway MongoDB (TEST_MONGO_URL, e.g. mongodb://127.0.0.1:27999; skipped without it) and fakechain.ts
// in place of kaspad + chaind. Run from app/: TEST_MONGO_URL=… node --test test/stack.test.ts
import 'fake-indexeddb/auto';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MongoClient } from 'mongodb';
import { createServer, type ViteDevServer } from 'vite';
import { startFakeChain } from './fakechain.ts';

const MONGO = process.env.TEST_MONGO_URL;
const skip = !MONGO && 'TEST_MONGO_URL not set';
const DB = `kv_stack_test_${Date.now()}`;
const root = new URL('../', import.meta.url).pathname;
const PASS = 'correct horse';

// The proof-of-work worker, run inline (Node has no Web Worker).
(globalThis as any).Worker = class {
  onmessage: ((e: { data: unknown }) => void) | null = null;
  postMessage({ challenge, bits }: { challenge: string; bits: number }) {
    const c = Buffer.from(challenge, 'hex');
    for (let n = 0; ; n++) {
      const h = createHash('sha256').update(c).update(n.toString(16)).digest();
      let ok = true;
      for (let i = 0; i < bits && ok; i++) if ((h[i >> 3] >> (7 - (i & 7))) & 1) ok = false;
      if (ok) return void setTimeout(() => this.onmessage?.({ data: { nonce: n.toString(16) } }));
    }
  }
  terminate() {}
};

let chain: Awaited<ReturnType<typeof startFakeChain>>;
let relay: ChildProcess;
let indexer: ChildProcess;
let vite: ViteDevServer;
let mongo: MongoClient;
let dataDir = '';
let Engine: any;
let Vault: any;
let newMnemonic: () => string;
const engines: any[] = [];
const logs: string[] = [];

function spawnService(script: string, env: Record<string, string>, ready: string) {
  const p = spawn(process.execPath, [join(root, script)], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  p.stderr!.on('data', (d) => logs.push(`${script}: ${d}`));
  return new Promise<ChildProcess>((resolve, reject) => {
    p.stdout!.on('data', (d) => String(d).includes(ready) && resolve(p));
    p.on('exit', (c) => reject(new Error(`${script} exited ${c}: ${logs.join('')}`)));
  });
}

before(async () => {
  if (skip) return;
  chain = await startFakeChain();
  dataDir = mkdtempSync(join(tmpdir(), 'kv-stack-'));
  const relayPort = 21_000 + Math.floor(Math.random() * 9_000);
  const indexPort = relayPort + 10_000;
  const common = { MONGO_URL: MONGO!, MONGO_DB: DB, KASPAVEIL_CHAIND: chain.url };
  relay = await spawnService('../relay/src/index.ts', { ...common, PORT: String(relayPort), KASPAVEIL_RELAY_DATA: dataDir, KASPAVEIL_NAME_POW_BITS: '8', KASPAVEIL_TESTPAY: '1', KASPAVEIL_PRIVATE_NAMES: '', KASPAVEIL_ORDER_TTL_MS: '10000', KASPAVEIL_WATCH_EVERY_MS: '1000' }, 'kaspaveil-relay on');
  indexer = await spawnService('../indexer/src/index.ts', { ...common, PORT: String(indexPort), KASPAVEIL_JSON_RPC: chain.ws }, 'kaspaveil-indexer on');
  // The app calls /api/relay and /api/index on its own origin, as behind nginx.
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((url: string, init?: RequestInit) => realFetch(String(url).replace(/^\/api\/relay/, `http://127.0.0.1:${relayPort}`).replace(/^\/api\/index/, `http://127.0.0.1:${indexPort}`), init)) as typeof fetch;
  vite = await createServer({ root, logLevel: 'error', appType: 'custom', server: { middlewareMode: true, hmr: false } });
  ({ Engine, newMnemonic } = await vite.ssrLoadModule('/src/lib/engine.ts'));
  ({ Vault } = await vite.ssrLoadModule('/src/lib/vault.ts'));
  mongo = new MongoClient(MONGO!);
  await mongo.connect();
});
after(async () => {
  if (skip) return;
  for (const e of engines) e.stop();
  relay.kill();
  indexer.kill();
  chain.close();
  await vite.close();
  await mongo.db(DB).dropDatabase();
  await mongo.close();
  rmSync(dataDir, { recursive: true, force: true });
});

const until = async (what: string, f: () => boolean | Promise<boolean>, ms = 30_000) => {
  for (const t0 = Date.now(); Date.now() - t0 < ms; await new Promise((r) => setTimeout(r, 250))) if (await f()) return;
  throw new Error(`timed out waiting for ${what}\n${logs.join('')}`);
};
async function user(slot: string, mnemonic = newMnemonic()) {
  const e = new Engine();
  e.vault = new Vault(slot);
  await e.create(mnemonic, PASS);
  await e.loadConfig();
  engines.push(e);
  return Object.assign(e, { mnemonic });
}
// The bundle reaches the directory through the chain and the indexer, as in production.
const published = (e: any) => until(`@${e.st.name}'s keys`, async () => !!(await e.lookup(e.st.name, true).catch(() => null)));
const texts = (e: any, cid: string) => (e.st.convos[cid]?.msgs ?? []).filter((m: any) => !m.note).map((m: any) => m.text);
const dmWith = (e: any, other: any) => `d:${other.ownerHex}`;

let alice: any, bob: any;

test('two new users sign up, publish keys (dated in seconds) and talk', { skip, timeout: 120_000 }, async () => {
  alice = await user('alice');
  bob = await user('bob');
  await alice.registerFree(0);
  await bob.registerFree(0);
  await published(alice);
  await published(bob);
  const held = await mongo.db(DB).collection('bundles').find().toArray();
  assert.ok(held.length === 2 && held.every((b) => b.c > 1_700_000_000 && b.c < 2_000_000_000), 'created is Unix seconds');
  alice.start();
  bob.start();

  const cid = await alice.startChat(bob.st.name);
  await alice.sendText(cid, 'hello bob');
  await until('bob gets the first contact', () => texts(bob, dmWith(bob, alice)).includes('hello bob'));
  assert.equal(bob.st.convos[dmWith(bob, alice)].request, true, 'a first contact arrives as a request');
  await bob.sendText(dmWith(bob, alice), 'hi alice');
  await until('alice gets the reply', () => texts(alice, cid).includes('hi alice'));
});

test('out of credits: messages wait in order and all go out after a top-up', { skip, timeout: 180_000 }, async () => {
  const cid = dmWith(alice, bob);
  for (let i = 1; i <= 12; i++) await alice.sendText(cid, `m${i}`);
  assert.ok(alice.st.outbox.length > 0, 'some messages are waiting');
  assert.match(alice.status.lastError, /out of message credits/);
  const waiting = alice.st.convos[cid].msgs.filter((m: any) => m.state === 'sending').length;
  assert.equal(waiting, alice.st.outbox.length, 'a waiting message shows as sending, not as failed');

  const order = await alice.orderTopup(20);
  await alice.testPay(order);
  await until('the top-up completes', async () => { await alice.pollOrdersNow(); return alice.st.orders[0].status === 'done'; }, 60_000);
  await until('the queue empties', () => alice.st.outbox.length === 0, 60_000);
  await until('bob has m1..m12', () => Array.from({ length: 12 }, (_, i) => `m${i + 1}`).every((t) => texts(bob, dmWith(bob, alice)).includes(t)), 60_000);
  assert.ok(alice.st.convos[cid].msgs.every((m: any) => m.state !== 'sending' && m.state !== 'failed'));
});

test('a crash right after sending never reuses a message key', { skip, timeout: 120_000 }, async () => {
  const cid = dmWith(alice, bob);
  await alice.sendText(cid, 'before the crash');
  // Killed at once: no debounced save gets to run.
  alice.stop();
  alice.vault.lock();
  const again = new Engine();
  again.vault = new Vault('alice');
  engines.push(again);
  assert.ok(await again.unlock(PASS));
  again.start();
  await again.sendText(cid, 'after the crash');
  await until('bob gets the message sent after the crash', () => texts(bob, dmWith(bob, alice)).includes('after the crash'));
  // Every tag on the chain was used by exactly one payload: no message key was derived twice.
  const byTag = new Map<string, string>();
  for (const p of chain.relayed) {
    const tag = p.slice(2, 34);
    assert.ok(!byTag.has(tag) || byTag.get(tag) === p, `tag ${tag} reused for a different payload`);
    byTag.set(tag, p);
  }
  alice = again;
});

test('a group of three, one of whom has no session with another yet', { skip, timeout: 120_000 }, async () => {
  const carol = await user('carol');
  await carol.registerFree(0);
  await published(carol);
  carol.start();
  const gid = await alice.createGroup([bob.st.name, carol.st.name]);
  await until('bob and carol join', () => [bob, carol].every((e) => Object.keys(e.st.convos).includes(gid)));
  await carol.sendText(gid, 'hi both');
  await until('alice and bob get carol\'s group message', () => [alice, bob].every((e) => texts(e, gid).includes('hi both')));
});

test('an underpaid order is not lost: what arrived becomes message credits on the account', { skip, timeout: 120_000 }, async () => {
  const order = await alice.orderTopup(100);
  const o = alice.st.orders.find((x: any) => x.id === order);
  chain.pay(o.address, 50 * 1e8);
  await until('the order is credited and the app finds the credits', async () => {
    await alice.pollOrdersNow();
    return o.status === 'credited' && alice.st.accounts.some((a: any) => a.kind === 'topup' && a.secret !== o.claim);
  }, 60_000);
  assert.equal(o.extraSompi, 50 * 1e8);
  const before = alice.status.credits;
  await alice.refreshCredits();
  assert.ok(alice.status.credits >= Math.floor((50 * 1e8 * 0.75) / 421_000), `credits ${alice.status.credits} (was ${before})`);
});

test('restore from the phrase: names, prekey and paid credits come back', { skip, timeout: 120_000 }, async () => {
  const restored = await user('alice-restored', alice.st.mnemonic);
  const found = await restored.findMyNames();
  await restored.adoptNames(found);
  assert.equal(restored.st.name, alice.st.name);
  assert.equal(restored.st.spkId, alice.st.spkId + 1, 'moves on from the latest published prekey');
  assert.deepEqual(restored.st.oldSpks.map((o: any) => o.id), [alice.st.spkId]);
  assert.ok(restored.st.accounts.some((a: any) => a.kind === 'topup'), 'the paid top-up is found again');
  assert.equal(restored.st.accounts.filter((a: any) => a.kind === 'topup').length, alice.st.accounts.filter((a: any) => a.kind === 'topup').length, 'and the credits from the underpaid order');
  restored.stop();
});

test('no errors in the relay or indexer logs', { skip }, () => {
  assert.deepEqual(logs.filter((l) => !/ExperimentalWarning|--trace-warnings/.test(l)), []);
});
