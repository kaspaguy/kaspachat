// Lane filing against a throwaway MongoDB (TEST_MONGO_URL, e.g. mongodb://127.0.0.1:27999; skipped without it).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { MongoClient, type Collection } from 'mongodb';
import { bundlePayload, bundleTag, identityFromSeed, makeBundle, signedPrekey } from '../../protocol/src/index.ts';
import { detRand } from '../../protocol/src/detrand.ts';
import { LANE, fileBlocks, type BundleDoc, type Msg } from '../src/lane.ts';

const MONGO = process.env.TEST_MONGO_URL;
const skip = !MONGO && 'TEST_MONGO_URL not set';
const NOW = 1_780_000_000;
let mongo: MongoClient;
let msgs: Collection<Msg>;
let bundles: Collection<BundleDoc>;
const DB = `kv_indexer_test_${randomBytes(4).toString('hex')}`;
before(async () => {
  if (skip) return;
  mongo = new MongoClient(MONGO!);
  await mongo.connect();
  msgs = mongo.db(DB).collection('messages');
  bundles = mongo.db(DB).collection('bundles');
});
after(async () => {
  if (skip) return;
  await mongo.db(DB).dropDatabase();
  await mongo.close();
});

let n = 0;
const block = (...payloads: Uint8Array[][]) => ({
  verboseData: { hash: `blk${++n}`, isChainBlock: true },
  transactions: payloads.map((ps) => ({ subnetworkId: LANE, payload: Buffer.concat(ps).toString('hex'), verboseData: { transactionId: `tx${++n}`, blockTime: NOW * 1000 } })),
});
const file = (...payloads: Uint8Array[][]) => fileBlocks([block(...payloads)], msgs, bundles, NOW);
const victim = identityFromSeed(detRand('lane-victim')(64));
const mallory = identityFromSeed(detRand('lane-mallory')(64));
const pub = (id: typeof victim, created: number, spkId = 1) => bundlePayload(makeBundle(id, signedPrekey(id, spkId), BigInt(created), [], new Uint8Array(32)));
const held = async (id: typeof victim) => bundles.findOne({ _id: Buffer.from(bundleTag(id.ownerPub)).toString('hex') });

test('messages: each payload of a transaction is filed once; other lanes and odd lengths are ignored', { skip }, async () => {
  const m1 = new Uint8Array(1536).fill(1);
  const m2 = new Uint8Array(1536).fill(2);
  const blk = block([m1, m2]);
  const r = await fileBlocks([blk], msgs, bundles, NOW);
  assert.equal(r.seen, 2);
  assert.equal(r.lastChain, blk.verboseData.hash);
  await fileBlocks([blk], msgs, bundles, NOW);
  assert.equal(await msgs.countDocuments(), 2);
  const other = { verboseData: { hash: 'x' }, transactions: [{ subnetworkId: '00'.repeat(20), payload: Buffer.from(m1).toString('hex'), verboseData: { transactionId: 'o', blockTime: 0 } }, { subnetworkId: LANE, payload: 'ab', verboseData: { transactionId: 'p', blockTime: 0 } }] };
  assert.equal((await fileBlocks([other], msgs, bundles, NOW)).seen, 0);
});

test('bundles: the owner\'s valid bundle is filed; a forged one under their tag is not', { skip }, async () => {
  await file([pub(victim, NOW - 100)]);
  assert.equal((await held(victim))!.c, NOW - 100);
  const forged = pub(mallory, NOW);
  forged.set(bundleTag(victim.ownerPub), 1);
  await file([forged]);
  assert.equal((await held(victim))!.c, NOW - 100, 'the victim\'s keys are untouched');
  assert.equal(await bundles.countDocuments(), 1);
});

test('bundles: an older one (a replay) never replaces a newer one; same time, higher spkId wins', { skip }, async () => {
  await file([pub(victim, NOW - 50)]);
  await file([pub(victim, NOW - 100)]);
  assert.equal((await held(victim))!.c, NOW - 50);
  await file([pub(victim, NOW - 50, 2)]);
  assert.equal((await held(victim))!.k, 2);
  await file([pub(victim, NOW - 50, 1)]);
  assert.equal((await held(victim))!.k, 2);
});

test('bundles: created in milliseconds (far future) is ignored; a pre-fix document is replaced by any valid bundle', { skip }, async () => {
  await file([pub(mallory, NOW * 1000)]);
  assert.equal(await held(mallory), null);
  const tag = Buffer.from(bundleTag(mallory.ownerPub)).toString('hex');
  await bundles.insertOne({ _id: tag, b: 0, p: Buffer.alloc(1536), t: new Date(), tx: 'old' });
  await file([pub(mallory, NOW - 10)]);
  assert.equal((await held(mallory))!.c, NOW - 10);
});
