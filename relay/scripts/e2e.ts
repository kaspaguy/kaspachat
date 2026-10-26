// End-to-end check of the Phase 2 testnet stack, as a client would use it: two new users register free names,
// get blind tokens, publish bundles, then talk (first contact + reply) through the relay, the treasury pot,
// testnet-10 and the indexer. Usage: node scripts/e2e.ts [relayBase] [indexerBase]
import { createHash, randomBytes } from 'node:crypto';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import {
  KIND_TEXT, buildFirstContact, bundlePayload, bundleTag, decrypt, encrypt, expectedTags, identityFromSeed, inboxBucket,
  makeBundle, openFirstContact, parseBundlePayload, registryBucket, signedPrekey, tagBucket, type Identity, type Session,
} from '../../protocol/src/index.ts';

const RELAY = process.argv[2] ?? 'http://127.0.0.1:5511';
const INDEXER = process.argv[3] ?? 'http://127.0.0.1:5510';
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const enc = new TextEncoder();
const t0 = Date.now();
const log = (s: string) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`);
async function api(base: string, path: string, body?: unknown) {
  const r = await fetch(base + path, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j: any = await r.json();
  if (r.status !== 200) throw new Error(`${path}: ${r.status} ${j.error}`);
  return j;
}
function solve(challenge: string, bits: number) {
  const c = Buffer.from(challenge, 'hex');
  for (let n = 0; ; n++) {
    const nonce = n.toString(16);
    const h = createHash('sha256').update(c).update(nonce).digest();
    let ok = true;
    for (let i = 0; i < bits && ok; i++) if ((h[i >> 3] >> (7 - (i & 7))) & 1) ok = false;
    if (ok) return nonce;
  }
}

type User = { id: Identity; spk: ReturnType<typeof signedPrekey>; name: string; account: string; tokens: any[] };
const cfg = await api(RELAY, '/v1/config');
const pk = unhex(cfg.tokenPublicKey);

async function getTokens(u: User, n: number) {
  const acct = await api(RELAY, '/v1/account', { account: u.account });
  const P = ristretto255_oprf.poprf(enc.encode(acct.info));
  const items = Array.from({ length: n }, () => {
    const input = randomBytes(32);
    return { input, ...P.blind(input, pk) };
  });
  const r = await api(RELAY, '/v1/tokens', { account: u.account, blinded: items.map((i) => hex(i.blinded)) });
  const outs = P.finalizeBatch(items.slice(0, r.evaluated.length).map((it, i) => ({ input: it.input, blind: it.blind, evaluated: unhex(r.evaluated[i]), blinded: it.blinded })), unhex(r.proof), items[0].tweakedKey);
  u.tokens.push(...outs.map((o, i) => ({ info: r.info, input: hex(items[i].input), output: hex(o) })));
  log(`${u.name}: ${outs.length} tokens (proof verified), ${r.remaining} credits left`);
}

async function newUser(label: string): Promise<User> {
  const id = identityFromSeed(randomBytes(64));
  const ch = await api(RELAY, '/v1/pow');
  const s = Date.now();
  const nonce = solve(ch.challenge, ch.bits);
  log(`${label}: proof of work (${ch.bits} bits) in ${((Date.now() - s) / 1000).toFixed(1)}s`);
  // solve() blocks the event loop; a long one outlasts the relay's 5 s keep-alive, and fetch would send the next POST
  // on the connection the relay has already closed. Let the close be seen first (the v0.5.3 deploy, 2026-10-23).
  await new Promise((r) => setImmediate(r));
  const r = await api(RELAY, '/v1/names/default', { owner: hex(id.ownerPub), n: 0, pow: { challenge: ch.challenge, nonce } });
  log(`${label}: registered @${r.name} on-chain (${r.txid.slice(0, 12)}…), ${r.credits} welcome credits`);
  const u: User = { id, spk: signedPrekey(id, 1), name: r.name, account: r.account, tokens: [] };
  const b = await api(RELAY, '/v1/bundle', { payload: hex(bundlePayload(makeBundle(id, u.spk, BigInt(Math.floor(Date.now() / 1000))))) });
  log(`${label}: bundle published (${b.txid.slice(0, 12)}…)`);
  await getTokens(u, 3);
  return u;
}

// Directory lookup as the app does it: the registry bucket for the name, then the bundle bucket for its owner.
async function lookup(name: string) {
  const reg = await api(INDEXER, `/v1/registry/bucket/${registryBucket(name)}`);
  const e = reg.entries.find((x: any) => x.name === name);
  if (!e) return null;
  const owner = unhex(e.owner);
  const tag = bundleTag(owner);
  for (let i = 0; i < 60; i++) {
    const bs = await api(INDEXER, `/v1/bundles/${tagBucket(tag)}`);
    const hit = bs.bundles.find((x: any) => x.tag === hex(tag));
    const bundle = hit && parseBundlePayload(unhex(hit.p), Date.now() / 1000, owner);
    if (bundle) return bundle;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return null;
}

async function poll(bucket: number, since: number, match: (p: Uint8Array) => boolean) {
  for (let i = 0; i < 90; i++) {
    const r = await api(INDEXER, `/v1/bucket/${bucket}?since=${since}`);
    for (const m of r.messages) {
      const p = unhex(m.p);
      if (match(p)) return p;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`nothing arrived in bucket ${bucket}`);
}

const alice = await newUser('alice');
const bob = await newUser('bob');
const bobBundle = await lookup(bob.name);
if (!bobBundle) throw new Error('bob not found');
log(`alice: looked up @${bob.name} (registry bucket + bundle, signature checked against the registry owner key)`);

const since = Date.now() - 5000;
const fc = buildFirstContact(alice.id, alice.name, bobBundle, enc.encode('hi bob, this is alice on testnet-10'));
const s1 = await api(RELAY, '/v1/send', { payload: hex(fc.payload), token: alice.tokens.pop() });
log(`alice: first contact sent via the relay (${s1.txid.slice(0, 12)}…), paid by the treasury pot`);
const sent = Date.now();

const aliceBundle = await lookup(alice.name);
const inbox = inboxBucket(bob.id.idXPub);
let opened: ReturnType<typeof openFirstContact> = null;
await poll(inbox, since, (p) => {
  opened = openFirstContact(bob.id, [bob.spk], p, (n) => (n === alice.name && aliceBundle ? { ownerPub: aliceBundle.ownerPub, idXPub: aliceBundle.idXPub } : null));
  return !!opened;
});
const o = opened!;
log(`bob: first contact from @${o.from}: "${new TextDecoder().decode(o.text)}" (${((Date.now() - sent) / 1000).toFixed(1)}s after sending)`);

const bobSession: Session = o.session;
const reply = encrypt(bobSession, KIND_TEXT, enc.encode('hey alice, got it'));
const s2 = await api(RELAY, '/v1/send', { payload: hex(reply), token: bob.tokens.pop() });
log(`bob: reply sent (${s2.txid.slice(0, 12)}…)`);
const sent2 = Date.now();
const aliceSession = fc.session;
const want = expectedTags(aliceSession);
const buckets = [...new Set(want.map((w) => tagBucket(w.tag)))];
let got: string | null = null;
for (let i = 0; i < 90 && !got; i++) {
  for (const b of buckets) {
    const r = await api(INDEXER, `/v1/bucket/${b}?since=${since}`);
    for (const m of r.messages) {
      const d = decrypt(aliceSession, unhex(m.p));
      if (d) got = new TextDecoder().decode(d.content);
    }
  }
  if (!got) await new Promise((r) => setTimeout(r, 1000));
}
if (!got) throw new Error('reply never arrived');
log(`alice: reply decrypted: "${got}" (${((Date.now() - sent2) / 1000).toFixed(1)}s after sending)`);

// Double spend of a token must be refused.
const used = { ...alice.tokens[0] };
await api(RELAY, '/v1/send', { payload: hex(encrypt(aliceSession, KIND_TEXT, enc.encode('one more'))), token: used });
try {
  await api(RELAY, '/v1/send', { payload: hex(encrypt(aliceSession, KIND_TEXT, enc.encode('again'))), token: used });
  throw new Error('double spend accepted');
} catch (e) {
  if (!String(e).includes('409')) throw e;
  log('relay: a spent token was refused (409)');
}
console.log('E2E PASS');
