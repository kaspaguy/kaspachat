// Kaspaguy relay + doorman (Phase 2, testnet-10). The public face of the operator's services:
//  - doorman: free default names (proof of work + rate limits), Plus names (launch shape, reserved list), renewals;
//  - credits: blind tokens (RFC 9497 POPRF, ristretto255-SHA512). The token's public `info` is the day its month began
//    ("d:YYYY-MM-DD", accepted for 30 days) or "topup" (never expires): the relay can check a token but not link it to
//    the payment that bought it;
//  - relay: one token pays one message from the treasury's spending pot (chaind); bundles and cover traffic are free
//    within limits;
//  - payments (SC-0018): each order gets its own payment-covenant address (keyless; the 25/75 split is fixed in the
//    contract). Once the full amount is there, chaind settles it and the doorman registers, renews or hands over the
//    name (lapsed names go to the first claimant after grace, Kaspaguy 2026-10-14). KAS only: no swaps in the app.
// No IP logs (PROTOCOL_SPEC §6.3): addresses only ever sit in in-memory rate-limit counters, cleared within minutes.
import http from 'node:http';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { MongoClient, type Collection } from 'mongodb';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { BUNDLE_MARKER, PAYLOAD_LEN, defaultName, parseBundlePayload } from '../../protocol/src/index.ts';
import { doorman, loadPatterns, loadReserved } from '../../bouncer/src/policy.ts';
import { feedbackMail, parseFeedback, smtpSend, type SmtpConf } from './feedback.ts';

const PORT = Number(process.env.PORT ?? 5511);
const CHAIND = process.env.KASPAVEIL_CHAIND ?? 'http://127.0.0.1:5512';
const DATA = process.env.KASPAVEIL_RELAY_DATA ?? '/var/lib/kaspaveil/relay';
const RESERVED = process.env.KASPAVEIL_RESERVED ?? new URL('../../registry/reserved/', import.meta.url).pathname;
const KAS = 100_000_000;
const MSG_FEE = 421_000; // sompi per relay-paid message in 5-message batches, measured on testnet-10 under load 2026-10-14 (SC-0020)
const WELCOME = 10;
const MIN_TOPUP = 20 * KAS;
const MONTH_MS = 30 * 24 * 3600 * 1000;
const TOKEN_DAYS = 30;
const NAME_BITS = Number(process.env.KASPAVEIL_NAME_POW_BITS ?? 22);
const COVER_BITS = 16;
const MAX_BATCH = 100;
const NETWORK = process.env.KASPAVEIL_NETWORK ?? 'testnet-10';
const ORDER_TTL_MS = Number(process.env.KASPAVEIL_ORDER_TTL_MS ?? 2 * 3600_000); // an order waits this long for its full payment
const WATCH_DAYS = 30; // payments to an order's address are credited for this long after the order
const WATCH_EVERY_MS = Number(process.env.KASPAVEIL_WATCH_EVERY_MS ?? 60_000);
// Testnet only: the faucet may pay an order's deposit (POST /v1/order/testpay). Never set on mainnet.
const TESTPAY = process.env.KASPAVEIL_TESTPAY === '1';
// Tester feedback (POST /v1/feedback) is mailed, never stored; off unless the send-only mailbox login is set.
const SMTP: SmtpConf | null = process.env.FEEDBACK_SMTP_USER && process.env.FEEDBACK_SMTP_PASS
  ? { host: process.env.FEEDBACK_SMTP_HOST ?? 'mail.kaspachat.com', port: Number(process.env.FEEDBACK_SMTP_PORT ?? 465), user: process.env.FEEDBACK_SMTP_USER, pass: process.env.FEEDBACK_SMTP_PASS, to: process.env.FEEDBACK_TO ?? 'testnet@kaspachat.com' }
  : null;

// ---------- secrets (testnet; the mainnet relay keys come from the ceremony plan) ----------
mkdirSync(DATA, { recursive: true, mode: 0o700 });
function secret(name: string): Uint8Array {
  const p = `${DATA}/${name}`;
  if (!existsSync(p)) writeFileSync(p, randomBytes(32).toString('hex'), { mode: 0o600 });
  return Buffer.from(readFileSync(p, 'utf8').trim(), 'hex');
}
const POW_KEY = secret('pow.key');
const TOKEN_KEYS = ristretto255_oprf.poprf(new Uint8Array()).deriveKeyPair(secret('token.seed'), new TextEncoder().encode('kaspaveil/v1/relay-tokens'));
const enc = new TextEncoder();
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const sha = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex');
const day = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);

const reserved = loadReserved(`${RESERVED}/reserved.csv`);
const patterns = loadPatterns(`${RESERVED}/patterns.json`);

// ---------- storage ----------
type Account = { _id: string; kind: 'welcome' | 'plus' | 'topup'; credits: number; info: string; start: Date; months: number; monthIdx: number; perMonth: number; name?: string; order?: string };
type Order = {
  _id: string; kind: 'plus' | 'renew' | 'topup' | 'claim'; name?: string; owner?: string; months: number; amount: number; deposit: string; address: string;
  // claimHash = sha256 of the account secret; `claim` (the secret itself) only on orders made before 2026-10-22.
  claimHash?: string; claim?: string; status: 'pending' | 'paid' | 'done' | 'failed' | 'expired' | 'credited'; created: Date; error?: string; txids: string[];
  testpaid?: boolean; active?: boolean; registered?: string;
  // SC-0024: what reaches the order's address and isn't used by the order becomes message credits in the order's extras
  // account (secret = HMAC-SHA256(claim, "kaspachat/v1/extra"), derivable from the phrase). seen = payments counted.
  extraHash?: string; seen?: string[]; extraSompi?: number;
};
const mongo = new MongoClient(process.env.MONGO_URL ?? 'mongodb://127.0.0.1:27017');
await mongo.connect();
const db = mongo.db(process.env.MONGO_DB ?? 'kaspaveil_tn10');
const accounts: Collection<Account> = db.collection('accounts');
const spent: Collection<{ _id: string; at: Date; exp?: Date }> = db.collection('spent');
const orders: Collection<Order> = db.collection('orders');
// Abuse reports (Apple 1.2 / Play UGC policy): only what the reporter chose to send. No IP, no reporter identity.
type Report = { _id: string; name: string; reason: string; note: string; group: boolean; messages: { from: 'reported' | 'reporter'; text: string; t: number }[]; at: Date; status: 'open' | 'done'; action?: string };
const reports: Collection<Report> = db.collection('reports');
const REASONS = ['spam', 'harassment', 'illegal', 'impersonation', 'other'];
// The reference indexer's message store (same database): a relayed message is filed for delivery as soon as the node
// accepts it into its mempool, so recipients don't wait for the pot's chained spends to confirm. The indexer files
// the same transaction again from its block later (no overwrite). Bundles are left to the indexer, which checks them.
const messages = db.collection<{ _id: string; tag: string; b: number; p: Buffer; t: Date; bt: number; blk: string }>('messages');
async function fileForDelivery(txid: string, index: number, payloadHex: string) {
  const p = Buffer.from(payloadHex, 'hex');
  if (p.subarray(17, 49).equals(Buffer.from(BUNDLE_MARKER))) return;
  const tag = p.subarray(1, 17);
  const b = (tag[0] << 4) | (tag[1] >> 4);
  try {
    await messages.updateOne({ _id: `${txid}:${index}` }, { $setOnInsert: { tag: tag.toString('hex'), b, p, t: new Date(), bt: Date.now(), blk: 'mempool' } }, { upsert: true });
  } catch {}
}
await spent.createIndex({ exp: 1 }, { expireAfterSeconds: 0 });
await orders.createIndex({ name: 1 }, { unique: true, partialFilterExpression: { active: true } });
await orders.createIndex({ created: 1 }, { expireAfterSeconds: 90 * 24 * 3600 });
// Reports are deleted 90 days after they arrive; their message text goes as soon as they are decided (reports.ts).
await reports.createIndex({ at: 1 }, { expireAfterSeconds: 90 * 24 * 3600 });

// ---------- helpers ----------
async function chaind(path: string, body?: unknown): Promise<any> {
  const r = await fetch(CHAIND + path, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const text = await r.text();
  if (r.status !== 200) throw new Error(text || `chaind ${r.status}`);
  return JSON.parse(text);
}
const limits = new Map<string, number>();
setInterval(() => limits.clear(), 10 * 60_000);
function over(req: http.IncomingMessage, what: string, max: number) {
  const k = `${what}|${(req.headers['cf-connecting-ip'] as string) ?? req.socket.remoteAddress}`;
  const n = (limits.get(k) ?? 0) + 1;
  limits.set(k, n);
  return n > max;
}
class HttpError extends Error {
  code: number;
  constructor(code: number, msg: string) { super(msg); this.code = code; }
}
const fail = (code: number, msg: string): never => { throw new HttpError(code, msg); };
const isHex = (s: unknown, len: number) => typeof s === 'string' && s.length === len * 2 && /^[0-9a-f]+$/.test(s);
// Account secrets may come from the client (derived from its recovery phrase, so a restore can find them again);
// the relay only ever stores their hash.
const claimFrom = (c: unknown) => (isHex(c, 32) ? (c as string) : randomBytes(32).toString('hex'));
// A restored app may offer the secret of an order still open; it gets a 409 and moves on to the next one.
async function freshClaim(c: unknown) {
  const claim = claimFrom(c);
  const h = sha(claim);
  if ((await accounts.findOne({ _id: h })) || (await orders.findOne({ $or: [{ claimHash: h }, { claim }], status: { $in: ['pending', 'paid'] } }))) fail(409, 'account secret already in use');
  return { claim, claimHash: h, extraHash: sha(extraSecret(claim)) };
}
// The extras account's secret, from the order's account secret (the app derives the same; relay stores only its hash).
const extraSecret = (claim: string) => createHmac('sha256', Buffer.from(claim, 'hex')).update('kaspachat/v1/extra').digest('hex');
// Credits a payment that the order didn't use: top-up credits (never lapse) in the order's extras account.
async function creditExtra(o: Order, sompi: number, ids: string[]) {
  if (!o.extraHash || !ids.length) return;
  const credits = Math.floor((sompi * 0.75) / MSG_FEE);
  await accounts.updateOne(
    { _id: o.extraHash },
    { $setOnInsert: { kind: 'topup', info: 'topup', start: new Date(), months: 1, monthIdx: 0, perMonth: 0, order: o._id }, $inc: { credits } },
    { upsert: true },
  );
  await orders.updateOne({ _id: o._id }, { $addToSet: { seen: { $each: ids } }, $inc: { extraSompi: sompi } });
}

// ---------- proof of work: sha256(challenge || nonce) must start with `bits` zero bits ----------
const POW_TTL_MS = 15 * 60_000;
const usedChallenges = new Map<string, number>(); // challenge -> when it was used
setInterval(() => { for (const [c, at] of usedChallenges) if (Date.now() - at > POW_TTL_MS) usedChallenges.delete(c); }, 60_000);
function newChallenge(bits: number) {
  const body = Buffer.concat([Buffer.from([bits]), Buffer.alloc(8), randomBytes(16)]);
  body.writeBigUInt64BE(BigInt(Date.now()), 1);
  const mac = createHmac('sha256', POW_KEY).update(body).digest().subarray(0, 16);
  return { challenge: Buffer.concat([body, mac]).toString('hex'), bits };
}
function checkPow(p: any, minBits: number) {
  if (!p || !isHex(p.challenge, 41) || typeof p.nonce !== 'string' || p.nonce.length > 32) fail(400, 'proof of work missing');
  const c = Buffer.from(p.challenge, 'hex');
  const body = c.subarray(0, 25);
  if (!timingSafeEqual(createHmac('sha256', POW_KEY).update(body).digest().subarray(0, 16), c.subarray(25))) fail(400, 'bad challenge');
  const bits = c[0];
  if (bits < minBits) fail(400, 'challenge too easy');
  if (Date.now() - Number(c.readBigUInt64BE(1)) > POW_TTL_MS) fail(400, 'challenge expired');
  if (usedChallenges.has(p.challenge)) fail(400, 'challenge used');
  const h = createHash('sha256').update(c).update(p.nonce).digest();
  for (let i = 0; i < bits; i++) if ((h[i >> 3] >> (7 - (i & 7))) & 1) fail(400, 'proof of work does not verify');
  usedChallenges.set(p.challenge, Date.now());
}

// ---------- tokens ----------
function tokenInfoValid(info: string) {
  if (info === 'topup') return true;
  const m = /^d:(\d{4}-\d{2}-\d{2})$/.exec(info);
  if (!m) return false;
  const age = Date.now() - Date.parse(m[1]);
  return age >= -86_400_000 && age < TOKEN_DAYS * 86_400_000;
}
// Plus accounts: each paid month gets its own credits and its own token day; unused credits lapse when the month renews.
function rollMonth(a: Account): Account {
  if (a.kind !== 'plus') return a;
  const idx = Math.floor((Date.now() - a.start.getTime()) / MONTH_MS);
  if (idx <= a.monthIdx) return a;
  if (idx >= a.months) return { ...a, credits: 0, monthIdx: idx };
  return { ...a, credits: a.perMonth, monthIdx: idx, info: `d:${day(a.start.getTime() + idx * MONTH_MS)}` };
}
async function newAccount(claimHash: string, kind: Account['kind'], credits: number, months = 1, name?: string, order?: string) {
  const a: Account = { _id: claimHash, kind, credits, info: kind === 'topup' ? 'topup' : `d:${day()}`, start: new Date(), months, monthIdx: 0, perMonth: credits, name, order };
  await accounts.insertOne(a);
  return a;
}
async function redeem(token: any) {
  if (!token || typeof token.info !== 'string' || !isHex(token.input, 32) || !isHex(token.output, 64)) fail(400, 'token missing');
  if (!tokenInfoValid(token.info)) fail(402, 'token expired');
  const out = ristretto255_oprf.poprf(enc.encode(token.info)).evaluate(TOKEN_KEYS.secretKey, unhex(token.input));
  if (!timingSafeEqual(Buffer.from(out), Buffer.from(token.output, 'hex'))) fail(402, 'invalid token');
  const id = sha(`${token.info}|${token.input}`);
  const exp = token.info === 'topup' ? undefined : new Date(Date.parse(token.info.slice(2)) + (TOKEN_DAYS + 2) * 86_400_000);
  try {
    await spent.insertOne(exp ? { _id: id, at: new Date(), exp } : { _id: id, at: new Date() });
  } catch {
    fail(409, 'token already spent');
  }
  return id;
}
function checkPayload(payload: unknown) {
  if (!isHex(payload, PAYLOAD_LEN) || !(payload as string).startsWith('01')) fail(400, 'payload must be 1,536 bytes, version 1');
}
async function relayPayload(payload: unknown, refund?: string) {
  checkPayload(payload);
  try {
    const r = await chaind('/relay', { payload });
    await fileForDelivery(r.txid, r.index ?? 0, payload as string);
    return r;
  } catch (e) {
    if (refund) await spent.deleteOne({ _id: refund });
    fail(503, `relay: ${(e as Error).message}`);
  }
}

// ---------- orders (testnet stand-in for the payment covenant) ----------
const GRACE_DAA = 25_920_000;
// A registered name is claimable once it has lapsed: held after a reclaim, released, or past expiry + grace.
async function nameStatus(name: string): Promise<'free' | 'taken' | 'claimable'> {
  const r = await chaind(`/registry/name/${encodeURIComponent(name)}`);
  if (!r.taken) return 'free';
  const e = r.entry;
  const zero = e.owner === '00'.repeat(32);
  if (zero) return 'claimable';
  if (e.expiry <= 1) return 'taken';
  const daa = (await chaind('/status')).daa;
  return daa >= e.expiry + GRACE_DAA ? 'claimable' : 'taken';
}
async function priceNow(): Promise<number> {
  const m = await chaind('/registry/meta');
  return m.shards[0].state.price;
}
let processing = false;
async function processOrders() {
  if (processing) return;
  processing = true;
  try {
    await processOrdersOnce();
  } finally {
    processing = false;
  }
}
async function processOrdersOnce() {
  for (const o of await orders.find({ status: { $in: ['pending', 'paid'] } }).toArray()) {
    try {
      if (o.status === 'pending') {
        const d = await chaind(`/deposit/${o.deposit}`);
        const ids: string[] = (d.coins ?? []).map((c: { id: string }) => c.id);
        if (d.received < o.amount) {
          if (Date.now() - o.created.getTime() > ORDER_TTL_MS) {
            // Not paid in full in time: whatever did arrive becomes message credits, nothing is lost.
            await creditExtra(o, d.received, ids);
            await orders.updateOne({ _id: o._id }, { $set: { status: d.received > 0 ? 'credited' : 'expired', active: false } });
          }
          continue;
        }
        const f = await chaind(`/deposit/${o.deposit}/forward`, {});
        await orders.updateOne({ _id: o._id }, { $set: { status: 'paid', amount: d.received, seen: ids }, $push: { txids: f.txid } });
        o.status = 'paid';
        o.amount = d.received;
      }
      if (o.status === 'paid') {
        if (o.kind !== 'topup' && !o.registered) {
          let txid = '';
          if (o.kind === 'plus') txid = (await chaind('/registry/prepaid', { name: o.name, owner: o.owner, months: o.months })).txid;
          if (o.kind === 'renew') txid = (await chaind('/registry/renew', { name: o.name, owner: '00'.repeat(32), months: o.months })).txid;
          if (o.kind === 'claim') txid = (await chaind('/registry/claim', { name: o.name, owner: o.owner, months: o.months })).txids.join(',');
          await orders.updateOne({ _id: o._id }, { $set: { registered: txid }, $push: { txids: txid } });
        }
        const claimHash = o.claimHash ?? sha(o.claim!);
        const perMonth = Math.floor((o.amount * 0.75) / o.months / MSG_FEE);
        try {
          await newAccount(claimHash, o.kind === 'topup' ? 'topup' : 'plus', perMonth, o.kind === 'topup' ? 1 : o.months, o.name, o._id);
        } catch (e) {
          if ((e as { code?: number }).code !== 11000) throw e;
          if ((await accounts.findOne({ _id: claimHash }))?.order !== o._id) {
            await orders.updateOne({ _id: o._id }, { $set: { status: 'failed', active: false, error: 'account secret already in use: credits need a manual fix' } });
            continue;
          }
        }
        await orders.updateOne({ _id: o._id }, { $set: { status: 'done', active: false }, $unset: { claim: '' } });
      }
    } catch (e) {
      const msg = (e as Error).message;
      console.error(`order ${o._id}: ${msg}`);
      if (o.status === 'paid') await orders.updateOne({ _id: o._id }, { $set: { error: msg } });
    }
  }
}
setInterval(() => processOrders().catch((e) => console.error('orders:', e.message)), 4000);

// Payments that arrive after an order is done, expired or credited (a second payment, a late part) are credited as
// they are seen; payments 3 days old that no order will use are settled on-chain with settleLate (payment.sil).
let watching = false;
async function watchPaid() {
  if (watching) return;
  watching = true;
  try {
    const since = new Date(Date.now() - WATCH_DAYS * 86_400_000);
    for (const o of await orders.find({ status: { $in: ['done', 'expired', 'credited', 'failed'] }, created: { $gt: since }, extraHash: { $exists: true } }).toArray()) {
      try {
        const d = await chaind(`/deposit/${o.deposit}`);
        const coins: { id: string; sompi: number; late: boolean }[] = d.coins ?? [];
        const fresh = coins.filter((c) => !(o.seen ?? []).includes(c.id));
        if (fresh.length) await creditExtra(o, fresh.reduce((n, c) => n + c.sompi, 0), fresh.map((c) => c.id));
        if (coins.some((c) => c.late)) await chaind(`/deposit/${o.deposit}/forward`, {});
      } catch (e) {
        console.error(`watch ${o._id}: ${(e as Error).message}`);
      }
    }
  } finally {
    watching = false;
  }
}
setInterval(() => watchPaid().catch((e) => console.error('watch:', e.message)), WATCH_EVERY_MS);

// ---------- routes ----------
async function readBody(req: http.IncomingMessage): Promise<any> {
  let n = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    n += c.length;
    if (n > 64 * 1024) fail(413, 'too large');
    chunks.push(c);
  }
  if (!n) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    return fail(400, 'bad json');
  }
}

const routes: Record<string, (req: http.IncomingMessage, body: any, arg?: string) => Promise<unknown>> = {
  'GET /v1/config': async () => {
    let price = 0;
    try { price = await priceNow(); } catch {}
    return {
      network: NETWORK, tokenPublicKey: hex(TOKEN_KEYS.publicKey), nameBits: NAME_BITS, coverBits: COVER_BITS, welcome: WELCOME,
      plusPrice: price, minTopup: MIN_TOPUP, msgFee: MSG_FEE, creditsPerMonth: Math.floor((price * 0.75) / MSG_FEE), tokenDays: TOKEN_DAYS,
      feedback: !!SMTP,
    };
  },
  'GET /v1/pow': async (req, _b, arg) => {
    if (over(req, 'pow', 60)) fail(429, 'slow down');
    return newChallenge(arg === 'cover' ? COVER_BITS : NAME_BITS);
  },
  // Free default name: kv + 8 characters derived from the owner key, re-rolls n = 0..2 (the contract checks it).
  'POST /v1/names/default': async (req, b) => {
    if (!isHex(b.owner, 32) || ![0, 1, 2].includes(b.n)) fail(400, 'owner and n (0-2)');
    checkPow(b.pow, NAME_BITS);
    if (over(req, 'name', 5)) fail(429, 'too many new names from here; try again later');
    const name = defaultName(unhex(b.owner), b.n);
    const { claim, claimHash } = await freshClaim(b.claim);
    const r = await chaind('/registry/default', { name, owner: b.owner, n: b.n });
    await newAccount(claimHash, 'welcome', WELCOME);
    return { name, txid: r.txid, account: claim, credits: WELCOME };
  },
  'GET /v1/names/check': async (req, _b, arg) => {
    if (over(req, 'check', 120)) fail(429, 'slow down');
    const name = String(arg ?? '');
    const v = doorman('register', name, reserved, patterns);
    if (!v.allowed) return { name, available: false, reason: v.reason };
    const st = await nameStatus(name);
    const held = await orders.findOne({ name, active: true });
    return { name, available: st !== 'taken' && !held, lapsed: st === 'claimable', reason: st === 'taken' ? 'taken' : held ? 'being registered' : undefined };
  },
  // Plus: a chosen launch-shape name, 1-12 months, paid to a one-off deposit address.
  'POST /v1/plus/order': async (req, b) => {
    if (over(req, 'order', 10)) fail(429, 'slow down');
    const name = String(b.name ?? '');
    const months = Number(b.months ?? 1);
    if (!isHex(b.owner, 32) || !Number.isInteger(months) || months < 1 || months > 12) fail(400, 'name, owner, months 1-12');
    const v = doorman('register', name, reserved, patterns);
    if (!v.allowed) fail(400, v.reason);
    const st = await nameStatus(name);
    if (st === 'taken') fail(409, 'taken');
    const lapsed = st === 'claimable';
    const amount = (await priceNow()) * months;
    const { claim, claimHash, extraHash } = await freshClaim(b.claim);
    const dep = await chaind('/deposit', { reservoir: months === 1 ? 'month' : 'long', min: amount });
    const o: Order = { _id: randomBytes(16).toString('hex'), kind: lapsed ? 'claim' : 'plus', name, owner: b.owner, months, amount, deposit: dep.id, address: dep.address, claimHash, extraHash, status: 'pending', created: new Date(), txids: [], active: true };
    try {
      await orders.insertOne(o);
    } catch {
      fail(409, 'being registered');
    }
    return { order: o._id, kind: o.kind, claim, address: dep.address, amount, name, months };
  },
  'POST /v1/plus/renew': async (req, b) => {
    if (over(req, 'order', 10)) fail(429, 'slow down');
    const months = Number(b.months ?? 1);
    const name = String(b.name ?? '');
    if (!Number.isInteger(months) || months < 1 || months > 12) fail(400, 'months 1-12');
    const e = (await chaind(`/registry/name/${encodeURIComponent(name)}`)).entry;
    if (!e || e.expiry <= 1) fail(400, 'not a Pro name');
    const amount = (await priceNow()) * months;
    const { claim, claimHash, extraHash } = await freshClaim(b.claim);
    const dep = await chaind('/deposit', { reservoir: months === 1 ? 'month' : 'long', min: amount });
    const o: Order = { _id: randomBytes(16).toString('hex'), kind: 'renew', name, months, amount, deposit: dep.id, address: dep.address, claimHash, extraHash, status: 'pending', created: new Date(), txids: [] };
    await orders.insertOne(o);
    return { order: o._id, claim, address: dep.address, amount, name, months };
  },
  'POST /v1/topup/order': async (req, b) => {
    if (over(req, 'order', 10)) fail(429, 'slow down');
    const amount = Math.round(Number(b.kas ?? 20) * KAS);
    if (!(amount >= MIN_TOPUP && amount <= 10_000 * KAS)) fail(400, 'top-up 20-10,000 KAS');
    const { claim, claimHash, extraHash } = await freshClaim(b.claim);
    const dep = await chaind('/deposit', { reservoir: 'topup', min: amount });
    const o: Order = { _id: randomBytes(16).toString('hex'), kind: 'topup', months: 1, amount, deposit: dep.id, address: dep.address, claimHash, extraHash, status: 'pending', created: new Date(), txids: [] };
    await orders.insertOne(o);
    return { order: o._id, claim, address: dep.address, amount };
  },
  'GET /v1/order': async (_req, _b, arg) => {
    const o = await orders.findOne({ _id: String(arg) });
    if (!o) fail(404, 'no such order');
    return { order: o!._id, kind: o!.kind, status: o!.status, name: o!.name, months: o!.months, amount: o!.amount, address: o!.address, txids: o!.txids, error: o!.error, extraSompi: o!.extraSompi ?? 0 };
  },
  // Testnet only: the Kaspaguy faucet pays the order's deposit address, so volunteers can try Plus without test coins.
  'POST /v1/order/testpay': async (req, _b, arg) => {
    if (!TESTPAY) fail(404, 'not found');
    if (over(req, 'testpay', 6)) fail(429, 'slow down');
    const o = await orders.findOne({ _id: String(arg) });
    if (!o || o.status !== 'pending') fail(400, 'order not pending');
    if (o!.testpaid) fail(409, 'already paid by the test faucet');
    await orders.updateOne({ _id: o!._id }, { $set: { testpaid: true } });
    const r = await chaind('/faucet', { address: o!.address, sompi: o!.amount });
    return { txid: r.txid };
  },
  // Blind tokens: the client sends blinded inputs for one account; one credit each.
  'POST /v1/tokens': async (req, b) => {
    if (over(req, 'tokens', 120)) fail(429, 'slow down');
    if (!isHex(b.account, 32) || !Array.isArray(b.blinded) || b.blinded.length < 1 || b.blinded.length > MAX_BATCH || !b.blinded.every((x: unknown) => isHex(x, 32))) fail(400, 'account and 1-100 blinded elements');
    const id = sha(b.account);
    let a = await accounts.findOne({ _id: id });
    if (!a) fail(404, 'no such account');
    const rolled = rollMonth(a!);
    if (rolled !== a) {
      await accounts.updateOne({ _id: id, monthIdx: a!.monthIdx }, { $set: { credits: rolled.credits, monthIdx: rolled.monthIdx, info: rolled.info } });
      a = await accounts.findOne({ _id: id });
    }
    const want = Math.min(b.blinded.length, a!.credits);
    if (want === 0) fail(402, 'no credits left');
    const r = await accounts.updateOne({ _id: id, credits: { $gte: want }, info: a!.info }, { $inc: { credits: -want } });
    if (r.modifiedCount !== 1) fail(409, 'retry');
    const ev = ristretto255_oprf.poprf(enc.encode(a!.info)).blindEvaluateBatch(TOKEN_KEYS.secretKey, b.blinded.slice(0, want).map(unhex));
    return { info: a!.info, evaluated: ev.evaluated.map(hex), proof: hex(ev.proof), remaining: a!.credits - want, kind: a!.kind };
  },
  'POST /v1/account': async (req, b) => {
    if (over(req, 'tokens', 120)) fail(429, 'slow down');
    if (!isHex(b.account, 32)) fail(400, 'account');
    const a = await accounts.findOne({ _id: sha(b.account) });
    if (!a) fail(404, 'no such account');
    const r = rollMonth(a!);
    return { kind: r.kind, credits: r.credits, info: r.info, months: r.months, monthIdx: r.monthIdx, start: r.start.getTime(), name: r.name };
  },
  // One token pays one message.
  'POST /v1/send': async (_req, b) => {
    checkPayload(b.payload);
    const id = await redeem(b.token);
    return relayPayload(b.payload, id);
  },
  // Bundles (public keys) are free: the owner must hold a registered name; a few per owner per day.
  'POST /v1/bundle': async (req, b) => {
    if (!isHex(b.payload, PAYLOAD_LEN)) fail(400, 'payload');
    const bundle = parseBundlePayload(unhex(b.payload), Date.now() / 1000);
    if (!bundle) fail(400, 'not a valid bundle publication (marker, own tag, signature, created in seconds)');
    const owner = hex(bundle!.ownerPub);
    if (over(req, `bundle|${owner}`, 5)) fail(429, 'too many bundle updates');
    const names = (await chaind(`/registry/owner/${owner}`)).entries;
    if (!names.length) fail(403, 'register a name first');
    return relayPayload(b.payload);
  },
  'POST /v1/report': async (req, b) => {
    if (over(req, 'report', 10)) fail(429, 'too many reports, try again later');
    if (typeof b.name !== 'string' || !/^[a-z0-9-]{1,20}$/.test(b.name) || !REASONS.includes(b.reason)) fail(400, 'name and reason');
    const msgs = Array.isArray(b.messages) ? b.messages.slice(0, 20) : [];
    if (!msgs.every((m: any) => (m.from === 'reported' || m.from === 'reporter') && typeof m.text === 'string' && Number.isFinite(m.t))) fail(400, 'messages');
    const id = randomBytes(8).toString('hex');
    await reports.insertOne({
      _id: id, name: b.name, reason: b.reason, note: String(b.note ?? '').slice(0, 1000), group: !!b.group, at: new Date(), status: 'open',
      messages: msgs.map((m: any) => ({ from: m.from, text: m.text.slice(0, 2000), t: m.t })),
    });
    return { ok: true, id };
  },
  'POST /v1/feedback': async (req, b) => {
    if (!SMTP) fail(404, 'not found');
    if (over(req, 'feedback', 5)) fail(429, 'thanks! that is a lot of feedback at once, try again in a few minutes');
    const f = parseFeedback(b, NETWORK);
    if (typeof f === 'string') fail(400, f);
    await smtpSend(SMTP!, feedbackMail(f as Exclude<typeof f, string>, SMTP!.user, SMTP!.to)).catch((e) => {
      console.error('feedback:', (e as Error).message.slice(0, 120));
      fail(502, 'could not send right now, please try again later');
    });
    return { ok: true };
  },
  // Cover traffic: indistinguishable on-chain, paid by the treasury; a small proof of work per message.
  'POST /v1/cover': async (req, b) => {
    if (over(req, 'cover', 12)) fail(429, 'cover budget reached');
    checkPow(b.pow, COVER_BITS);
    return relayPayload(b.payload);
  },
};

const server = http.createServer(async (req, res) => {
  const send = (code: number, body: unknown) => {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };
  try {
    const url = new URL(req.url ?? '/', 'http://x');
    const parts = url.pathname.split('/').filter(Boolean);
    let h = routes[`${req.method} ${url.pathname}`];
    let arg: string | undefined;
    if (!h && parts.length >= 3) {
      try {
        arg = decodeURIComponent(parts[parts.length - 1]);
      } catch {
        return send(400, { error: 'bad path' });
      }
      h = routes[`${req.method} /${parts.slice(0, -1).join('/')}`];
    }
    if (!h) return send(404, { error: 'not found' });
    send(200, await h(req, req.method === 'POST' ? await readBody(req) : {}, arg));
  } catch (e) {
    if (e instanceof HttpError) return send(e.code, { error: e.message });
    console.error((e as Error).message);
    send(500, { error: 'internal error' });
  }
});
server.listen(PORT, '127.0.0.1', () => console.log(`kaspaveil-relay on 127.0.0.1:${PORT}`));
