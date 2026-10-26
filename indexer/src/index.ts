// Kaspaveil reference indexer (PROTOCOL_SPEC §6.2). Follows the Kaspaveil lane on its own Kaspa node, keeps message
// ciphertext for the 7-day delivery window and bundles for good, and serves both by bucket. Holds only public data.
// No IP logs: no access log, nothing per address in memory beyond short-lived rate-limit counters.
import http from 'node:http';
import { MongoClient, type Collection } from 'mongodb';
import { fileBlocks, type BundleDoc, type Msg } from './lane.ts';

const RPC = process.env.KASPAVEIL_JSON_RPC ?? 'ws://127.0.0.1:18210';
const PORT = Number(process.env.PORT ?? 5510);
const CHAIND = process.env.KASPAVEIL_CHAIND ?? 'http://127.0.0.1:5512';
const DELIVERY_WINDOW_S = 7 * 24 * 3600;
const NETWORK = process.env.KASPAVEIL_NETWORK ?? 'testnet-10';
const RPC_TIMEOUT_MS = 30_000;


const mongo = new MongoClient(process.env.MONGO_URL ?? 'mongodb://127.0.0.1:27017');
await mongo.connect();
const db = mongo.db(process.env.MONGO_DB ?? 'kaspaveil_tn10');
const msgs: Collection<Msg> = db.collection('messages');
const bundles: Collection<BundleDoc> = db.collection('bundles');
const meta = db.collection<{ _id: string; v: string }>('meta');
// Directory holds set after a reviewed report (relay/scripts/reports.ts): this operator's indexer doesn't serve the
// held owner's bundles until `until`. Keyed by bundle tag; Mongo drops each one when it ends.
const holds = db.collection<{ _id: string; until: Date }>('holds');
await msgs.createIndex({ b: 1, t: 1 });
await msgs.createIndex({ t: 1 }, { expireAfterSeconds: DELIVERY_WINDOW_S });
await bundles.createIndex({ b: 1 });
await holds.createIndex({ until: 1 }, { expireAfterSeconds: 0 });

// ---------- node connection (JSON wRPC) ----------
let ws: WebSocket | null = null;
let seq = 0;
const waiting = new Map<number, (v: any) => void>();
function connect(): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = new WebSocket(RPC);
    s.onopen = () => { ws = s; resolve(); };
    s.onerror = () => reject(new Error('node connection failed'));
    s.onclose = () => { ws = null; for (const r of waiting.values()) r({ error: 'closed' }); waiting.clear(); };
    s.onmessage = (e) => {
      const m = JSON.parse(String(e.data));
      const r = waiting.get(m.id);
      if (r) { waiting.delete(m.id); r(m); }
    };
  });
}
// A node that stops answering would otherwise stall the follower for good: drop the connection and reconnect.
async function call(method: string, params: object = {}): Promise<any> {
  if (!ws) await connect();
  const id = ++seq;
  const m: any = await new Promise((r) => {
    const timer = setTimeout(() => { waiting.delete(id); ws?.close(); r({ error: 'timeout' }); }, RPC_TIMEOUT_MS);
    waiting.set(id, (v) => { clearTimeout(timer); r(v); });
    ws!.send(JSON.stringify({ id, method, params }));
  });
  if (m.error) throw new Error(`${method}: ${JSON.stringify(m.error)}`);
  return m.params;
}

let tipDaa = 0;
let lastSync = 0;
let laneSeen = 0;

// getBlocks(lowHash = the previous sink) returns every block in past(new sink) \ past(old sink): nothing is skipped,
// and blocks not yet merged arrive in a later round. Lane transactions are upserted by txid.
async function follow() {
  let cursor = (await meta.findOne({ _id: 'cursor' }))?.v;
  for (;;) {
    try {
      const info = await call('getBlockDagInfo');
      tipDaa = Number(info.virtualDaaScore);
      if (!cursor) cursor = info.sink as string;
      const r = await call('getBlocks', { lowHash: cursor, includeBlocks: true, includeTransactions: true });
      const blocks: any[] = r.blocks ?? [];
      const filed = await fileBlocks(blocks, msgs, bundles);
      const lastChain = filed.lastChain ?? cursor;
      laneSeen += filed.seen;
      cursor = blocks.length >= 200 ? lastChain : (info.sink as string);
      await meta.updateOne({ _id: 'cursor' }, { $set: { v: cursor } }, { upsert: true });
      lastSync = Date.now();
      if (blocks.length < 200) await new Promise((r) => setTimeout(r, 500));
    } catch (e) {
      console.error('follow:', (e as Error).message);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}

// ---------- HTTP ----------
const limits = new Map<string, number>();
setInterval(() => limits.clear(), 60_000);
function limited(req: http.IncomingMessage, max: number) {
  const k = (req.headers['cf-connecting-ip'] as string) ?? req.socket.remoteAddress ?? '';
  const n = (limits.get(k) ?? 0) + 1;
  limits.set(k, n);
  return n > max;
}
function send(res: http.ServerResponse, code: number, body: unknown) {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

const sinceOf = (url: URL) => {
  const n = Number(url.searchParams.get('since') ?? 0);
  return Number.isFinite(n) ? new Date(Math.max(0, n)) : null;
};

async function chaind(path: string) {
  const r = await fetch(CHAIND + path);
  return { code: r.status, body: r.status === 200 ? await r.json() : { error: await r.text() } };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://x');
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts[0] !== 'v1') return send(res, 404, { error: 'not found' });
    if (limited(req, 600)) return send(res, 429, { error: 'slow down' });
    // GET /v1/bucket/:b?since=<ms>  messages in one tag bucket (0..4095) seen after `since`
    if (parts[1] === 'bucket' && parts.length === 3) {
      const b = Number(parts[2]);
      if (!Number.isInteger(b) || b < 0 || b > 4095) return send(res, 400, { error: 'bucket' });
      const since = sinceOf(url);
      if (!since) return send(res, 400, { error: 'since' });
      const rows = await msgs.find({ b, t: { $gt: since } }).sort({ t: 1 }).limit(1000).toArray();
      return send(res, 200, { bucket: b, now: Date.now(), messages: rows.map((m) => ({ id: m._id, p: m.p.toString('hex'), t: m.t.getTime() })) });
    }
    // GET /v1/buckets?b=1,2,3&since=<ms>  several tag buckets in one request (at most 64); same privacy as one request each
    if (parts[1] === 'buckets' && parts.length === 2) {
      const list = [...new Set((url.searchParams.get('b') ?? '').split(',').filter(Boolean).map(Number))];
      if (!list.length || list.length > 64 || list.some((b) => !Number.isInteger(b) || b < 0 || b > 4095)) return send(res, 400, { error: 'buckets' });
      const since = sinceOf(url);
      if (!since) return send(res, 400, { error: 'since' });
      const rows = await msgs.find({ b: { $in: list }, t: { $gt: since } }).sort({ t: 1 }).limit(2000).toArray();
      return send(res, 200, { now: Date.now(), messages: rows.map((m) => ({ id: m._id, b: m.b, p: m.p.toString('hex'), t: m.t.getTime() })) });
    }
    // GET /v1/bundles/:b  the newest bundle for every bundle tag in bucket b
    if (parts[1] === 'bundles' && parts.length === 3) {
      const b = Number(parts[2]);
      if (!Number.isInteger(b) || b < 0 || b > 4095) return send(res, 400, { error: 'bucket' });
      const rows = await bundles.find({ b }).toArray();
      const held = new Set((await holds.find({ _id: { $in: rows.map((x) => x._id) }, until: { $gt: new Date() } }).toArray()).map((h) => h._id));
      return send(res, 200, { bucket: b, bundles: rows.filter((x) => !held.has(x._id)).map((x) => ({ tag: x._id, p: x.p.toString('hex'), t: x.t.getTime() })) });
    }
    // GET /v1/registry/bucket/:b, /v1/registry/meta  (Phase 2: served from the doorman's registry copy; see Project_Progress)
    if (parts[1] === 'registry' && parts[2] === 'bucket' && parts.length === 4) {
      const b = Number(parts[3]);
      if (!Number.isInteger(b) || b < 0 || b > 255) return send(res, 400, { error: 'bucket' });
      const r = await chaind(`/registry/bucket/${b}`);
      return send(res, r.code, r.body);
    }
    // GET /v1/registry/owner/:owner  names held by one owner key (used when restoring from a recovery phrase)
    if (parts[1] === 'registry' && parts[2] === 'owner' && parts.length === 4) {
      if (!/^[0-9a-f]{64}$/.test(parts[3])) return send(res, 400, { error: 'owner' });
      const r = await chaind(`/registry/owner/${parts[3]}`);
      return send(res, r.code, r.body);
    }
    if (parts[1] === 'registry' && parts[2] === 'meta') {
      const r = await chaind('/registry/meta');
      return send(res, r.code, r.body);
    }
    if (parts[1] === 'tip') return send(res, 200, { daa: tipDaa, synced: Date.now() - lastSync < 10_000, now: Date.now() });
    // GET /v1/audit  the public, chain-derived views (spec §8.5a): treasury lanes and throttle, reservoirs, registry counters.
    if (parts[1] === 'audit') {
      const [st, meta] = await Promise.all([chaind('/status'), chaind('/registry/meta')]);
      if (st.code !== 200 || meta.code !== 200) return send(res, 503, { error: 'unavailable' });
      const p = (st.body as any).pot ?? {};
      const m = meta.body as any;
      const sum = (k: string) => m.shards.reduce((a: number, s: any) => a + (s.state[k] ?? 0), 0);
      return send(res, 200, {
        network: NETWORK, at: Date.now(), daa: (st.body as any).daa,
        treasury: { covenantId: p.cov, lanes: p.lanes, valueSompi: p.value, hourlyAllowanceSompi: p.allowance, reservoirs: (st.body as any).reservoirs },
        registry: { registryId: m.registryId, shards: m.shards.map((s: any) => ({ id: s.id, covenantId: s.cov, names: s.state.size - 1 })), names: sum('size') - m.shards.length,
          prepaidRegistrations: sum('prepaid_regs'), prepaidMonths: sum('prepaid_months'), monthlyPriceSompi: m.shards[0].state.price, transfersOpen: m.shards[0].state.transfers_open === 1 },
      });
    }
    if (parts[1] === 'health') {
      return send(res, 200, { synced: Date.now() - lastSync < 10_000, tipDaa, laneSeen, messages: await msgs.estimatedDocumentCount(), bundles: await bundles.estimatedDocumentCount() });
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error((e as Error).message);
    send(res, 500, { error: 'internal error' });
  }
});
server.listen(PORT, '127.0.0.1', () => console.log(`kaspaveil-indexer on 127.0.0.1:${PORT}, node ${RPC}`));
follow();
