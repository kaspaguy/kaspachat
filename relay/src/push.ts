// KaspaChat push service for iPhones (opt-in, off by default; PROTOCOL_SPEC §7). iOS pauses apps soon after they're
// left, so a phone that opted in asks this service to wake it through Apple when a message lands in a bucket it
// watches. It knows device tokens and bucket numbers, never names, keys or tags. The buckets come from the phone's
// upcoming message tags only (not its fixed first-contact inbox), so they change as conversations move on. The phone
// decides by itself whether a message is for it (mobile/ios/NotificationService) and shows nothing when it isn't.
// Cover traffic lands in buckets too, so some wake-ups are for nothing; that's intended. No IP logs.
import http from 'node:http';
import http2 from 'node:http2';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { MongoClient, type Collection } from 'mongodb';

const PORT = Number(process.env.PORT ?? 5514);
const TOPIC = process.env.APNS_TOPIC ?? 'com.kaspaguy.kaspachat';
const KEY_FILE = process.env.APNS_KEY_FILE; // the .p8 auth key from the Apple account, outside the repo
const KEY_ID = process.env.APNS_KEY_ID ?? '';
const TEAM_ID = process.env.APNS_TEAM_ID ?? '';
const SUB_TTL_S = 3 * 86_400; // the app re-registers at least every 12 hours while it runs
const COALESCE_MS = 5_000;

type Sub = { _id: string; env: 'sandbox' | 'production'; b: number[]; at: Date };
const mongo = new MongoClient(process.env.MONGO_URL ?? 'mongodb://127.0.0.1:27017');
await mongo.connect();
const db = mongo.db(process.env.MONGO_DB ?? 'kaspaveil_tn10');
const subs: Collection<Sub> = db.collection('push_subs');
const msgs = db.collection<{ b: number; t: Date }>('messages');
await subs.createIndex({ b: 1 });
await subs.createIndex({ at: 1 }, { expireAfterSeconds: SUB_TTL_S });

// ---------- Apple (token-based auth, HTTP/2) ----------
const key = KEY_FILE ? createPrivateKey(readFileSync(KEY_FILE)) : null;
let jwt = { token: '', at: 0 };
function bearer() {
  if (Date.now() - jwt.at < 45 * 60_000) return jwt.token;
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const body = `${b64({ alg: 'ES256', kid: KEY_ID })}.${b64({ iss: TEAM_ID, iat: Math.floor(Date.now() / 1000) })}`;
  const sig = createSign('SHA256').update(body).sign({ key: key!, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  jwt = { token: `${body}.${sig}`, at: Date.now() };
  return jwt.token;
}
const sessions = new Map<string, http2.ClientHttp2Session>();
function apple(env: Sub['env']) {
  let s = sessions.get(env);
  if (!s || s.closed || s.destroyed) {
    s = http2.connect(env === 'production' ? 'https://api.push.apple.com' : 'https://api.sandbox.push.apple.com');
    s.on('error', () => sessions.delete(env));
    s.on('close', () => sessions.delete(env));
    sessions.set(env, s);
  }
  return s;
}
let dryRun = 0;
function push(sub: Sub, buckets: number[]) {
  if (!key) return void dryRun++;
  const body = JSON.stringify({ aps: { alert: { title: 'KaspaChat', body: 'New message' }, sound: 'default', 'mutable-content': 1 }, kc: { b: buckets } });
  const req = apple(sub.env).request({
    ':method': 'POST', ':path': `/3/device/${sub._id}`, authorization: `bearer ${bearer()}`, 'apns-topic': TOPIC,
    'apns-push-type': 'alert', 'apns-priority': '10', 'apns-expiration': String(Math.floor(Date.now() / 1000) + 86_400),
  });
  req.on('response', (h) => {
    const code = Number(h[':status']);
    if (code === 410 || code === 400) {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => { if (code === 410 || /BadDeviceToken|DeviceTokenNotForTopic/.test(raw)) void subs.deleteOne({ _id: sub._id }); });
    }
  });
  req.on('error', () => {});
  req.end(body);
}

// ---------- watching the indexer's message store ----------
let last = new Date();
const lastPush = new Map<string, number>();
const pending = new Map<string, { sub: Sub; b: Set<number> }>();
let polling = false;
setInterval(async () => {
  if (polling) return; // a slow round must not overlap the next and push twice
  polling = true;
  try {
    const rows = await msgs.find({ t: { $gt: last } }, { projection: { b: 1, t: 1 } }).sort({ t: 1 }).limit(5000).toArray();
    if (rows.length) last = rows[rows.length - 1].t;
    const hit = [...new Set(rows.map((r) => r.b))];
    if (hit.length) for (const s of await subs.find({ b: { $in: hit } }).toArray()) {
      const p = pending.get(s._id) ?? { sub: s, b: new Set<number>() };
      for (const b of s.b) if (hit.includes(b)) p.b.add(b);
      pending.set(s._id, p);
    }
    for (const [t, p] of pending) {
      if (Date.now() - (lastPush.get(t) ?? 0) < COALESCE_MS) continue;
      push(p.sub, [...p.b]);
      lastPush.set(t, Date.now());
      pending.delete(t);
    }
    for (const [t, at] of lastPush) if (Date.now() - at > 60_000) lastPush.delete(t);
  } catch {} finally {
    polling = false;
  }
}, 2_000);

// ---------- API (behind nginx at /api/push/) ----------
const hits = new Map<string, { n: number; reset: number }>();
const over = (ip: string, limit: number) => {
  const h = hits.get(ip);
  if (!h || h.reset < Date.now()) return hits.set(ip, { n: 1, reset: Date.now() + 600_000 }), false;
  return ++h.n > limit;
};
setInterval(() => { for (const [k, v] of hits) if (v.reset < Date.now()) hits.delete(k); }, 60_000);

http.createServer(async (req, res) => {
  const send = (code: number, body: object) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (req.method === 'GET' && req.url === '/v1/status') return send(200, { apple: !!key, subs: await subs.estimatedDocumentCount(), dryRun });
  if (req.method !== 'POST' || (req.url !== '/v1/register' && req.url !== '/v1/unregister')) return send(404, { error: 'not found' });
  if (over(String(req.headers['cf-connecting-ip'] ?? ''), 60)) return send(429, { error: 'too many requests' });
  let raw = '';
  for await (const c of req) if ((raw += c).length > 4096) return send(413, { error: 'too large' });
  let b: any;
  try { b = JSON.parse(raw); } catch { return send(400, { error: 'json' }); }
  if (typeof b.token !== 'string' || !/^[0-9a-f]{64,200}$/.test(b.token)) return send(400, { error: 'token' });
  if (req.url === '/v1/unregister') {
    await subs.deleteOne({ _id: b.token });
    return send(200, { ok: true });
  }
  const buckets = Array.isArray(b.buckets) ? [...new Set<number>(b.buckets)] : [];
  if (!buckets.length || buckets.length > 64 || !buckets.every((x) => Number.isInteger(x) && x >= 0 && x <= 4095)) return send(400, { error: 'buckets' });
  if (b.env !== 'sandbox' && b.env !== 'production') return send(400, { error: 'env' });
  await subs.updateOne({ _id: b.token }, { $set: { env: b.env, b: buckets, at: new Date() } }, { upsert: true });
  send(200, { ok: true });
}).listen(PORT, '127.0.0.1');
