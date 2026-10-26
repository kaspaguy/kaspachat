// A stand-in for kaspad + chaind, for running the real relay, indexer and app engine on one machine with no network.
// HTTP side: the chaind endpoints the relay and indexer call. WebSocket side: the two JSON wRPC calls the indexer makes
// (getBlockDagInfo, getBlocks). Every relayed payload becomes a one-transaction chain block on the Kaspaveil lane.
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { registryBucket } from '../../protocol/src/index.ts';

const LANE = '4b564c0100000000000000000000000000000000';
export const PRICE = 100 * 1e8;

type Entry = { name: string; owner: string; expiry: number };
type Block = { verboseData: { hash: string; isChainBlock: boolean }; transactions: unknown[] };

export async function startFakeChain() {
  const names = new Map<string, Entry>();
  const deposits = new Map<string, { address: string; min: number; coins: { id: string; sompi: number }[] }>();
  const blocks: Block[] = [{ verboseData: { hash: randomBytes(32).toString('hex'), isChainBlock: true }, transactions: [] }];
  const relayed: string[] = []; // every payload that reached the chain, in order
  let daa = 1_000_000;

  const mine = (payload: string) => {
    const txid = randomBytes(32).toString('hex');
    blocks.push({ verboseData: { hash: randomBytes(32).toString('hex'), isChainBlock: true }, transactions: [{ subnetworkId: LANE, payload, verboseData: { transactionId: txid, blockTime: Date.now() } }] });
    relayed.push(payload);
    daa += 10;
    return txid;
  };
  const pay = (address: string, sompi: number) => {
    for (const d of deposits.values()) if (d.address === address) d.coins.push({ id: `${randomBytes(32).toString('hex')}:0`, sompi });
  };
  const register = (name: string, owner: string, expiry: number) => {
    if (names.has(name) && names.get(name)!.owner !== '00'.repeat(32)) throw new Error('name taken');
    names.set(name, { name, owner, expiry });
    return { txid: randomBytes(32).toString('hex') };
  };

  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    const b = raw ? JSON.parse(raw) : {};
    const url = req.url!;
    const ok = (o: unknown) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    const no = (code: number, msg: string) => { res.writeHead(code); res.end(msg); };
    try {
      if (url === '/status') return ok({ daa, pot: { cov: 'fake', lanes: 32, value: 1e12, allowance: 2e10 }, reservoirs: [] });
      if (url === '/registry/meta') return ok({ registryId: 'fake', shards: [{ id: 0, cov: 'fake', state: { price: PRICE, size: names.size + 1, prepaid_regs: 0, prepaid_months: 0, transfers_open: 0 } }] });
      if (url.startsWith('/registry/name/')) {
        const e = names.get(decodeURIComponent(url.slice(15)));
        return ok(e ? { taken: true, entry: e } : { taken: false });
      }
      if (url.startsWith('/registry/bucket/')) {
        const bucket = Number(url.slice(17));
        return ok({ entries: [...names.values()].filter((e) => registryBucket(e.name) === bucket) });
      }
      if (url.startsWith('/registry/owner/')) return ok({ entries: [...names.values()].filter((e) => e.owner === url.slice(16)) });
      if (url === '/registry/default') return ok(register(b.name, b.owner, 0));
      if (url === '/registry/prepaid' || url === '/registry/claim') {
        const r = register(b.name, b.owner, daa + b.months * 2_592_000);
        return ok(url === '/registry/claim' ? { txids: [r.txid] } : r);
      }
      if (url === '/registry/renew') {
        const e = names.get(b.name)!;
        e.expiry += b.months * 2_592_000;
        return ok({ txid: randomBytes(32).toString('hex') });
      }
      if (url === '/deposit') {
        const id = randomBytes(8).toString('hex');
        const address = `kaspatest:q${createHash('sha256').update(id).digest('hex').slice(0, 60)}`;
        deposits.set(id, { address, min: b.min, coins: [] });
        return ok({ id, address });
      }
      const dep = /^\/deposit\/([0-9a-f]+)(\/forward)?$/.exec(url);
      if (dep) {
        const d = deposits.get(dep[1]);
        const sum = (d?.coins ?? []).reduce((n, c) => n + c.sompi, 0);
        if (dep[2]) {
          if (d && sum >= d.min) d.coins = []; // settle(); nothing here is ever old enough for settleLate
          return ok({ txid: randomBytes(32).toString('hex') });
        }
        return ok({ received: sum, coins: (d?.coins ?? []).map((c) => ({ ...c, late: false })) });
      }
      if (url === '/faucet') {
        pay(b.address, b.sompi);
        return ok({ txid: randomBytes(32).toString('hex') });
      }
      if (url === '/relay') return ok({ txid: mine(b.payload), index: 0 });
      no(404, 'not found');
    } catch (e) {
      no(400, (e as Error).message);
    }
  });

  // Minimal WebSocket server: text frames only, which is all JSON wRPC uses.
  server.on('upgrade', (req, socket) => {
    const accept = createHash('sha1').update(`${req.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    let buf = Buffer.alloc(0);
    const send = (o: unknown) => {
      const data = Buffer.from(JSON.stringify(o));
      const head = data.length < 126 ? Buffer.from([0x81, data.length]) : data.length < 65536 ? Buffer.from([0x81, 126, data.length >> 8, data.length & 255]) : Buffer.concat([Buffer.from([0x81, 127]), (() => { const l = Buffer.alloc(8); l.writeBigUInt64BE(BigInt(data.length)); return l; })()]);
      socket.write(Buffer.concat([head, data]));
    };
    socket.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 2) return;
        const op = buf[0] & 15;
        let len = buf[1] & 127;
        let o = 2;
        if (len === 126) { len = buf.readUInt16BE(2); o = 4; } else if (len === 127) { len = Number(buf.readBigUInt64BE(2)); o = 10; }
        if (buf.length < o + 4 + len) return;
        const mask = buf.subarray(o, o + 4);
        const data = Buffer.from(buf.subarray(o + 4, o + 4 + len).map((x, i) => x ^ mask[i & 3]));
        buf = buf.subarray(o + 4 + len);
        if (op === 8) return socket.end();
        if (op !== 1) continue;
        const m = JSON.parse(data.toString());
        if (m.method === 'getBlockDagInfo') send({ id: m.id, params: { virtualDaaScore: String(daa), sink: blocks.at(-1)!.verboseData.hash } });
        else if (m.method === 'getBlocks') {
          const i = blocks.findIndex((x) => x.verboseData.hash === m.params.lowHash);
          send({ id: m.id, params: { blocks: blocks.slice(i + 1) } });
        } else send({ id: m.id, error: { message: 'unknown method' } });
      }
    });
    socket.on('error', () => {});
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}`, ws: `ws://127.0.0.1:${port}`, names, relayed, pay, close: () => server.close() };
}
