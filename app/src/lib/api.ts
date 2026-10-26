// The two public services: Kaspaguy's relay/doorman and an indexer (Kaspaguy's by default; any indexer works).
import { apiBase, httpFetch } from './platform';
import { cleanIndexerUrl, firstAnswer } from './failover';

const RELAY = apiBase('/api/relay');
const INDEX = apiBase('/api/index');

export class ApiError extends Error {
  status: number;
  constructor(status: number, msg: string) {
    super(msg);
    this.status = status;
  }
}

async function call(base: string, path: string, body?: unknown): Promise<any> {
  const r = await httpFetch(base + path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j: any = null;
  try {
    j = await r.json();
  } catch {
    throw new ApiError(r.status, `service unavailable (${r.status})`);
  }
  if (!r.ok) throw new ApiError(r.status, j?.error ?? `error ${r.status}`);
  return j;
}

export const relay = (path: string, body?: unknown) => call(RELAY, path, body);
// Extra indexers the user added (Account → Indexers), tried after the default one.
export function extraIndexers(): string[] {
  try {
    const l = JSON.parse(localStorage.getItem('kc.indexers') ?? '[]');
    return Array.isArray(l) ? l.filter((x) => typeof x === 'string' && cleanIndexerUrl(x) === x) : [];
  } catch { return []; }
}
export function setExtraIndexers(list: string[]) {
  try { localStorage.setItem('kc.indexers', JSON.stringify([...new Set(list.map((x) => cleanIndexerUrl(x)).filter((x): x is string => !!x))])); } catch {}
}
const unreachable = (e: unknown) => !(e instanceof ApiError) || e.status >= 500;
export const indexer = (path: string) => firstAnswer([INDEX, ...extraIndexers()], (b) => call(b, path), unreachable);

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
