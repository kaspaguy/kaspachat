// Several indexers (PROTOCOL_SPEC §6.2): the default first, then any the user added. A request moves to the next one when
// an indexer is unreachable or answers with a server error; a definite answer (including "not found") is final.
export class Unreachable extends Error {}

export async function firstAnswer<T>(bases: string[], ask: (base: string) => Promise<T>, unreachable: (e: unknown) => boolean): Promise<T> {
  let last: unknown = new Unreachable('no indexer');
  for (const b of bases) {
    try {
      return await ask(b);
    } catch (e) {
      if (!unreachable(e)) throw e;
      last = e;
    }
  }
  throw last;
}

// https only, or a plain-http .onion address (Tor already encrypts it). No credentials, query or fragment.
export function cleanIndexerUrl(s: string): string | null {
  let u: URL;
  try { u = new URL(s.trim()); } catch { return null; }
  const onion = u.hostname.endsWith('.onion');
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && onion))) return null;
  if (u.username || u.password || u.search || u.hash) return null;
  return u.origin + u.pathname.replace(/\/+$/, '');
}
