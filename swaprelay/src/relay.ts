import { coinKey, type Coin, type Currency, type Offer, type Provider, type Swap } from './types.ts';

/** Kaspa mainnet address (bech32 charset, P2PK or P2SH). */
const KAS_ADDRESS = /^kaspa:[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{60,62}$/;

export type Offers = { offers: Offer[]; unavailable: { provider: string; reason: string }[] };

/**
 * The thin server-side relay of §4a: it holds the partner keys, lists every coin any provider swaps into KAS,
 * merges every provider's offer best first, and opens the swap the user picked. Non-custodial by construction:
 * the payout is always the address the user's own wallet sent, and it must be a Kaspa address. Nothing is
 * logged — callers must not log payout or refund addresses either (privacy policy: seen in transit only).
 */
export class SwapRelay {
  private cache = new Map<string, { at: number; value: Offers }>();
  private list: { at: number; value: Currency[] } | null = null;

  private readonly providers: Provider[];
  /** Quotes are cached per coin and amount; CypherGoat's default limit is 30 requests/min. */
  private readonly cacheMs: number;
  /** At most this many cached quotes: callers choose the amount, so the cache must not grow without bound. */
  private readonly cacheMax: number;
  private readonly now: () => number;
  /** The merged currency list changes rarely; refreshed hourly. */
  private readonly listMs: number;

  constructor(providers: Provider[], cacheMs = 20_000, now: () => number = Date.now, cacheMax = 1_000, listMs = 3_600_000) {
    this.providers = providers;
    this.cacheMs = cacheMs;
    this.now = now;
    this.cacheMax = cacheMax;
    this.listMs = listMs;
  }

  /** Every coin at least one ready provider swaps into KAS, with the providers that do, by name. */
  async currencies(): Promise<Currency[]> {
    if (this.list && this.now() - this.list.at < this.listMs) return this.list.value;
    const live = this.providers.filter((p) => p.ready());
    const res = await Promise.allSettled(live.map((p) => p.currencies()));
    const merged = new Map<string, Currency>();
    res.forEach((r, i) => {
      if (r.status === 'rejected') return;
      for (const c of r.value) {
        const k = coinKey(c);
        const m = merged.get(k);
        if (m) { if (!m.providers.includes(live[i].name)) m.providers.push(live[i].name); }
        else merged.set(k, { ticker: c.ticker, network: c.network, name: c.name, providers: [live[i].name] });
      }
    });
    const value = [...merged.values()].sort((a, b) => a.name.localeCompare(b.name) || a.network.localeCompare(b.network));
    if (value.length) this.list = { at: this.now(), value };
    return value;
  }

  async offers(from: Coin, amount: number): Promise<Offers> {
    if (!(amount > 0) || !Number.isFinite(amount)) throw new Error('amount must be positive');
    const cur = (await this.currencies()).find((c) => coinKey(c) === coinKey(from));
    if (!cur) throw new Error(`unsupported coin ${from.ticker} on ${from.network}`);
    const key = `${coinKey(from)}:${amount}`;
    const hit = this.cache.get(key);
    if (hit && this.now() - hit.at < this.cacheMs) return hit.value;
    const live = this.providers.filter((p) => p.ready() && cur.providers.includes(p.name));
    const res = await Promise.allSettled(live.map((p) => p.quote(from, amount)));
    const value: Offers = { offers: [], unavailable: [] };
    const unit = from.ticker.toUpperCase();
    res.forEach((r, i) => {
      if (r.status === 'rejected') return value.unavailable.push({ provider: live[i].name, reason: String(r.reason instanceof Error ? r.reason.message : r.reason) });
      const o = r.value;
      if (amount < o.min) return value.unavailable.push({ provider: o.provider, reason: `minimum ${o.min} ${unit}` });
      if (o.max !== null && amount > o.max) return value.unavailable.push({ provider: o.provider, reason: `maximum ${o.max} ${unit}` });
      value.offers.push(o);
    });
    value.offers.sort((a, b) => b.toAmount - a.toAmount);
    if (this.cache.size >= this.cacheMax) {
      for (const [k, v] of this.cache) if (this.now() - v.at >= this.cacheMs) this.cache.delete(k);
      while (this.cache.size >= this.cacheMax) this.cache.delete(this.cache.keys().next().value!);
    }
    this.cache.set(key, { at: this.now(), value });
    return value;
  }

  async create(provider: string, from: Coin, amount: number, payout: string, refund: string | null = null): Promise<Swap> {
    if (!KAS_ADDRESS.test(payout)) throw new Error('payout must be a kaspa: address from the user’s own wallet');
    if (!(amount > 0) || !Number.isFinite(amount)) throw new Error('amount must be positive');
    const p = this.providers.find((x) => x.name === provider && x.ready());
    if (!p) throw new Error(`provider ${provider} is not available`);
    const cur = (await this.currencies()).find((c) => coinKey(c) === coinKey(from));
    if (!cur?.providers.includes(p.name)) throw new Error(`${provider} doesn't swap ${from.ticker} on ${from.network} into KAS`);
    const s = await p.create(from, amount, payout, refund);
    if (s.payout !== payout) throw new Error('provider changed the payout address');
    return s;
  }

  status(provider: string, id: string) {
    const p = this.providers.find((x) => x.name === provider);
    if (!p) throw new Error(`unknown provider ${provider}`);
    return p.status(id);
  }
}
