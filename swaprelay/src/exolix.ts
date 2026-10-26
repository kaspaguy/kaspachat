import type { Coin, Fetch, Provider, Status } from './types.ts';

const BASE = 'https://exolix.com/api/v2';
const STATUS: Record<string, Status> = { wait: 'waiting', confirmation: 'confirming', confirmed: 'exchanging', exchanging: 'exchanging', sending: 'sending', success: 'finished', overdue: 'expired', refunded: 'refunded' };
const PAGE = 100;

/**
 * Exolix API v2. Currencies and rates need no key (checked live 2026-10-11: 504 coins); swaps created with
 * the partner key earn the affiliate share.
 */
export function exolix(apiKey: string | undefined, f: Fetch = fetch): Provider {
  const call = async <T>(path: string, init?: RequestInit): Promise<T> => {
    const r = await f(BASE + path, { ...init, headers: { 'Content-Type': 'application/json', ...(apiKey ? { Authorization: apiKey } : {}) }, signal: AbortSignal.timeout(10_000) });
    const j = (await r.json()) as T & { message?: string | null; error?: string };
    if (!r.ok) throw new Error(`exolix ${path.split('?')[0]}: ${r.status} ${j.message ?? j.error ?? ''}`.trim());
    return j;
  };
  const up = (c: Coin) => ({ coin: c.ticker.toUpperCase(), net: c.network.toUpperCase() });
  const pair = (from: Coin) => `coinFrom=${up(from).coin}&networkFrom=${up(from).net}&coinTo=KAS&networkTo=KAS`;
  return {
    name: 'Exolix',
    ready: () => Boolean(apiKey),
    async currencies() {
      type Page = { data: { code: string; name: string; networks: { network: string }[] }[]; count: number };
      const out: (Coin & { name: string })[] = [];
      for (let page = 1, seen = 0; ; page++) {
        const p = await call<Page>(`/currencies?withNetworks=true&page=${page}&size=${PAGE}`);
        for (const c of p.data) if (c.code !== 'KAS') for (const n of c.networks) out.push({ ticker: c.code.toLowerCase(), network: n.network.toLowerCase(), name: c.name });
        seen += p.data.length;
        if (seen >= p.count || p.data.length === 0) return out;
      }
    },
    async quote(from, amount) {
      const r = await call<{ toAmount: number; minAmount: number; maxAmount: number; message: string | null }>(`/rate?${pair(from)}&amount=${amount}&rateType=float`);
      if (r.message) throw new Error(`exolix: ${r.message}`);
      return { provider: 'Exolix', from, fromAmount: amount, toAmount: r.toAmount, min: r.minAmount, max: r.maxAmount, kyc: 'No account; may ask for ID if a payment is flagged' };
    },
    async create(from, amount, payout, refund) {
      const r = await call<{ id: string; depositAddress: string; depositExtraId: string | null; amountTo: number }>('/transactions', {
        method: 'POST',
        body: JSON.stringify({ coinFrom: up(from).coin, networkFrom: up(from).net, coinTo: 'KAS', networkTo: 'KAS', amount, withdrawalAddress: payout, rateType: 'float', ...(refund ? { refundAddress: refund } : {}) }),
      });
      return { provider: 'Exolix', id: r.id, from, fromAmount: amount, depositAddress: r.depositAddress, depositExtraId: r.depositExtraId || null, expectedKas: r.amountTo, payout };
    },
    async status(id) {
      const r = await call<{ status: string; amountTo: number; hashIn?: { hash: string | null }; hashOut?: { hash: string | null } }>(`/transactions/${encodeURIComponent(id)}`);
      return { status: STATUS[r.status] ?? 'exchanging', payinTx: r.hashIn?.hash ?? null, payoutTx: r.hashOut?.hash ?? null, kas: r.status === 'success' ? r.amountTo : null };
    },
  };
}
