import type { Coin, Fetch, Provider, Status } from './types.ts';

const BASE = 'https://api.changenow.io/v2';
const STATUS: Record<string, Status> = { new: 'waiting', waiting: 'waiting', confirming: 'confirming', exchanging: 'exchanging', sending: 'sending', finished: 'finished', failed: 'failed', refunded: 'refunded', verifying: 'exchanging' };

/** ChangeNOW API v2. The currency list is public; every other call, quotes included, needs the partner key. */
export function changenow(apiKey: string | undefined, f: Fetch = fetch): Provider {
  const call = async <T>(path: string, init?: RequestInit, keyed = true): Promise<T> => {
    if (keyed && !apiKey) throw new Error('changenow: no partner key');
    const r = await f(BASE + path, { ...init, headers: { 'Content-Type': 'application/json', ...(apiKey ? { 'x-changenow-api-key': apiKey } : {}) }, signal: AbortSignal.timeout(10_000) });
    const j = (await r.json()) as T & { message?: string; error?: string };
    if (!r.ok) throw new Error(`changenow ${path.split('?')[0]}: ${r.status} ${j.message ?? j.error ?? ''}`.trim());
    return j;
  };
  const pair = (from: Coin) => `fromCurrency=${from.ticker}&fromNetwork=${from.network}&toCurrency=kas&toNetwork=kas&flow=standard`;
  return {
    name: 'ChangeNOW',
    ready: () => Boolean(apiKey),
    async currencies() {
      const list = await call<{ ticker: string; network: string; name: string; sell: boolean; isFiat: boolean }[]>('/exchange/currencies?active=true&flow=standard', undefined, false);
      return list.filter((c) => c.sell && !c.isFiat && c.ticker !== 'kas').map((c) => ({ ticker: c.ticker.toLowerCase(), network: c.network.toLowerCase(), name: c.name }));
    },
    async quote(from, amount) {
      const [est, range] = await Promise.all([
        call<{ toAmount: number }>(`/exchange/estimated-amount?${pair(from)}&fromAmount=${amount}&type=direct`),
        call<{ minAmount: number; maxAmount: number | null }>(`/exchange/range?${pair(from)}`),
      ]);
      return { provider: 'ChangeNOW', from, fromAmount: amount, toAmount: est.toAmount, min: range.minAmount, max: range.maxAmount, kyc: 'No account; may ask for ID if a payment is flagged' };
    },
    async create(from, amount, payout, refund) {
      const r = await call<{ id: string; payinAddress: string; payinExtraId?: string | null; toAmount: number }>('/exchange', {
        method: 'POST',
        body: JSON.stringify({ fromCurrency: from.ticker, fromNetwork: from.network, toCurrency: 'kas', toNetwork: 'kas', fromAmount: String(amount), address: payout, flow: 'standard', type: 'direct', ...(refund ? { refundAddress: refund } : {}) }),
      });
      return { provider: 'ChangeNOW', id: r.id, from, fromAmount: amount, depositAddress: r.payinAddress, depositExtraId: r.payinExtraId || null, expectedKas: r.toAmount, payout };
    },
    async status(id) {
      const r = await call<{ status: string; payinHash: string | null; payoutHash: string | null; amountTo: number | null }>(`/exchange/by-id?id=${encodeURIComponent(id)}`);
      return { status: STATUS[r.status] ?? 'exchanging', payinTx: r.payinHash, payoutTx: r.payoutHash, kas: r.status === 'finished' ? r.amountTo : null };
    },
  };
}
