/**
 * A coin on one network, lower case ("usdt" on "trx"). Any coin a provider swaps into KAS can be offered (§4a,
 * Kaspaguy 2026-10-11); Kaspaveil itself only ever receives KAS, in the user's own wallet.
 */
export type Coin = { ticker: string; network: string };
export type Currency = Coin & { name: string; providers: string[] };

export type Offer = {
  provider: string;
  from: Coin;
  fromAmount: number;
  /** KAS the user receives, after the provider's fees and our commission. */
  toAmount: number;
  min: number;
  max: number | null;
  /** Shown next to the offer (Kaspaguy: honest labels). */
  kyc: string;
};

export type Status = 'waiting' | 'confirming' | 'exchanging' | 'sending' | 'finished' | 'failed' | 'refunded' | 'expired';

export type Swap = {
  provider: string;
  id: string;
  from: Coin;
  fromAmount: number;
  depositAddress: string;
  /** Memo/tag some coins need alongside the address (XRP, XLM, some exchange deposits). */
  depositExtraId: string | null;
  expectedKas: number;
  payout: string;
};

export type SwapState = { status: Status; payinTx: string | null; payoutTx: string | null; kas: number | null };

export interface Provider {
  name: string;
  /** False while its partner key is missing: it is left out of the currencies and the offers. */
  ready(): boolean;
  /** Every coin it can swap into KAS, KAS itself excluded. */
  currencies(): Promise<(Coin & { name: string })[]>;
  quote(from: Coin, amount: number): Promise<Offer>;
  create(from: Coin, amount: number, payout: string, refund: string | null): Promise<Swap>;
  status(id: string): Promise<SwapState>;
}

export type Fetch = typeof fetch;

export const coinKey = (c: Coin) => `${c.ticker}:${c.network}`;
