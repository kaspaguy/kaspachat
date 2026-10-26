/** Live offers for one coin, network and amount: `node scripts/offers.ts ltc ltc 1`. Keys come from the environment. */
import { SwapRelay } from '../src/relay.ts';
import { exolix } from '../src/exolix.ts';
import { changenow } from '../src/changenow.ts';

const [ticker = 'btc', network = ticker, amount = '0.01'] = process.argv.slice(2);
// Exolix currencies and quotes need no key; mark it ready for this read-only listing.
const ex = exolix(process.env.EXOLIX_API_KEY);
const relay = new SwapRelay([{ ...ex, ready: () => true }, changenow(process.env.CHANGENOW_API_KEY)]);
console.log(`${(await relay.currencies()).length} coins can be swapped into KAS`);
const r = await relay.offers({ ticker, network }, Number(amount));
for (const o of r.offers) console.log(`${o.provider.padEnd(10)} ${o.toAmount.toFixed(2).padStart(12)} KAS  (min ${o.min}, max ${o.max ?? '—'} ${ticker.toUpperCase()})  ${o.kyc}`);
for (const u of r.unavailable) console.log(`${u.provider.padEnd(10)} unavailable: ${u.reason}`);
