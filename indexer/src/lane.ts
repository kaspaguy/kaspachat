// Files the Kaspaveil lane transactions of a batch of blocks: messages by txid:index, bundles by tag.
import type { Collection } from 'mongodb';
import { BUNDLE_MARKER, PAYLOAD_LEN, parseBundlePayload } from '../../protocol/src/index.ts';

export const LANE = '4b564c0100000000000000000000000000000000';
const MARKER = Buffer.from(BUNDLE_MARKER);

export type Msg = { _id: string; tag: string; b: number; p: Buffer; t: Date; bt: number; blk: string };
export type BundleDoc = { _id: string; b: number; p: Buffer; t: Date; tx: string; c?: number; k?: number }; // c = created (s), k = spkId

// Returns the last chain block's hash (if any) and how many lane payloads were seen.
export async function fileBlocks(blocks: any[], msgs: Collection<Msg>, bundles: Collection<BundleDoc>, nowSec = Date.now() / 1000) {
  let lastChain: string | null = null;
  let seen = 0;
  const ops: any[] = [];
  const bops: any[] = [];
  for (const blk of blocks) {
    if (blk.verboseData?.isChainBlock) lastChain = blk.verboseData.hash;
    for (const tx of blk.transactions ?? []) {
      // SC-0020: a transaction carries 1 to 5 messages of 1,536 bytes; each is filed on its own (id = txid:index).
      if (tx.subnetworkId !== LANE || typeof tx.payload !== 'string' || !tx.payload.length || tx.payload.length % (PAYLOAD_LEN * 2) !== 0 || tx.payload.length > PAYLOAD_LEN * 10) continue;
      const all = Buffer.from(tx.payload, 'hex');
      const txid = tx.verboseData.transactionId as string;
      const bt = Number(tx.verboseData.blockTime);
      for (let i = 0; i * PAYLOAD_LEN < all.length; i++) {
        const p = all.subarray(i * PAYLOAD_LEN, (i + 1) * PAYLOAD_LEN);
        const tag = p.subarray(1, 17);
        const b = (tag[0] << 4) | (tag[1] >> 4);
        seen++;
        if (p.subarray(17, 49).equals(MARKER)) {
          // §3/§4.3: only a valid bundle under its owner's own tag, and only if newer than the one held
          // (highest created, then highest spkId), so nobody can file over someone else's keys or replay old ones.
          const bundle = parseBundlePayload(p, nowSec);
          if (!bundle) continue;
          const c = Number(bundle.created);
          const k = bundle.spkId;
          bops.push({ updateOne: {
            filter: { _id: tag.toString('hex'), $or: [{ c: { $exists: false } }, { c: { $lt: c } }, { c, k: { $lt: k } }] },
            update: { $set: { b, p, t: new Date(bt), tx: txid, c, k } }, upsert: true,
          } });
        } else {
          ops.push({ updateOne: { filter: { _id: `${txid}:${i}` }, update: { $setOnInsert: { tag: tag.toString('hex'), b, p, t: new Date(), bt, blk: blk.verboseData.hash } }, upsert: true } });
        }
      }
    }
  }
  if (ops.length) await msgs.bulkWrite(ops, { ordered: false });
  // An older bundle matches no document and its upsert collides with the newer one: that duplicate key means "keep".
  for (const op of bops) await bundles.bulkWrite([op]).catch((e) => { if (e?.code !== 11000) throw e; });
  return { lastChain, seen };
}
