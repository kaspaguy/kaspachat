import { TAG_LEN } from './constants.ts';
import { b2, concat, kdf, u32, utf8 } from './crypto.ts';

// Bucket = first 12 bits of the tag, big-endian (4,096 buckets). Indexers serve by bucket.
export const tagBucket = (tag: Uint8Array) => (tag[0] << 4) | (tag[1] >> 4);

// Registry lookups fetch a whole bucket: byte 0 of BLAKE2b(name) (256 buckets).
export const registryBucket = (name: string) => b2(utf8(name))[0];

// First contacts land in the recipient's inbox bucket, derived from their identity key.
export function inboxBucket(idXPub: Uint8Array): number {
  const h = b2(concat(utf8('kasveil/v1/inbox'), idXPub));
  return (h[0] << 4) | (h[1] >> 4);
}

export function withBucket(tag: Uint8Array, bucket: number): Uint8Array {
  const t = tag.slice();
  t[0] = bucket >> 4;
  t[1] = ((bucket & 0x0f) << 4) | (t[1] & 0x0f);
  return t;
}

// Per-direction tag chain: tag i = BLAKE2b(tagKey || i)[0..16]; every tag is fresh and unlinkable.
export const chainTag = (tagKey: Uint8Array, i: number) => b2(concat(tagKey, u32(i)), TAG_LEN);
export const headerKey = (tagKey: Uint8Array, i: number) => kdf(tagKey, 'header', 32, u32(i));
