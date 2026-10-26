import { schnorr } from '@noble/curves/secp256k1.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { FIELD_LEN, MLKEM_PK_LEN, PAYLOAD_LEN, TAG_LEN, VERSION } from './constants.ts';
import { b2, concat, equal, readU32, systemRand, u32, utf8 } from './crypto.ts';
import type { Identity, SignedPrekey } from './keys.ts';

// Public key bundle, signed by the owner key the registry maps the name to.
// ver | ownerPub 32 | idXPub 32 | spkId u32 | spkXPub 32 | spkKemPub 1184 | created u64 | nDevices u8 | devices 32*n | sig 64
export type Bundle = {
  ownerPub: Uint8Array;
  idXPub: Uint8Array;
  spkId: number;
  spkXPub: Uint8Array;
  spkKemPub: Uint8Array;
  created: bigint;
  devices: Uint8Array[];
};

const BUNDLE_VERSION = 1;
const FIXED = 1 + 32 + 32 + 4 + 32 + MLKEM_PK_LEN + 8 + 1;
export const MAX_DEVICES = Math.floor((PAYLOAD_LEN - 1 - TAG_LEN - FIELD_LEN - FIXED - 64) / 32);
export const BUNDLE_MARKER = b2(utf8('kasveil/v1/bundle-marker'));

function body(b: Bundle): Uint8Array {
  const created = new Uint8Array(8);
  new DataView(created.buffer).setBigUint64(0, b.created, false);
  return concat(
    new Uint8Array([BUNDLE_VERSION]), b.ownerPub, b.idXPub, u32(b.spkId), b.spkXPub, b.spkKemPub,
    created, new Uint8Array([b.devices.length]), ...b.devices,
  );
}

const digest = (bytes: Uint8Array) => b2(concat(utf8('kasveil/v1/bundle'), bytes));

export function makeBundle(id: Identity, spk: SignedPrekey, created: bigint, devices: Uint8Array[] = [], aux?: Uint8Array): Uint8Array {
  if (devices.length > MAX_DEVICES) throw new Error('too many devices');
  const bytes = body({ ownerPub: id.ownerPub, idXPub: id.idXPub, spkId: spk.spkId, spkXPub: spk.xPub, spkKemPub: spk.kemPub, created, devices });
  return concat(bytes, schnorr.sign(digest(bytes), id.ownerSk, aux ?? systemRand(32)));
}

// Returns the bundle only if its signature verifies against expectedOwner (from the registry).
export function parseBundle(bytes: Uint8Array, expectedOwner: Uint8Array): Bundle | null {
  if (bytes.length < FIXED + 64 || bytes[0] !== BUNDLE_VERSION) return null;
  const n = bytes[FIXED - 1];
  if (n > MAX_DEVICES) return null;
  const end = FIXED + 32 * n;
  if (bytes.length !== end + 64) return null;
  const signed = bytes.subarray(0, end);
  const ownerPub = bytes.slice(1, 33);
  if (!equal(ownerPub, expectedOwner) || !schnorr.verify(bytes.subarray(end), digest(signed), ownerPub)) return null;
  let o = 33;
  const take = (len: number) => bytes.slice(o, (o += len));
  const idXPub = take(32);
  const spkId = readU32(bytes, o);
  o += 4;
  const spkXPub = take(32);
  const spkKemPub = take(MLKEM_PK_LEN);
  const created = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(o, false);
  o += 9;
  const devices = Array.from({ length: n }, () => take(32));
  try {
    ml_kem768.encapsulate(spkKemPub, new Uint8Array(32)); // FIPS 203 key check: a bad ML-KEM key makes the bundle invalid
  } catch {
    return null;
  }
  return { ownerPub, idXPub, spkId, spkXPub, spkKemPub, created, devices };
}

// On-chain bundle publication: ver | tag | marker | bundle | zero padding. Bundles are public directory data.
export const bundleTag = (ownerPub: Uint8Array) => b2(concat(utf8('kasveil/v1/bundle-tag'), ownerPub), TAG_LEN);

// A bundle publication as indexers and clients must check it (§3, §4.3): the marker, a tag that is the tag of the
// bundle's own owner key, a valid bundle, and `created` (Unix seconds) no more than 24 hours ahead of nowSec.
export const BUNDLE_MAX_AHEAD_S = 24 * 3600;
export function parseBundlePayload(payload: Uint8Array, nowSec: number, expectedOwner?: Uint8Array): Bundle | null {
  const o = 1 + TAG_LEN + FIELD_LEN;
  if (payload.length !== PAYLOAD_LEN || payload[0] !== VERSION || !equal(payload.subarray(1 + TAG_LEN, o), BUNDLE_MARKER)) return null;
  const n = payload[o + FIXED - 1];
  if (n > MAX_DEVICES) return null;
  const owner = payload.slice(o + 1, o + 33);
  if ((expectedOwner && !equal(owner, expectedOwner)) || !equal(payload.subarray(1, 1 + TAG_LEN), bundleTag(owner))) return null;
  const b = parseBundle(payload.subarray(o, o + FIXED + 32 * n + 64), owner);
  return b && b.created <= BigInt(Math.floor(nowSec) + BUNDLE_MAX_AHEAD_S) ? b : null;
}

export function bundlePayload(bundle: Uint8Array): Uint8Array {
  const out = new Uint8Array(PAYLOAD_LEN);
  out[0] = VERSION;
  out.set(bundleTag(bundle.subarray(1, 33)), 1);
  out.set(BUNDLE_MARKER, 1 + TAG_LEN);
  out.set(bundle, 1 + TAG_LEN + FIELD_LEN);
  return out;
}
