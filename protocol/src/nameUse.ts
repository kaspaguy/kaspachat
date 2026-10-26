import { KIND_NAME } from './constants.ts';

// Name in use (body kind 0x08): the name the sender now goes by, sent over every established session when it
// changes (WIRE_FORMAT §7.3). The receiver adopts it only after the registry confirms the name belongs to the
// sender's key, and reads the tier from that registry entry, never from the message.
// version u8 = 0x01 | length u8 (1-20) | name (ASCII a-z, 0-9, '-')
const NAME_RE = /^[a-z0-9-]{1,20}$/;

export function encodeNameUse(name: string): Uint8Array {
  if (!NAME_RE.test(name)) throw new Error('not a valid name');
  const b = new Uint8Array(2 + name.length);
  b[0] = 1;
  b[1] = name.length;
  for (let i = 0; i < name.length; i++) b[2 + i] = name.charCodeAt(i);
  return b;
}

export function decodeNameUse(b: Uint8Array): string | null {
  if (b.length < 3 || b[0] !== 1 || b.length !== 2 + b[1]) return null;
  const name = String.fromCharCode(...b.subarray(2));
  return NAME_RE.test(name) ? name : null;
}

export { KIND_NAME };
