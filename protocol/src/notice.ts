import { KIND_NOTICE } from './constants.ts';
import { GROUP_ID_LEN } from './group.ts';

// Conversation notices (body kind 0x07): something that happened on a member's device that the other members
// should see in the chat, sent by the app itself (WIRE_FORMAT §7.2). Shown as a line in the chat, never as a message.
// version u8 = 0x01 | context u8 (0x00 = the 1:1 session, 0x01 + 16-byte group ID) | event u8 | time u32 (Unix seconds)
export const NOTICE_SCREENSHOT = 0x01; // the device detected a screenshot (iPhone; Android 14 and later)
export const NOTICE_POSSIBLE_SCREENSHOT = 0x02; // a screenshot shortcut was pressed; the capture itself can't be seen
export const NOTICE_RECORDING = 0x03; // screen recording or mirroring started
export type Notice = { groupId: Uint8Array | null; event: number; time: number };

export function encodeNotice(n: Notice): Uint8Array {
  if (n.event < 1 || n.event > 3) throw new Error('unknown notice event');
  const k = n.groupId ? GROUP_ID_LEN : 0;
  const b = new Uint8Array(7 + k);
  b[0] = 1;
  b[1] = n.groupId ? 1 : 0;
  if (n.groupId) b.set(n.groupId, 2);
  b[2 + k] = n.event;
  new DataView(b.buffer).setUint32(3 + k, n.time >>> 0, false);
  return b;
}

// Unknown events are dropped, not shown: a newer app may add events an older one can't word correctly.
export function decodeNotice(b: Uint8Array): Notice | null {
  if (b.length < 7 || b[0] !== 1 || b[1] > 1) return null;
  const k = b[1] === 1 ? GROUP_ID_LEN : 0;
  if (b.length !== 7 + k) return null;
  const event = b[2 + k];
  if (event < 1 || event > 3) return null;
  return { groupId: k ? b.slice(2, 2 + k) : null, event, time: new DataView(b.buffer, b.byteOffset).getUint32(3 + k, false) };
}

export { KIND_NOTICE };
