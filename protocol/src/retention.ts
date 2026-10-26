// Disappearing messages. Every app in the conversation, the sender's included, runs this on its own copy: a message
// is deleted TIMER_SECONDS (30 hours) after it arrived on that device, unless the conversation's timer is off
// (effectiveSettings in settings.ts: only when every member is Plus and every member chose it off). Message keys
// are already gone by then: the ratchet deletes each one as soon as it decrypts its message.
import { TIMER_SECONDS } from './settings.ts';

export type Retained = { arrived: number };

export function purgeExpired<M extends Retained>(msgs: M[], timerSeconds: number, nowMs: number): M[] {
  if (timerSeconds === 0) return msgs;
  return msgs.filter((m) => nowMs - m.arrived < timerSeconds * 1000);
}

export { TIMER_SECONDS };
