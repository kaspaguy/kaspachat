// KaspaChat client engine: everything between the screen and the network. All state lives in the encrypted vault;
// every change runs through one queue so the ratchet sessions are never touched concurrently.
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  KIND_GROUP_STATE, KIND_GROUP_TEXT, KIND_KEM_STEP, KIND_NAME, KIND_NOTICE, KIND_SETTINGS, KIND_TEXT, MAX_TEXT, MAX_TEXT_FIRST_CONTACT, GROUP_CAP,
  buildFirstContact, bundlePayload, bundleTag, coverFirstContact, coverPayload, decodePrefs, decrypt, defaultName, effectiveSettings,
  decodeNameUse, decodeNotice, encodeNameUse, encodeNotice, encodePrefs, encrypt, expectedTags, forgetPrekey, identityFromSeed, inboxBucket, kemOffer, kemStepDue, makeBundle, makeGroupState,
  makeGroupText, onFirstContactFromKnownPeer, parseBundlePayload, reachByFirstContact, receiveFirstContact, receiveGroupState, receiveGroupText,
  NOTICE_POSSIBLE_SCREENSHOT, NOTICE_RECORDING, NOTICE_SCREENSHOT, purgeExpired, registryBucket, sendToGroup, signedPrekey, tagBucket,
  type Bundle, type Group, type GroupMember, type Groups, type Identity, type Prefs, type SeenFirstContacts, type Session, type SignedPrekey,
} from '../../../protocol/src/index.ts';
import { ApiError, hex, indexer, relay, unhex } from './api.ts';
import { Vault } from './vault.ts';

const GRACE_DAA = 25_920_000;
const SPK_ROTATE_MS = 7 * 86_400_000;
const READONLY_MS = 7 * 86_400_000;
const WATCH_AHEAD = 8;
const FREE_TEST_KAS = 20; // the relay's minimum top-up; about 3,500 credits
const ACCOUNT_SCAN_GAP = 20; // unused account secrets in a row before a restore stops looking (abandoned orders use some)
const enc = new TextEncoder();
const dec = new TextDecoder();

export type Contact = { owner: string; name: string; idXPub: Uint8Array; bundle: Bundle | null; expiry: number; checked: number };
export type Msg = { id: string; from: string; text: string; t: number; arrived: number; state?: 'sending' | 'sent' | 'failed'; note?: boolean };
export type Convo = {
  id: string; kind: 'dm' | 'group'; peer?: string; groupId?: string; title: string; msgs: Msg[]; unread: number; request?: boolean;
  myPrefs?: Prefs; theirPrefs: Record<string, Prefs>; updated: number;
};
type SessionRec = { s: Session; fcTag: Uint8Array; until?: number };
export type Token = { info: string; input: string; output: string };
export type Order = {
  id: string; claim: string; kind: 'plus' | 'renew' | 'topup' | 'claim'; name?: string; months?: number; amount: number; address: string; status: string; created: number; error?: string;
  extraSompi?: number; extraChecked?: number;
};
// An encrypted payload waiting to be broadcast; `msg` is the chat message it carries a part of.
type Outbox = { payload: string; msg?: { convo: string; id: string } };
export type MyName = { name: string; expiry: number; n?: number; checked?: number };

export type State = {
  v: 1;
  mnemonic: string;
  seed: Uint8Array;
  name: string | null;
  names: MyName[];
  spkId: number;
  spkAt: number;
  oldSpks: { id: number; until: number }[];
  bundleAt: number;
  bundleSec?: boolean; // the published bundle's `created` is in seconds (WIRE_FORMAT §3); older apps wrote milliseconds
  accounts: { secret: string; kind: string; empty?: boolean }[];
  tokens: Token[];
  contacts: Record<string, Contact>;
  sessions: Record<string, SessionRec>;
  readonly: Record<string, SessionRec[]>;
  seenFC: SeenFirstContacts;
  groups: Groups;
  pendingGroup: { from: string; content: Uint8Array; at: number }[];
  convos: Record<string, Convo>;
  since: number;
  seenIds: string[];
  outbox: Outbox[];
  cover: { on: boolean; perDay: number; next: number; sentToday: number; day: string };
  orders: Order[];
  tipDaa: number;
  acctIndex: number;
  blocked?: Record<string, { name: string; at: number }>;
  announced?: Record<string, string>;
  notify?: { on: boolean; names: boolean };
  push?: { on: boolean; token?: string };
};
export type ReportReason = 'spam' | 'harassment' | 'illegal' | 'impersonation' | 'other';
export type Incoming = { convo: string; from: string; name: string };

export const newMnemonic = () => generateMnemonic(wordlist, 256);
const now = () => Date.now();
const rid = () => hex(crypto.getRandomValues(new Uint8Array(8)));
const today = () => new Date().toISOString().slice(0, 10);

export function isPlus(expiry: number, tipDaa: number) {
  return expiry > 1 && tipDaa > 0 && tipDaa <= expiry + GRACE_DAA;
}

// UTF-8 safe split into chunks of at most `max` bytes.
function chunks(text: string, max: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let cur = '';
  for (const ch of text) {
    if (enc.encode(cur + ch).length > max) {
      out.push(enc.encode(cur));
      cur = ch;
    } else cur += ch;
  }
  if (cur || !out.length) out.push(enc.encode(cur));
  return out;
}

function solvePow(challenge: string, bits: number, onProgress?: (n: number) => void): Promise<string> {
  return new Promise((resolve) => {
    const w = new Worker(new URL('./pow.worker.ts', import.meta.url), { type: 'module' });
    w.onmessage = (e) => {
      if (e.data.nonce !== undefined) {
        w.terminate();
        resolve(e.data.nonce);
      } else onProgress?.(e.data.progress);
    };
    w.postMessage({ challenge, bits });
  });
}

export class Engine {
  vault = new Vault<State>();
  id!: Identity;
  private q: Promise<unknown> = Promise.resolve();
  private listeners = new Set<() => void>();
  private timers: ReturnType<typeof setInterval>[] = [];
  private polling = false;
  status = { online: false, synced: false, lastError: '' as string, credits: 0 };
  config: any = null;
  // Called for every new message from someone else (the app decides whether to show a notification).
  onIncoming: (m: Incoming) => void = () => {};
  onWatch: ((t: { buckets: number[]; tags: string[] }) => Promise<boolean>) | null = null;
  private pushSig = '';
  private pushAt = 0;
  private noticeAt = new Map<string, number>();
  // Each session's watched tags, computed once until a payload on that session decrypts (only that moves them).
  private tagCache = new WeakMap<Session, { list: ReturnType<typeof expectedTags>; hexes: Set<string> }>();
  private watching(s: Session) {
    let w = this.tagCache.get(s);
    if (!w) {
      const list = expectedTags(s);
      w = { list, hexes: new Set(list.map((x) => hex(x.tag))) };
      this.tagCache.set(s, w);
    }
    return w;
  }

  get st(): State {
    return this.vault.data!;
  }
  subscribe(f: () => void) {
    this.listeners.add(f);
    return () => {
      this.listeners.delete(f);
    };
  }
  private emit() {
    this.vault.save();
    for (const f of this.listeners) f();
  }
  private run<T>(f: () => Promise<T>): Promise<T> {
    const p = this.q.then(f, f);
    this.q = p.catch(() => {});
    return p;
  }

  // ---------- lifecycle ----------
  async create(mnemonic: string, pass: string) {
    if (mnemonic.split(' ').length !== 24 || !validateMnemonic(mnemonic, wordlist)) throw new Error('not a valid 24-word phrase');
    const seed = mnemonicToSeedSync(mnemonic, '');
    const st: State = {
      v: 1, mnemonic, seed, name: null, names: [], spkId: 1, spkAt: now(), oldSpks: [], bundleAt: 0, accounts: [], tokens: [], contacts: {}, sessions: {},
      readonly: {}, seenFC: new Map(), groups: new Map(), pendingGroup: [], convos: {}, since: now() - 60_000, seenIds: [], outbox: [],
      cover: { on: true, perDay: 4, next: now() + 10 * 60_000, sentToday: 0, day: today() }, orders: [], tipDaa: 0, acctIndex: 0,
    };
    await this.vault.create(pass, st);
    this.id = identityFromSeed(seed);
  }
  async unlock(pass: string) {
    if (!(await this.vault.unlock(pass))) return false;
    this.id = identityFromSeed(this.st.seed);
    return true;
  }
  start() {
    this.timers.push(setInterval(() => void this.poll(), 2000));
    this.timers.push(setInterval(() => void this.run(() => this.maintenance()), 15_000));
    void this.loadConfig();
    void this.poll();
    void this.run(() => this.maintenance());
  }
  stop() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
  }
  async loadConfig() {
    try {
      this.config = await relay('/v1/config');
      this.status.online = true;
    } catch {
      this.status.online = false;
    }
    this.emit();
  }

  // Credit-account secrets come from the recovery phrase (index i), so a restored device finds its Plus months and
  // top-ups again. The relay stores only their hash.
  private claim(i: number) {
    return hex(hmac(sha256, sha256(new Uint8Array([...this.st.seed, ...enc.encode('kaspachat/v1/accounts')])), enc.encode(String(i))));
  }
  // SC-0024: an order's extras account (payments the order didn't use become credits there), same derivation as the relay.
  private extraSecret(claim: string) {
    return hex(hmac(sha256, unhex(claim), enc.encode('kaspachat/v1/extra')));
  }
  private async adoptExtras(o: Order) {
    const secret = this.extraSecret(o.claim);
    o.extraChecked = now();
    if (this.st.accounts.some((a) => a.secret === secret)) return;
    try {
      await relay('/v1/account', { account: secret });
      this.st.accounts.push({ secret, kind: 'topup' });
      setTimeout(() => void this.refreshCredits(), 0);
    } catch {}
  }
  private nextClaim() {
    this.st.acctIndex = (this.st.acctIndex ?? 0) + 1;
    return this.claim(this.st.acctIndex - 1);
  }
  // The relay refuses (409) a secret already in use, e.g. by an order still open from before a restore: take the next.
  private async withClaim<T>(f: (claim: string) => Promise<T>): Promise<T> {
    for (let i = 0; ; i++) {
      const claim = await this.run(async () => this.nextClaim());
      try {
        return await f(claim);
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 409 && /account secret/.test(e.message)) || i >= ACCOUNT_SCAN_GAP) throw e;
      }
    }
  }
  private async recoverAccounts() {
    let misses = 0;
    for (let i = 0; misses < ACCOUNT_SCAN_GAP && i < 200; i++) {
      let used = false;
      for (const c of [this.claim(i), this.extraSecret(this.claim(i))]) {
        try {
          const r = await relay('/v1/account', { account: c });
          if (!this.st.accounts.some((a) => a.secret === c)) this.st.accounts.push({ secret: c, kind: r.kind });
          used = true;
        } catch {}
      }
      if (used) {
        this.st.acctIndex = i + 1;
        misses = 0;
      } else misses++;
    }
  }

  spk(id = this.st.spkId): SignedPrekey {
    return signedPrekey(this.id, id);
  }
  get ownerHex() {
    return hex(this.id.ownerPub);
  }
  get myPlus() {
    const n = this.st.names.find((x) => x.name === this.st.name);
    return !!n && isPlus(n.expiry, this.st.tipDaa);
  }

  // ---------- registration ----------
  // Finds names this key already holds (after a restore): the free names it can derive, and any Plus names.
  async findMyNames() {
    const found: MyName[] = [];
    for (let n = 0; n <= 2; n++) {
      const name = defaultName(this.id.ownerPub, n);
      const r = await indexer(`/v1/registry/bucket/${registryBucket(name)}`);
      const e = r.entries.find((x: any) => x.name === name && x.owner === this.ownerHex);
      if (e) found.push({ name, expiry: e.expiry, n });
    }
    try {
      const r = await indexer(`/v1/registry/owner/${this.ownerHex}`);
      for (const e of r.entries) if (e.name && !found.some((f) => f.name === e.name)) found.push({ name: e.name, expiry: e.expiry });
    } catch {}
    return found;
  }

  async registerFree(n: number, onProgress?: (msg: string) => void) {
    const r = await this.withClaim(async (claim) => {
      onProgress?.('Getting a puzzle from the doorman…');
      const ch = await relay('/v1/pow');
      onProgress?.('Solving the anti-spam puzzle on this device…');
      const nonce = await solvePow(ch.challenge, ch.bits);
      onProgress?.('Registering your name on the Kaspa testnet…');
      return relay('/v1/names/default', { owner: this.ownerHex, n, pow: { challenge: ch.challenge, nonce }, claim });
    });
    await this.run(async () => {
      this.st.names.push({ name: r.name, expiry: 0, n });
      if (!this.st.name || this.st.names.length === 1) this.st.name = r.name;
      this.st.accounts.push({ secret: r.account, kind: 'welcome' });
      this.emit();
    });
    onProgress?.('Publishing your public keys…');
    await this.run(() => this.publishBundle());
    await this.run(() => this.ensureTokens(10));
    return r.name as string;
  }

  async adoptNames(found: MyName[]) {
    await this.run(async () => {
      this.st.names = found;
      // A restored client reads its current prekey from its latest bundle (WIRE_FORMAT §2), moves on to the next one
      // and keeps that one a week for first contacts already on their way.
      const mine = await this.fetchBundle(this.id.ownerPub).catch(() => null);
      if (mine && mine.spkId >= this.st.spkId) {
        this.st.oldSpks = [{ id: mine.spkId, until: now() + SPK_ROTATE_MS }];
        this.st.spkId = mine.spkId + 1;
        this.st.spkAt = now();
      }
      const plus = found.find((f) => f.expiry > 1);
      this.st.name = plus?.name ?? found[0]?.name ?? null;
      await this.recoverAccounts();
      this.emit();
    });
    await this.run(() => this.publishBundle());
  }

  private async publishBundle() {
    const b = makeBundle(this.id, this.spk(), BigInt(Math.floor(now() / 1000)));
    try {
      await relay('/v1/bundle', { payload: hex(bundlePayload(b)) });
      this.st.bundleAt = now();
      this.st.bundleSec = true;
    } catch (e) {
      this.status.lastError = `Could not publish keys: ${(e as Error).message}`;
    }
    this.emit();
  }

  // ---------- credits (blind tokens) ----------
  async refreshCredits() {
    let total = this.st.tokens.length;
    for (const a of this.st.accounts) {
      try {
        const r = await relay('/v1/account', { account: a.secret });
        total += r.credits;
        a.empty = r.credits === 0;
      } catch {}
    }
    this.status.credits = total;
    this.emit();
  }
  private async ensureTokens(min = 5) {
    // Drop tokens whose month has ended (the relay would refuse them).
    this.st.tokens = this.st.tokens.filter((t) => t.info === 'topup' || now() - Date.parse(t.info.slice(2)) < 30 * 86_400_000);
    if (this.st.tokens.length >= min || !this.config) return;
    const pk = unhex(this.config.tokenPublicKey);
    const order = ['plus', 'welcome', 'topup'];
    for (const a of [...this.st.accounts].sort((x, y) => order.indexOf(x.kind) - order.indexOf(y.kind))) {
      if (this.st.tokens.length >= min) break;
      if (a.empty && a.kind !== 'plus') continue; // a Plus account refills when its next month starts
      try {
        const info = (await relay('/v1/account', { account: a.secret })).info as string;
        const P = ristretto255_oprf.poprf(enc.encode(info));
        const items = Array.from({ length: 20 }, () => {
          const input = crypto.getRandomValues(new Uint8Array(32));
          return { input, ...P.blind(input, pk) };
        });
        const r = await relay('/v1/tokens', { account: a.secret, blinded: items.map((i) => hex(i.blinded)) });
        const use = items.slice(0, r.evaluated.length);
        const outs = P.finalizeBatch(use.map((it, i) => ({ input: it.input, blind: it.blind, evaluated: unhex(r.evaluated[i]), blinded: it.blinded })), unhex(r.proof), use[0].tweakedKey);
        this.st.tokens.push(...outs.map((o, i) => ({ info: r.info, input: hex(use[i].input), output: hex(o) })));
        a.empty = r.remaining === 0;
      } catch (e) {
        if (e instanceof ApiError && (e.status === 402 || e.status === 404)) a.empty = true;
      }
    }
    this.emit();
  }

  // Every encrypted payload leaves through the outbox (WIRE_FORMAT §4.1). The vault, holding the session that produced it,
  // is written before anything is broadcast, so a crash can never make the app derive the same message key again;
  // a payload that can't go now is retried later as it is, in order, and never re-encrypted or dropped.
  private async enqueue(payload: Uint8Array, msg?: Outbox['msg']) {
    this.st.outbox.push({ payload: hex(payload), msg });
    await this.vault.flush();
  }
  private outboxWait = 0;
  // Sends what it can, oldest first; false if something is still waiting. `force` ignores the back-off (the user sent).
  private async flushOutbox(force = false): Promise<boolean> {
    if (!force && now() < this.outboxWait) return !this.st.outbox.length;
    while (this.st.outbox.length) {
      const o = this.st.outbox[0];
      try {
        await this.sendPayload(unhex(o.payload));
      } catch (e) {
        const credits = e instanceof ApiError && e.status === 402;
        this.outboxWait = now() + (credits ? 60_000 : 5_000);
        this.status.lastError = `${this.st.outbox.length} message${this.st.outbox.length > 1 ? 's' : ''} waiting to go out: ${credits ? 'out of message credits. Top up or get Pro and they will be sent.' : (e as Error).message}`;
        return false;
      }
      this.st.outbox.shift();
      if (o.msg && !this.st.outbox.some((x) => x.msg?.id === o.msg!.id && x.msg.convo === o.msg!.convo)) {
        const m = this.st.convos[o.msg.convo]?.msgs.find((x) => x.id === o.msg!.id);
        if (m) m.state = 'sent';
      }
    }
    this.status.lastError = '';
    return true;
  }

  // One token pays one message. Throws when out of credits. Encrypted payloads go through enqueue(), not here.
  private async sendPayload(payload: Uint8Array) {
    for (let attempt = 0; attempt < 4; attempt++) {
      await this.ensureTokens(1);
      const t = this.st.tokens.shift();
      if (!t) throw new ApiError(402, 'Out of message credits. Top up or get Pro.');
      try {
        const r = await relay('/v1/send', { payload: hex(payload), token: t });
        this.emit();
        return r.txid as string;
      } catch (e) {
        if (e instanceof ApiError && (e.status === 402 || e.status === 409)) continue; // expired or spent token: drop it
        this.st.tokens.unshift(t);
        throw e;
      }
    }
    throw new ApiError(402, 'Out of message credits.');
  }

  // ---------- directory ----------
  async lookup(name: string, fresh = false): Promise<Contact | null> {
    name = name.trim().toLowerCase().replace(/^@/, '');
    const known = Object.values(this.st.contacts).find((c) => c.name === name);
    if (known && known.bundle && !fresh && now() - known.checked < 3600_000) return known;
    const c = await this.fetchContact(name);
    if (c) await this.run(async () => {
      this.remember(c);
      this.emit();
    });
    return c;
  }
  // lookup() runs inside the queue too; inside a queued task use this variant to avoid waiting on ourselves.
  private async lookupInner(name: string) {
    const c = await this.fetchContact(name.trim().toLowerCase().replace(/^@/, ''));
    if (c) this.remember(c);
    return c;
  }
  // The owner's current bundle from the directory, checked as WIRE_FORMAT §3/§4.3 require.
  private async fetchBundle(owner: Uint8Array): Promise<Bundle | null> {
    const tag = bundleTag(owner);
    const hit = (await indexer(`/v1/bundles/${tagBucket(tag)}`)).bundles.find((x: any) => x.tag === hex(tag));
    return hit ? parseBundlePayload(unhex(hit.p), now() / 1000, owner) : null;
  }
  // A name's registry entry and its owner's keys; null if it isn't registered, has lapsed, or has no valid keys out.
  private async fetchContact(name: string): Promise<Contact | null> {
    const e = (await indexer(`/v1/registry/bucket/${registryBucket(name)}`)).entries.find((x: any) => x.name === name);
    if (!e || e.owner === '00'.repeat(32)) return null;
    const bundle = await this.fetchBundle(unhex(e.owner));
    return bundle && { owner: e.owner, name, idXPub: bundle.idXPub, bundle, expiry: e.expiry, checked: now() };
  }
  // Someone we know by their Plus name keeps it when we look them up by another of their names.
  private remember(c: Contact) {
    const prev = this.st.contacts[c.owner];
    this.st.contacts[c.owner] = prev && prev.name !== c.name && prev.expiry > 1 && isPlus(prev.expiry, this.st.tipDaa) ? { ...c, name: prev.name } : c;
  }

  // ---------- conversations ----------
  private convo(id: string, init: () => Convo) {
    return (this.st.convos[id] ??= init());
  }
  private dmConvo(owner: string) {
    const c = this.st.contacts[owner];
    return this.convo(`d:${owner}`, () => ({ id: `d:${owner}`, kind: 'dm', peer: owner, title: c ? `@${c.name}` : 'unknown', msgs: [], unread: 0, theirPrefs: {}, updated: now() }));
  }
  private push(cv: Convo, m: Msg, unread = true) {
    if (cv.msgs.some((x) => x.id === m.id)) return;
    cv.msgs.push(m);
    cv.updated = now();
    if (unread && m.from !== 'me' && !m.note) cv.unread++;
  }

  // key: from an invite (lib/invite.ts), the start of the owner key the name had when the invite was made.
  async startChat(name: string, key?: string): Promise<string> {
    const c = await this.lookup(name, true);
    if (!c) throw new Error(`@${name.replace(/^@/, '')} not found (or has not published keys yet)`);
    if (c.owner === this.ownerHex) throw new Error("That's you.");
    if (key && !c.owner.startsWith(key)) throw new Error(`@${c.name} now belongs to someone else, not the person who made this invite.`);
    return this.run(async () => {
      const cv = this.dmConvo(c.owner);
      cv.title = `@${c.name}`;
      this.emit();
      return cv.id;
    });
  }

  markRead(id: string) {
    const cv = this.st.convos[id];
    if (cv && (cv.unread || cv.request === undefined)) {
      cv.unread = 0;
      this.emit();
    }
  }
  accept(id: string) {
    const cv = this.st.convos[id];
    if (cv) {
      cv.request = false;
      this.emit();
    }
  }
  deleteConvo(id: string) {
    void this.run(async () => {
      delete this.st.convos[id];
      this.emit();
    });
  }

  // ---------- block and report ----------
  // Blocking is local: nothing tells the other person. Their texts and notices are dropped on this device; a first
  // contact from them opens nothing. In a group they stay a member (only the admin changes members), just unseen.
  isBlocked(owner: string) {
    return !!this.st.blocked?.[owner];
  }
  block(owner: string) {
    return this.run(async () => {
      (this.st.blocked ??= {})[owner] = { name: this.st.contacts[owner]?.name ?? '?', at: now() };
      const cv = this.st.convos[`d:${owner}`];
      if (cv?.request) delete this.st.convos[cv.id];
      this.emit();
    });
  }
  unblock(owner: string) {
    return this.run(async () => {
      delete this.st.blocked?.[owner];
      this.emit();
    });
  }
  // A report is the one time message text leaves the device unencrypted: only what the reporter picked, sent to
  // Kaspaguy's moderation inbox. The reporter's own name is not sent.
  async report(cvId: string, owner: string, reason: ReportReason, note: string, includeMsgs: boolean) {
    const cv = this.st.convos[cvId];
    const c = this.st.contacts[owner];
    const msgs = includeMsgs && cv ? cv.msgs.filter((m) => !m.note && (m.from === owner || m.from === 'me')).slice(-20) : [];
    await relay('/v1/report', {
      name: c?.name ?? '', reason, note: note.slice(0, 1000), group: cv?.kind === 'group',
      messages: msgs.map((m) => ({ from: m.from === owner ? 'reported' : 'reporter', text: m.text.slice(0, 2000), t: m.t })),
    });
  }

  // ---------- screenshot notices (PROTOCOL_SPEC §8.2) ----------
  // Sent by this device when it detects a screenshot, a likely screenshot or a screen recording in a protected chat.
  // Once per chat per 30 seconds; members without a session yet aren't told (a notice can't open a session).
  screenEvent(id: string, event: number) {
    const cv = this.st.convos[id];
    if (!cv || !this.settingsOf(cv).screenshotProtection) return;
    const key = `${id}:${event}`;
    if (now() - (this.noticeAt.get(key) ?? 0) < 30_000) return;
    this.noticeAt.set(key, now());
    return this.run(async () => {
      const content = encodeNotice({ groupId: cv.kind === 'group' ? unhex(cv.groupId!) : null, event, time: Math.floor(now() / 1000) });
      let told = true;
      try {
        if (cv.kind === 'dm') {
          if (this.st.sessions[cv.peer!]?.s.cks) await this.sendDm(cv.peer!, KIND_NOTICE, content);
          else told = false;
        } else {
          const g = this.st.groups.get(cv.groupId!)!;
          const sessions = new Map(Object.entries(this.st.sessions).filter(([, r]) => r.s.cks).map(([k, r]) => [k, r.s]));
          const { sent, missing } = sendToGroup(g, this.id.ownerPub, sessions, KIND_NOTICE as typeof KIND_GROUP_TEXT, content);
          for (const x of sent) await this.enqueue(x.payload);
          told = !missing.length;
        }
        told = (await this.flushOutbox(true)) && told;
      } catch {
        told = false;
      }
      const what = event === NOTICE_SCREENSHOT ? 'Screenshot detected on this device.' : event === NOTICE_RECORDING ? 'Screen recording detected on this device.' : 'Possible screenshot detected on this device.';
      this.push(cv, { id: rid(), from: 'me', text: `${what} ${told ? 'The others in this chat were told.' : "Not everyone could be told (no credits or no connection yet)."}`, t: now(), arrived: now(), note: true }, false);
      this.emit();
    });
  }

  // Effective timer and screenshot rule for a conversation (PROTOCOL_SPEC §8.1): members' tiers come from the registry.
  settingsOf(cv: Convo) {
    const members = this.membersOf(cv).map((o) => ({
      plus: o === this.ownerHex ? this.myPlus : isPlus(this.st.contacts[o]?.expiry ?? 0, this.st.tipDaa),
      prefs: o === this.ownerHex ? cv.myPrefs ?? null : cv.theirPrefs[o] ?? null,
    }));
    return { ...effectiveSettings(members), allPlus: members.every((m) => m.plus) };
  }
  membersOf(cv: Convo): string[] {
    if (cv.kind === 'dm') return [this.ownerHex, cv.peer!];
    const g = this.st.groups.get(cv.groupId!);
    return g ? g.state.members.map((m) => hex(m.ownerPub)) : [this.ownerHex];
  }

  setTimerOff(id: string, off: boolean) {
    return this.setPrefs(id, { timerOff: off });
  }
  // Plus only (PROTOCOL_SPEC §8.2): on for the whole conversation if any Plus member turns it on.
  setScreenshotProtection(id: string, on: boolean) {
    return this.setPrefs(id, { screenshotProtection: on });
  }
  private async setPrefs(id: string, change: { timerOff?: boolean; screenshotProtection?: boolean }) {
    return this.run(async () => {
      const cv = this.st.convos[id];
      const epoch = (cv.myPrefs?.epoch ?? 0) + 1;
      cv.myPrefs = {
        version: 2, epoch, groupId: cv.kind === 'group' ? unhex(cv.groupId!) : null,
        timerOff: change.timerOff ?? cv.myPrefs?.timerOff ?? false,
        screenshotProtection: change.screenshotProtection ?? cv.myPrefs?.screenshotProtection ?? false,
      };
      await this.sendToConvo(cv, KIND_SETTINGS, encodePrefs(cv.myPrefs));
      this.emit();
    });
  }

  // ---------- sending ----------
  sendText(id: string, text: string) {
    return this.run(async () => {
      const cv = this.st.convos[id];
      const body = text.trim();
      if (!cv || !body) return;
      cv.request = false;
      const msgId = crypto.getRandomValues(new Uint8Array(16));
      const m: Msg = { id: hex(msgId), from: 'me', text: body, t: now(), arrived: now(), state: 'sending' };
      this.push(cv, m, false);
      this.emit();
      const ref = { convo: cv.id, id: m.id };
      try {
        if (cv.kind === 'dm') {
          for (const p of chunks(body, MAX_TEXT)) await this.sendDm(cv.peer!, KIND_TEXT, p, ref);
        } else {
          const g = this.st.groups.get(cv.groupId!)!;
          for (const p of chunks(body, MAX_TEXT - 37)) await this.sendGroup(g, KIND_GROUP_TEXT, makeGroupText(g.state.groupId, g.state.epoch, msgId, p), ref);
        }
        await this.flushOutbox(true);
      } catch (e) {
        m.state = 'failed';
        this.status.lastError = (e as Error).message;
      }
      this.emit();
    });
  }

  private async sendToConvo(cv: Convo, kind: number, content: Uint8Array) {
    if (cv.kind === 'dm') await this.sendDm(cv.peer!, kind, content);
    else await this.sendGroup(this.st.groups.get(cv.groupId!)!, kind as typeof KIND_GROUP_STATE, content);
    await this.flushOutbox(true);
  }

  // One payload to a peer: over the session if there is one, else by first contact (with an empty opener when the
  // content doesn't fit). Starts a KEM step first when one is due.
  private async sendDm(owner: string, kind: number, content: Uint8Array, msg?: Outbox['msg']) {
    const rec = this.st.sessions[owner];
    if (rec?.s.cks) {
      if (kemStepDue(rec.s)) await this.enqueue(encrypt(rec.s, KIND_KEM_STEP, kemOffer(rec.s)));
      await this.enqueue(encrypt(rec.s, kind, content), msg);
      return;
    }
    const c = this.st.contacts[owner];
    const bundle = (c?.bundle && now() - c.checked < 3600_000 ? c : c?.name ? await this.lookupInner(c.name) : null)?.bundle;
    if (!bundle) throw new Error('No keys published for this contact.');
    const fits = kind === KIND_TEXT ? content.length <= MAX_TEXT_FIRST_CONTACT : false;
    const fc = buildFirstContact(this.id, this.st.name!, bundle, fits ? content : new Uint8Array(0));
    this.st.sessions[owner] = { s: fc.session, fcTag: fc.payload.subarray(1, 17) };
    await this.enqueue(fc.payload, msg);
    (this.st.announced ??= {})[owner] = this.st.name!;
    if (!fits) await this.enqueue(encrypt(fc.session, kind, content), msg);
  }

  private async sendGroup(g: Group, kind: typeof KIND_GROUP_STATE | typeof KIND_GROUP_TEXT, content: Uint8Array, msg?: Outbox['msg']) {
    const sessions = new Map(Object.entries(this.st.sessions).filter(([, r]) => r.s.cks).map(([k, r]) => [k, r.s]));
    const { sent, missing } = sendToGroup(g, this.id.ownerPub, sessions, kind, content);
    for (const x of sent) await this.enqueue(x.payload, msg);
    for (const m of missing) {
      const c = await this.lookupInner(m.name);
      if (!c?.bundle || c.owner !== hex(m.ownerPub)) continue;
      const r = reachByFirstContact(this.id, this.st.name!, c.bundle, kind, content);
      this.st.sessions[c.owner] = { s: r.session, fcTag: r.payloads[0].subarray(1, 17) };
      for (const p of r.payloads) await this.enqueue(p, msg);
    }
  }

  // ---------- groups ----------
  createGroup(names: string[]) {
    return this.run(async () => {
      const members: GroupMember[] = [{ ownerPub: this.id.ownerPub, idXPub: this.id.idXPub, name: this.st.name! }];
      for (const n of names) {
        const c = await this.lookupInner(n);
        if (!c) throw new Error(`@${n} not found`);
        if (!members.some((m) => hex(m.ownerPub) === c.owner)) members.push({ ownerPub: unhex(c.owner), idXPub: c.idXPub, name: c.name });
      }
      if (members.length < 2 || members.length > GROUP_CAP) throw new Error(`A group has 2 to ${GROUP_CAP} members, you included.`);
      const groupId = crypto.getRandomValues(new Uint8Array(16));
      const state = makeGroupState(this.id, groupId, 1, members);
      receiveGroupState(this.st.groups, this.id.ownerPub, this.id.ownerPub, state);
      const g = this.st.groups.get(hex(groupId))!;
      const cv = this.groupConvo(g);
      this.push(cv, { id: rid(), from: 'me', text: `You created the group with ${members.slice(1).map((m) => '@' + m.name).join(', ')}.`, t: now(), arrived: now(), note: true }, false);
      this.emit();
      await this.sendGroup(g, KIND_GROUP_STATE, state);
      await this.flushOutbox(true);
      this.emit();
      return cv.id;
    });
  }
  changeMembers(id: string, add: string[], remove: string[]) {
    return this.run(async () => {
      const cv = this.st.convos[id];
      const g = this.st.groups.get(cv.groupId!)!;
      if (hex(g.state.admin) !== this.ownerHex) throw new Error('Only the admin can change members.');
      let members = g.state.members.filter((m) => !remove.includes(m.name));
      for (const n of add) {
        const c = await this.lookupInner(n);
        if (!c) throw new Error(`@${n} not found`);
        if (!members.some((m) => hex(m.ownerPub) === c.owner)) members.push({ ownerPub: unhex(c.owner), idXPub: c.idXPub, name: c.name });
      }
      if (members.length > GROUP_CAP) throw new Error(`At most ${GROUP_CAP} members.`);
      const old = { ...g, state: { ...g.state } };
      const state = makeGroupState(this.id, g.state.groupId, g.state.epoch + 1, members);
      receiveGroupState(this.st.groups, this.id.ownerPub, this.id.ownerPub, state);
      // Removed members get the new state too, so they know they are out.
      const union = { ...old, state: { ...old.state, members: [...members, ...old.state.members.filter((m) => !members.some((x) => hex(x.ownerPub) === hex(m.ownerPub)))] } };
      await this.sendGroup(union, KIND_GROUP_STATE, state);
      await this.flushOutbox(true);
      this.push(cv, { id: rid(), from: 'me', text: `Members: ${members.map((m) => '@' + m.name).join(', ')}`, t: now(), arrived: now(), note: true }, false);
      this.emit();
    });
  }
  private groupConvo(g: Group) {
    const id = hex(g.state.groupId);
    const cv = this.convo(`g:${id}`, () => ({ id: `g:${id}`, kind: 'group', groupId: id, title: '', msgs: [], unread: 0, theirPrefs: {}, updated: now() }));
    cv.title = g.state.members.filter((m) => hex(m.ownerPub) !== this.ownerHex).map((m) => '@' + (this.st.contacts[hex(m.ownerPub)]?.name ?? m.name)).join(', ') || 'Group';
    return cv;
  }

  // ---------- receiving ----------
  private watchedBuckets(): number[] {
    const b = new Set<number>([inboxBucket(this.id.idXPub)]);
    for (const rec of [...Object.values(this.st.sessions), ...Object.values(this.st.readonly).flat()]) {
      const seen = new Map<string, number>();
      for (const w of this.watching(rec.s).list) {
        const n = seen.get(w.chain) ?? 0;
        if (n >= WATCH_AHEAD) continue;
        seen.set(w.chain, n + 1);
        b.add(tagBucket(w.tag));
      }
    }
    return [...b].slice(0, 64);
  }

  // iPhone push (opt-in): the upcoming tags of every session, for the phone's notification extension, and their
  // buckets for the push service. Never the fixed first-contact inbox bucket, which would identify the phone for good;
  // so message requests wait until the app is opened. Blocked owners' sessions are left out.
  watchTargets() {
    const tags: string[] = [];
    const entries = [...Object.entries(this.st.sessions).map(([o, r]) => [o, r] as const), ...Object.entries(this.st.readonly).flatMap(([o, l]) => l.map((r) => [o, r] as const))];
    for (const [o, rec] of entries) {
      if (this.isBlocked(o)) continue;
      const seen = new Map<string, number>();
      for (const w of this.watching(rec.s).list) {
        const n = seen.get(w.chain) ?? 0;
        if (n >= WATCH_AHEAD) continue;
        seen.set(w.chain, n + 1);
        tags.push(hex(w.tag));
      }
    }
    const buckets = [...new Set(tags.map((t) => tagBucket(unhex(t))))].slice(0, 64);
    return { buckets, tags: tags.filter((t) => buckets.includes(tagBucket(unhex(t)))) };
  }
  private async pushTick() {
    if (!this.st.push?.on || !this.onWatch) return;
    const t = this.watchTargets();
    const sig = t.tags.join('');
    if (!t.buckets.length || (sig === this.pushSig && now() - this.pushAt < 12 * 3600_000)) return;
    if (await this.onWatch(t).catch(() => false)) {
      this.pushSig = sig;
      this.pushAt = now();
    }
  }
  setPush(on: boolean, token?: string) {
    this.st.push = on ? { on, token } : { on: false };
    this.pushSig = '';
    this.emit();
    void this.run(() => this.pushTick());
  }

  async poll() {
    if (this.polling || !this.vault.data || !this.st.name) return;
    this.polling = true;
    try {
      const buckets = this.watchedBuckets();
      const since = this.st.since - 15_000;
      const r = await indexer(`/v1/buckets?b=${buckets.join(',')}&since=${since}`);
      this.status.online = true;
      this.status.synced = true;
      await this.run(async () => {
        const seen = new Set(this.st.seenIds);
        for (const m of r.messages) {
          if (seen.has(m.id)) continue;
          seen.add(m.id);
          this.st.seenIds.push(m.id);
          await this.receive(unhex(m.p), m.b);
        }
        if (this.st.seenIds.length > 4000) this.st.seenIds.splice(0, this.st.seenIds.length - 4000);
        this.st.since = r.now;
        await this.flushOutbox();
        this.emit();
      });
    } catch (e) {
      this.status.online = false;
      this.status.lastError = (e as Error).message;
      for (const f of this.listeners) f();
    } finally {
      this.polling = false;
    }
  }

  private async receive(p: Uint8Array, bucket: number) {
    const tag = hex(p.subarray(1, 17));
    for (const [owner, rec] of Object.entries(this.st.sessions)) {
      if (!this.watching(rec.s).hexes.has(tag)) continue;
      const d = decrypt(rec.s, p);
      if (!d) continue;
      this.tagCache.delete(rec.s);
      return this.handle(owner, d.kind, d.content, d.kemAnswer);
    }
    for (const [owner, list] of Object.entries(this.st.readonly)) {
      for (const rec of list) {
        if (!this.watching(rec.s).hexes.has(tag)) continue;
        const d = decrypt(rec.s, p);
        if (!d) continue;
        this.tagCache.delete(rec.s);
        return this.handle(owner, d.kind, d.content);
      }
    }
    if (bucket === inboxBucket(this.id.idXPub)) await this.firstContact(p);
  }

  private async firstContact(p: Uint8Array) {
    const prekeys = [this.spk(), ...this.st.oldSpks.map((o) => this.spk(o.id))];
    // First pass learns the claimed sender name without opening; the second checks it against the registry.
    const claimed = { name: '' };
    receiveFirstContact(new Map(this.st.seenFC), this.id, prekeys, p, (n) => ((claimed.name = n), null));
    if (!claimed.name) return;
    const c = await this.lookupInner(claimed.name);
    if (!c) return;
    const got = receiveFirstContact(this.st.seenFC, this.id, prekeys, p, (n) => (n === c.name ? { ownerPub: unhex(c.owner), idXPub: c.idXPub } : null));
    if (!got || got === 'replay') return;
    const owner = c.owner;
    if (this.isBlocked(owner)) return;
    const tagNew = p.subarray(1, 17);
    const cur = this.st.sessions[owner];
    if (cur && onFirstContactFromKnownPeer(cur.s, cur.fcTag, tagNew) === 'keep-current') {
      (this.st.readonly[owner] ??= []).push({ s: got.session, fcTag: tagNew, until: now() + READONLY_MS });
    } else {
      if (cur) (this.st.readonly[owner] ??= []).push({ ...cur, until: now() + READONLY_MS });
      this.st.sessions[owner] = { s: got.session, fcTag: tagNew };
    }
    const cv = this.st.convos[`d:${owner}`];
    if (!cv && got.kind === KIND_TEXT && got.text.length) this.dmConvo(owner).request = true;
    await this.handle(owner, got.kind, got.text);
  }

  private async handle(owner: string, kind: number, content: Uint8Array, kemAnswer?: Uint8Array) {
    if (this.isBlocked(owner) && kind !== KIND_GROUP_STATE && kind !== KIND_SETTINGS && kind !== KIND_KEM_STEP) return;
    if (kemAnswer) {
      const rec = this.st.sessions[owner];
      if (rec?.s.cks) await this.enqueue(encrypt(rec.s, KIND_KEM_STEP, kemAnswer));
    }
    if (kind === KIND_TEXT) {
      if (!content.length) return;
      const cv = this.dmConvo(owner);
      this.push(cv, { id: rid(), from: owner, text: dec.decode(content), t: now(), arrived: now() });
      this.onIncoming({ convo: cv.id, from: owner, name: this.st.contacts[owner]?.name ?? '' });
    } else if (kind === KIND_GROUP_STATE) {
      const r = receiveGroupState(this.st.groups, this.id.ownerPub, unhex(owner), content);
      if (!r) return;
      const g = this.st.groups.get(hex(r.groupId))!;
      for (const m of g.state.members) {
        const o = hex(m.ownerPub);
        if (o !== this.ownerHex && !this.st.contacts[o]) this.st.contacts[o] = { owner: o, name: m.name, idXPub: m.idXPub, bundle: null, expiry: 0, checked: 0 };
      }
      const cv = this.groupConvo(g);
      const text = r.event === 'joined' ? `@${this.st.contacts[owner]?.name ?? '?'} added you to the group.` : r.event === 'removed' ? 'You were removed from the group.' : `Members: ${g.state.members.map((m) => '@' + m.name).join(', ')}`;
      this.push(cv, { id: rid(), from: owner, text, t: now(), arrived: now(), note: true });
      const pending = this.st.pendingGroup;
      this.st.pendingGroup = [];
      for (const x of pending) await this.handle(x.from, KIND_GROUP_TEXT, x.content);
    } else if (kind === KIND_GROUP_TEXT) {
      const r = receiveGroupText(this.st.groups, this.id.ownerPub, unhex(owner), content);
      if (r === 'pending') {
        this.st.pendingGroup.push({ from: owner, content, at: now() });
        return;
      }
      if (!r) return;
      const g = this.st.groups.get(hex(r.groupId))!;
      const cv = this.groupConvo(g);
      const id = hex(r.msgId);
      const prev = cv.msgs.find((m) => m.id === id && m.from === owner);
      if (prev) prev.text += dec.decode(r.text);
      else {
        this.push(cv, { id, from: owner, text: dec.decode(r.text), t: now(), arrived: now() });
        this.onIncoming({ convo: cv.id, from: owner, name: this.st.contacts[owner]?.name ?? '' });
      }
    } else if (kind === KIND_SETTINGS) {
      const pr = decodePrefs(content);
      if (!pr) return;
      const cv = pr.groupId ? this.st.convos[`g:${hex(pr.groupId)}`] : this.dmConvo(owner);
      if (cv && (cv.theirPrefs[owner]?.epoch ?? 0) < pr.epoch) cv.theirPrefs[owner] = pr;
    } else if (kind === KIND_NOTICE) {
      const n = decodeNotice(content);
      if (!n) return;
      const g = n.groupId ? this.st.groups.get(hex(n.groupId)) : null;
      if (n.groupId && !g?.state.members.some((m) => hex(m.ownerPub) === owner)) return;
      const cv = g ? this.groupConvo(g) : this.st.convos[`d:${owner}`];
      if (!cv) return;
      const who = '@' + (this.st.contacts[owner]?.name ?? '?');
      const text = n.event === NOTICE_SCREENSHOT ? `Screenshot detected: ${who} took a screenshot.` : n.event === NOTICE_RECORDING ? `Screen recording detected on ${who}'s device.` : `Possible screenshot detected on ${who}'s device.`;
      this.push(cv, { id: rid(), from: owner, text, t: now(), arrived: now(), note: true });
    } else if (kind === KIND_NAME) {
      // Adopted only once the registry maps the name to this sender's key; the tier comes from that entry.
      const name = decodeNameUse(content);
      const c = this.st.contacts[owner];
      if (!name || !c || c.name === name) return;
      const r = await indexer(`/v1/registry/bucket/${registryBucket(name)}`).catch(() => null);
      const e = r?.entries.find((x: any) => x.name === name && x.owner === owner);
      if (!e) return;
      this.st.contacts[owner] = { ...c, name, expiry: e.expiry, checked: now() };
      const cv = this.st.convos[`d:${owner}`];
      if (cv) cv.title = `@${name}`;
      for (const g of this.st.groups.values()) if (g.state.members.some((m) => hex(m.ownerPub) === owner)) this.groupConvo(g);
    }
  }

  // ---------- upkeep ----------
  private async maintenance() {
    if (!this.vault.data || !this.st.name) return;
    try {
      const t = await indexer('/v1/tip');
      this.st.tipDaa = t.daa;
    } catch {}
    // My names' expiry (Plus status) from the registry, hourly.
    for (const n of this.st.names) {
      if (n.checked && now() - n.checked < 3600_000) continue;
      try {
        const r = await indexer(`/v1/registry/bucket/${registryBucket(n.name)}`);
        const e = r.entries.find((x: any) => x.name === n.name);
        if (e) n.expiry = e.expiry;
        n.checked = now();
      } catch {}
    }
    // Contacts' tiers, hourly.
    for (const c of Object.values(this.st.contacts)) {
      if (now() - c.checked < 3600_000 || !c.name) continue;
      try {
        const r = await indexer(`/v1/registry/bucket/${registryBucket(c.name)}`);
        const e = r.entries.find((x: any) => x.name === c.name && x.owner === c.owner);
        if (e) c.expiry = e.expiry;
        c.checked = now();
      } catch {}
    }
    // Disappearing messages (protocol/src/retention.ts).
    for (const cv of Object.values(this.st.convos)) cv.msgs = purgeExpired(cv.msgs, this.settingsOf(cv).timerSeconds, now());
    // Receive-only sessions after a crossing or re-contact: dropped after 7 days.
    for (const [o, list] of Object.entries(this.st.readonly)) {
      this.st.readonly[o] = list.filter((r) => (r.until ?? 0) > now());
      if (!this.st.readonly[o].length) delete this.st.readonly[o];
    }
    this.st.pendingGroup = this.st.pendingGroup.filter((x) => now() - x.at < READONLY_MS);
    // Signed prekey: rotate weekly, keep the old one a week for late first contacts.
    if (now() - this.st.spkAt > SPK_ROTATE_MS) {
      this.st.oldSpks.push({ id: this.st.spkId, until: now() + SPK_ROTATE_MS });
      this.st.spkId++;
      this.st.spkAt = now();
      await this.publishBundle();
    }
    for (const o of this.st.oldSpks.filter((x) => x.until < now())) forgetPrekey(this.st.seenFC, o.id);
    this.st.oldSpks = this.st.oldSpks.filter((x) => x.until >= now());
    if (!this.st.bundleSec || now() - this.st.bundleAt > 6 * 86_400_000) await this.publishBundle();
    await this.coverTick();
    await this.ordersTick();
    await this.announceName();
    await this.pushTick();
    await this.ensureTokens(5);
    this.emit();
  }

  // Name in use (WIRE_FORMAT §7.3): each established session hears once whenever the name this account goes by
  // changes, so contacts read the right tier and show the right name. Pending requests and blocked owners aren't told.
  private async announceName() {
    const name = this.st.name;
    if (!name) return;
    const told = (this.st.announced ??= {});
    for (const [o, rec] of Object.entries(this.st.sessions)) {
      if (told[o] === name || !rec.s.cks || this.isBlocked(o) || this.st.convos[`d:${o}`]?.request) continue;
      try {
        await this.sendDm(o, KIND_NAME, encodeNameUse(name));
        told[o] = name;
      } catch {
        return;
      }
    }
    await this.flushOutbox();
  }

  // Cover traffic (on by default): dummy messages at random times, indistinguishable on-chain, paid by the treasury.
  private async coverTick() {
    const c = this.st.cover;
    if (c.day !== today()) Object.assign(c, { day: today(), sentToday: 0 });
    if (!c.on || now() < c.next || c.sentToday >= c.perDay) return;
    c.next = now() + Math.round(-Math.log(1 - Math.random()) * (86_400_000 / c.perDay));
    try {
      const ch = await relay('/v1/pow/cover');
      const nonce = await solvePow(ch.challenge, ch.bits);
      const p = Math.random() < 0.5 ? coverPayload() : coverFirstContact(Math.floor(Math.random() * 4096));
      await relay('/v1/cover', { payload: hex(p), pow: { challenge: ch.challenge, nonce } });
      c.sentToday++;
    } catch {}
  }

  // ---------- Plus, top-ups (testnet stand-in for the payment covenant) ----------
  async checkName(name: string) {
    return relay(`/v1/names/check/${encodeURIComponent(name)}`);
  }
  async orderPlus(name: string, months: number) {
    const r = await this.withClaim((claim) => relay('/v1/plus/order', { name, owner: this.ownerHex, months, claim }));
    return this.run(async () => {
      this.st.orders.unshift({ id: r.order, claim: r.claim, kind: r.kind === 'claim' ? 'claim' : 'plus', name, months, amount: r.amount, address: r.address, status: 'pending', created: now() });
      this.emit();
      return r.order as string;
    });
  }
  async renewPlus(name: string, months: number) {
    const r = await this.withClaim((claim) => relay('/v1/plus/renew', { name, months, claim }));
    return this.run(async () => {
      this.st.orders.unshift({ id: r.order, claim: r.claim, kind: 'renew', name, months, amount: r.amount, address: r.address, status: 'pending', created: now() });
      this.emit();
      return r.order as string;
    });
  }
  async orderTopup(kas: number) {
    const r = await this.withClaim((claim) => relay('/v1/topup/order', { kas, claim }));
    return this.run(async () => {
      this.st.orders.unshift({ id: r.order, claim: r.claim, kind: 'topup', amount: r.amount, address: r.address, status: 'pending', created: now() });
      this.emit();
      return r.order as string;
    });
  }
  // Tester feedback (testnet): mailed to the team by the relay, which keeps no copy.
  sendFeedback(kind: 'bug' | 'idea' | 'other', text: string, contact: string, platform: string, heard = '') {
    return relay('/v1/feedback', { kind, text, contact, version: typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : 'dev', platform, heard });
  }
  testPay(orderId: string) {
    return relay(`/v1/order/testpay/${orderId}`, {});
  }
  get testnet() {
    return !!this.config?.network?.startsWith('testnet');
  }
  // Testnet only, one tap: the smallest top-up, paid by the Kaspaguy test faucet, so testers never need test coins.
  // Resolves once the credits are in (about a minute); the order also stays in the list like any other.
  async freeTestCredits() {
    if (!this.testnet) throw new Error('Free test credits are only on the testnet.');
    const id = await this.orderTopup(FREE_TEST_KAS);
    await this.testPay(id);
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 3000));
      await this.pollOrdersNow();
      const o = this.st.orders.find((x) => x.id === id);
      if (o?.status === 'done') return this.refreshCredits();
      if (o && o.status !== 'pending' && o.status !== 'paid') throw new Error(o.error ?? 'The test payment did not go through. Try again in a minute.');
    }
    throw new Error('The test coins are still on their way. Your credits will appear by themselves.');
  }
  private async ordersTick() {
    // Open orders every round; settled ones for 31 days, every 10 minutes, for payments that arrive later (SC-0024).
    const recent = (o: Order) => now() - o.created < 31 * 86_400_000 && now() - (o.extraChecked ?? 0) > 600_000;
    for (const o of this.st.orders.filter((x) => x.status === 'pending' || x.status === 'paid' || recent(x))) {
      try {
        const r = await relay(`/v1/order/${o.id}`);
        const was = o.status;
        o.status = r.status;
        o.error = r.error;
        if (r.extraSompi !== o.extraSompi || o.status !== 'pending') {
          o.extraSompi = r.extraSompi;
          if (r.extraSompi > 0) await this.adoptExtras(o);
          else o.extraChecked = now();
        }
        if (r.status === 'done' && was !== 'done') {
          setTimeout(() => void this.refreshCredits(), 0);
          this.outboxWait = 0; // new credits: what waits in the outbox can go now
          this.st.accounts.push({ secret: o.claim, kind: o.kind === 'topup' ? 'topup' : 'plus' });
          if ((o.kind === 'plus' || o.kind === 'claim') && o.name) {
            if (!this.st.names.some((x) => x.name === o.name)) this.st.names.push({ name: o.name, expiry: 0 });
            this.st.name = o.name;
          }
          const n = this.st.names.find((x) => x.name === o.name);
          if (n) {
            const r = await indexer(`/v1/registry/bucket/${registryBucket(n.name)}`);
            const e = r.entries.find((x: any) => x.name === n.name);
            if (e) n.expiry = e.expiry;
            n.checked = now();
          }
        }
      } catch {}
    }
  }
  pollOrdersNow() {
    return this.run(() => this.ordersTick().then(() => this.emit()));
  }
  setNotify(on: boolean, names: boolean) {
    this.st.notify = { on, names };
    this.emit();
  }
  setCover(on: boolean, perDay: number) {
    this.st.cover.on = on;
    this.st.cover.perDay = Math.max(1, Math.min(24, perDay));
    this.emit();
  }
  useName(name: string) {
    if (this.st.names.some((n) => n.name === name)) {
      this.st.name = name;
      this.emit();
    }
  }
}

export const engine = new Engine();
