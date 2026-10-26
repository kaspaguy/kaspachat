// Where the app runs: the web, a Capacitor phone app (Android/iOS) or a Tauri desktop app (Windows/macOS/Linux).
// Native builds talk to the server by full URL through the platform's own HTTP stack (no browser CORS), and are the
// only builds that can enforce screenshot protection (PROTOCOL_SPEC §8.2).
import { Capacitor, registerPlugin } from '@capacitor/core';

type Kind = 'web' | 'android' | 'ios' | 'desktop';
const tauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
export const kind: Kind = tauri ? 'desktop' : Capacitor.isNativePlatform() ? (Capacitor.getPlatform() as 'android' | 'ios') : 'web';
export const native = kind !== 'web';

// App Store / Play builds sell nothing inside the app (Apple 3.1.1, Play billing): Plus and top-ups are bought on
// kaspachat.com, the desktop app or the direct-download Android app, and used everywhere with the same phrase.
export const storeBuild = import.meta.env.VITE_STORE === '1';

const origin: string = native ? (import.meta.env.VITE_API_ORIGIN ?? '') : '';
// Private testnet builds only: the testnet sits behind basic auth. Injected at build time from a file outside the repo.
const auth: string | undefined = native && import.meta.env.VITE_API_AUTH ? `Basic ${import.meta.env.VITE_API_AUTH}` : undefined;

export const apiBase = (path: string) => origin + path;

// ---------- Tor (PROTOCOL_SPEC §6.3) ----------
// The desktop and phone apps reach Kaspaguy's services at their .onion address through the Tor built into the app
// (tor/, Arti), so the relay and indexer never see the user's IP address. On by default. If Tor can't connect, requests
// fail and the app says so: connecting directly is the user's choice (Account → Connection), never automatic.
// A web page can't choose its route, so the web app connects directly.
const onion: string = native ? (import.meta.env.VITE_API_ONION ?? '') : '';
export const canTor = !!onion && kind !== 'web';
export type TorStatus = { state: 'off' | 'connecting' | 'ready' | 'failed'; error?: string };
let tor: TorStatus = { state: 'off' };
let torPort: Promise<number> | null = null;
let torFailedAt = 0;
const torSubs = new Set<() => void>();
const setTor = (t: TorStatus) => { tor = t; torSubs.forEach((f) => f()); };
export const torStatus = () => tor;
export const onTorChange = (f: () => void) => { torSubs.add(f); return () => { torSubs.delete(f); }; };

export function torWanted(): boolean {
  if (!canTor) return false;
  try { return localStorage.getItem('kc.tor') !== 'off'; } catch { return true; }
}
export function setTorWanted(on: boolean) {
  try { localStorage.setItem('kc.tor', on ? 'on' : 'off'); } catch {}
  torFailedAt = 0;
  if (on) void startTor().catch(() => {});
  else if (tor.state !== 'ready') setTor({ state: 'off' }); // a running Tor stays up, unused, until the app restarts
}

function startTor(): Promise<number> {
  if (torPort) return torPort;
  if (Date.now() - torFailedAt < 30_000) return Promise.reject(new Error("Tor isn't connected"));
  setTor({ state: 'connecting' });
  const p: Promise<number> = kind === 'desktop'
    ? import('@tauri-apps/api/core').then(({ invoke }) => invoke<number>('tor_start', { host: onion }))
    : KaspaChatNative.torStart({ host: onion }).then((r) => r.port);
  torPort = p.then(
    (port) => { setTor({ state: 'ready' }); return port; },
    (e) => { torPort = null; torFailedAt = Date.now(); setTor({ state: 'failed', error: String(e?.message ?? e) }); throw new Error("Tor isn't connected"); },
  );
  return torPort;
}

// Capacitor patches window.fetch to native HTTP (CapacitorHttp in capacitor.config); Tauri needs its HTTP plugin.
// Through Tor: Tauri's HTTP plugin takes the SOCKS port as a proxy; on Android and iPhone the app's own plugin makes the request.
export async function httpFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (auth) headers.set('authorization', auth);
  if (torWanted()) {
    const port = await startTor();
    const u = origin && url.startsWith(origin) ? `http://${onion}${url.slice(origin.length)}` : url;
    if (kind === 'desktop') {
      const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
      return tauriFetch(u, { ...init, headers, proxy: { all: `socks5h://127.0.0.1:${port}` } });
    }
    const r = await KaspaChatNative.torFetch({ port, url: u, method: init.method ?? 'GET', headers: Object.fromEntries(headers), body: typeof init.body === 'string' ? init.body : undefined });
    return new Response([101, 204, 205, 304].includes(r.status) ? null : r.body, { status: r.status, headers: r.headers });
  }
  if (kind === 'desktop') {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(url, { ...init, headers });
  }
  return fetch(url, { ...init, headers });
}

// Linux has no capture-exclusion API; Windows and macOS do (Tauri setContentProtected).
const desktopCanProtect = kind === 'desktop' && /Windows|Macintosh|Mac OS/.test(navigator.userAgent);
export const canProtectScreen = kind === 'android' || kind === 'ios' || desktopCanProtect;

export async function setScreenProtection(on: boolean): Promise<void> {
  if (kind === 'desktop') {
    if (!desktopCanProtect) return;
    const { getCurrentWindow } = await import('@tauri-apps/api/window');
    await getCurrentWindow().setContentProtected(on);
  } else if (kind === 'android' || kind === 'ios') {
    const { PrivacyScreen } = await import('@capacitor-community/privacy-screen');
    await (on ? PrivacyScreen.enable() : PrivacyScreen.disable());
  }
}

export type ScreenEvent = 'screenshot' | 'possible' | 'recording';

// What each platform can tell us about captures of the chat (PROTOCOL_SPEC §8.2):
//  - iPhone: screenshots (after the fact) and the start of screen recording or mirroring;
//  - Android 14 and later: screenshots taken with the device's buttons (our native plugin, registerScreenCaptureCallback);
//  - desktop and web: only that a screenshot key was pressed, so "possible".
export async function onScreenEvent(cb: (e: ScreenEvent) => void): Promise<() => void> {
  const offs: (() => void)[] = [];
  if (kind === 'ios') {
    const { PrivacyScreen } = await import('@capacitor-community/privacy-screen');
    const a = await PrivacyScreen.addListener('screenshotTaken', () => cb('screenshot'));
    const b = await PrivacyScreen.addListener('screenRecordingStarted', () => cb('recording'));
    offs.push(() => void a.remove(), () => void b.remove());
  } else if (kind === 'android') {
    const h = await KaspaChatNative.addListener('screenshot', () => cb('screenshot'));
    offs.push(() => void h.remove());
  } else {
    const key = (e: KeyboardEvent) => {
      const mac = (e.metaKey && e.shiftKey && ['3', '4', '5', '6'].includes(e.key)) || (e.metaKey && e.shiftKey && /^Digit[3-6]$/.test(e.code));
      if (e.key === 'PrintScreen' || e.code === 'PrintScreen' || mac || (e.shiftKey && e.metaKey && e.key.toLowerCase() === 's')) cb('possible');
    };
    window.addEventListener('keyup', key, true);
    window.addEventListener('keydown', key, true);
    offs.push(() => { window.removeEventListener('keyup', key, true); window.removeEventListener('keydown', key, true); });
  }
  return () => offs.forEach((f) => f());
}

// ---------- notifications (no Apple or Google push: they would learn when a device gets a message) ----------
// The app shows its own notifications while it runs. On Android it can keep running in the background (a foreground
// service with a quiet "connected" notification, and an exemption from battery optimisation). iOS suspends apps
// shortly after they leave the screen, so an iPhone checks for messages when the app is opened.
type NativePlugin = {
  addListener(e: 'screenshot', f: () => void): Promise<{ remove: () => Promise<void> }>;
  startKeepAlive(): Promise<void>;
  stopKeepAlive(): Promise<void>;
  batteryStatus(): Promise<{ ignoring: boolean }>;
  requestBatteryExemption(): Promise<void>;
  setWatch(o: { tags: string[]; indexer: string; auth: string }): Promise<void>;
  torStart(o: { host: string }): Promise<{ port: number }>;
  torFetch(o: { port: number; url: string; method: string; headers: Record<string, string>; body?: string }): Promise<{ status: number; headers: Record<string, string>; body: string }>;
};
const KaspaChatNative = registerPlugin<NativePlugin>('KaspaChatNative');

export const canRunInBackground = kind === 'android' || kind === 'desktop';

export async function notifyPermission(ask: boolean): Promise<boolean> {
  if (kind === 'android' || kind === 'ios') {
    const { LocalNotifications } = await import('@capacitor/local-notifications');
    const p = ask ? await LocalNotifications.requestPermissions() : await LocalNotifications.checkPermissions();
    return p.display === 'granted';
  }
  if (kind === 'desktop') {
    const n = await import('@tauri-apps/plugin-notification');
    if (await n.isPermissionGranted()) return true;
    return ask ? (await n.requestPermission()) === 'granted' : false;
  }
  if (typeof Notification === 'undefined') return false;
  if (Notification.permission === 'granted') return true;
  return ask ? (await Notification.requestPermission()) === 'granted' : false;
}

let nid = 1;
export async function notify(title: string, body: string) {
  if (kind === 'android' || kind === 'ios') {
    const { LocalNotifications } = await import('@capacitor/local-notifications');
    await LocalNotifications.schedule({ notifications: [{ id: nid++, title, body, channelId: kind === 'android' ? 'messages' : undefined }] });
  } else if (kind === 'desktop') {
    const n = await import('@tauri-apps/plugin-notification');
    n.sendNotification({ title, body });
  } else if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
    new Notification(title, { body, icon: '/icon.svg' });
  }
}

export async function setupNotifications() {
  if (kind !== 'android') return;
  const { LocalNotifications } = await import('@capacitor/local-notifications');
  await LocalNotifications.createChannel({ id: 'messages', name: 'Messages', importance: 4, visibility: 0 });
}

// Android only. Returns whether the app may now keep running in the background.
export async function keepAlive(on: boolean): Promise<boolean> {
  if (kind !== 'android') return kind === 'desktop';
  if (!on) {
    await KaspaChatNative.stopKeepAlive();
    return false;
  }
  if (!(await KaspaChatNative.batteryStatus()).ignoring) await KaspaChatNative.requestBatteryExemption();
  await KaspaChatNative.startKeepAlive();
  return (await KaspaChatNative.batteryStatus()).ignoring;
}
export async function batteryExempt(): Promise<boolean> {
  return kind === 'android' ? (await KaspaChatNative.batteryStatus()).ignoring : true;
}

// iPhone only, opt-in, off by default (PROTOCOL_SPEC §7). Kaspaguy's push service asks Apple to wake the phone when a
// message lands in a bucket it watches; the phone's notification extension compares the new messages' tags with the
// ones this app expects and shows nothing when none match.
// VITE_PUSH=1 only once Apple has granted the filtering entitlement: without it the extension can't stay silent when
// a wake-up isn't for this phone, and every wake-up would show "New message".
export const canPush = kind === 'ios' && import.meta.env.VITE_PUSH === '1';
const json = (body: object): RequestInit => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

export async function pushStart(): Promise<string | null> {
  if (!canPush) return null;
  const { PushNotifications } = await import('@capacitor/push-notifications');
  if ((await PushNotifications.requestPermissions()).receive !== 'granted') return null;
  const handles: { remove: () => Promise<void> }[] = [];
  const token = new Promise<string | null>((resolve) => {
    void PushNotifications.addListener('registration', (t) => resolve(t.value)).then((h) => handles.push(h));
    void PushNotifications.addListener('registrationError', () => resolve(null)).then((h) => handles.push(h));
  });
  await PushNotifications.register();
  const t = await Promise.race([token, new Promise<null>((r) => setTimeout(() => r(null), 20_000))]);
  for (const h of handles) await h.remove();
  return t && /^[0-9a-f]{64,200}$/i.test(t) ? t.toLowerCase() : null;
}

export async function pushWatch(token: string, buckets: number[], tags: string[]): Promise<boolean> {
  await KaspaChatNative.setWatch({ tags, indexer: apiBase('/api/index'), auth: auth ?? '' });
  const env = import.meta.env.VITE_APNS_ENV === 'sandbox' ? 'sandbox' : 'production';
  return (await httpFetch(apiBase('/api/push/v1/register'), json({ token, env, buckets }))).ok;
}

export async function pushStop(token: string | undefined) {
  if (!canPush) return;
  if (token) await httpFetch(apiBase('/api/push/v1/unregister'), json({ token })).catch(() => {});
  await KaspaChatNative.setWatch({ tags: [], indexer: '', auth: '' }).catch(() => {});
  const { PushNotifications } = await import('@capacitor/push-notifications');
  await PushNotifications.unregister().catch(() => {});
}
