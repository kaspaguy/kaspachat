// Invites (a QR code, or a link to share): https://kaspachat.com/add/#<name>.<key>, where <key> is the first 16 hex digits
// of the name owner's registry key. The part after # never leaves the device (browsers don't send it), so the website
// can't learn who is being added. The key lets the app refuse if the name has since passed to someone else.
// The website's /add page opens the phone app at kaspachat://add/<name>.<key> and the web app at <app>/#add/<name>.<key>;
// the desktop app takes the link pasted into New chat.
import { kind } from './platform';

export const INVITE_PAGE = 'https://kaspachat.com/add/';
export type Invite = { name: string; key: string };

export const inviteLink = (name: string, ownerHex: string) => `${INVITE_PAGE}#${name}.${ownerHex.slice(0, 16)}`;

export function parseInvite(s: string): Invite | null {
  const m = s.trim().match(/^(?:https:\/\/kaspachat\.com\/add\/?#|kaspachat:\/\/add\/|#add\/)@?([a-z0-9-]{1,20})\.([0-9a-f]{16})$/i);
  return m ? { name: m[1].toLowerCase(), key: m[2].toLowerCase() } : null;
}

// The invite the app was opened with, kept until the user is signed in and has dealt with it.
let pending: Invite | null = null;
const subs = new Set<() => void>();
const setPending = (i: Invite | null) => { pending = i; subs.forEach((f) => f()); };
export const pendingInvite = () => pending;
export const clearInvite = () => setPending(null);
// A code scanned in the app opens New chat the same way a link the app was opened with does.
export const openInvite = (i: Invite) => setPending(i);
export const onInvite = (f: () => void) => { subs.add(f); return () => { subs.delete(f); }; };

export async function listenForInvites() {
  if (kind === 'android' || kind === 'ios') {
    const { App } = await import('@capacitor/app');
    await App.addListener('appUrlOpen', (e) => { const i = parseInvite(e.url); if (i) setPending(i); });
    const u = await App.getLaunchUrl();
    const i = u && parseInvite(u.url);
    if (i) setPending(i);
  } else if (kind === 'web') {
    const i = parseInvite(location.hash);
    if (i) {
      setPending(i);
      history.replaceState(null, '', location.pathname + location.search);
    }
  }
}

// The phone's share sheet; elsewhere the browser's, or the clipboard.
export async function shareInvite(link: string, name: string): Promise<'shared' | 'copied'> {
  const text = `Message me privately on KaspaChat: @${name}`;
  if (kind === 'android' || kind === 'ios') {
    const { Share } = await import('@capacitor/share');
    await Share.share({ title: 'KaspaChat', text, url: link });
    return 'shared';
  }
  if (navigator.share) {
    await navigator.share({ title: 'KaspaChat', text, url: link });
    return 'shared';
  }
  await navigator.clipboard.writeText(link);
  return 'copied';
}
