import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { batteryExempt, canProtectScreen, canPush, canRunInBackground, canTor, keepAlive, kind, notify, notifyPermission, onScreenEvent, onTorChange, pushStart, pushStop, pushWatch, setScreenProtection, setTorWanted, setupNotifications, storeBuild, torStatus, torWanted } from '../lib/platform';
import QRCode from 'qrcode';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { engine, isPlus, newMnemonic, type Convo, type Order, type ReportReason } from '../lib/engine.ts';
import { NOTICE_POSSIBLE_SCREENSHOT, NOTICE_RECORDING, NOTICE_SCREENSHOT } from '../../../protocol/src/index.ts';
import { Vault } from '../lib/vault.ts';
import { clearInvite, inviteLink, listenForInvites, onInvite, openInvite, parseInvite, pendingInvite, shareInvite, type Invite } from '../lib/invite.ts';
import { canCamera, scanImage, startCamera } from '../lib/scan.ts';
import { extraIndexers, setExtraIndexers } from '../lib/api';
import { cleanIndexerUrl } from '../lib/failover';

const KAS = 100_000_000;
const PASS_MIN = 8; // letters, numbers or both; it guards the recovery phrase on this device
const kas = (sompi: number) => (sompi / KAS).toLocaleString(undefined, { maximumFractionDigits: 2 });
const time = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function useEngine() {
  return useSyncExternalStore(
    (f) => engine.subscribe(f),
    () => engine.vault.data,
  );
}
// Re-render on every engine change (the vault object is mutated in place).
function useTick() {
  const [, set] = useState(0);
  useEffect(() => engine.subscribe(() => set((n) => n + 1)), []);
}

export function App() {
  const [phase, setPhase] = useState<'loading' | 'welcome' | 'locked' | 'ready'>('loading');
  useEffect(() => {
    Vault.exists().then((e) => setPhase(e ? 'locked' : 'welcome'));
    void listenForInvites().catch(() => {});
  }, []);
  if (phase === 'loading') return <div className="center muted">Loading…</div>;
  if (phase === 'welcome') return <Onboarding onDone={() => setPhase('ready')} />;
  if (phase === 'locked') return <Unlock onDone={() => setPhase('ready')} onReset={() => setPhase('welcome')} />;
  return <Main onLock={() => { engine.stop(); engine.vault.lock(); setPhase('locked'); }} onErase={async () => { engine.stop(); await keepAlive(false).catch(() => {}); await Vault.wipe(); location.reload(); }} />;
}

function Brand() {
  return (
    <div className="brand">
      <img src="/icon.svg" alt="" width={28} height={28} />
      <span>KaspaChat</span>
      <span className="pill">testnet</span>
    </div>
  );
}

const SITE = 'https://kaspachat.com';
function Legal() {
  return (
    <p className="muted small">By continuing you agree to the <a href={`${SITE}/terms`} target="_blank" rel="noopener noreferrer">Terms of use</a> (no tolerance for abuse) and the <a href={`${SITE}/privacy`} target="_blank" rel="noopener noreferrer">Privacy policy</a>.</p>
  );
}

function TestnetNote() {
  return <p className="note">Testnet preview. Names and credits use test coins with no value. Messages are end-to-end encrypted on your device.</p>;
}

// ---------- onboarding ----------
function Onboarding({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<'start' | 'phrase' | 'confirm' | 'restore' | 'pass' | 'name' | 'notify'>('start');
  const [mnemonic, setMnemonic] = useState('');
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState('');
  const words = mnemonic.split(' ');
  // Three random words of the new phrase to type back, in order.
  const checks = useMemo(() => [...crypto.getRandomValues(new Uint32Array(24))].map((r, i) => [r, i]).sort((a, b) => a[0] - b[0]).slice(0, 3).map(([, i]) => i).sort((a, b) => a - b), [mnemonic]);
  const [answers, setAnswers] = useState<string[]>(['', '', '']);

  async function finish() {
    setErr('');
    if (pass.length < PASS_MIN) return setErr(`Use at least ${PASS_MIN} characters (letters, numbers or both).`);
    if (pass !== pass2) return setErr('The two passcodes differ.');
    setBusy('Locking your keys on this device…');
    await engine.create(mnemonic, pass);
    setStep('name');
    try {
      // On a restore, and on a retry after a sign-up that got as far as the chain, this key already holds names.
      setBusy('Looking for your names in the registry…');
      const found = await engine.findMyNames();
      if (found.length) {
        await engine.adoptNames(found);
        engine.start();
        return setStep('notify');
      }
      await engine.loadConfig();
      await engine.registerFree(0, setBusy);
      engine.start();
      setStep('notify');
    } catch (e) {
      setBusy('');
      setErr((e as Error).message);
    }
  }

  return (
    <div className="onboard">
      <Brand />
      {step === 'start' && (
        <>
          <h1>Private messages with nothing to seize.</h1>
          <p className="lead">No phone number, no email, no account to hand over. Your keys live on your device; the operator can't read your messages or see who talks to whom.</p>
          <button className="primary" onClick={() => { setMnemonic(newMnemonic()); setStep('phrase'); }}>Create a new account</button>
          <button onClick={() => setStep('restore')}>I have a recovery phrase</button>
          <Legal />
          <TestnetNote />
        </>
      )}
      {step === 'phrase' && (
        <>
          <h2>Your recovery phrase</h2>
          <p>These 24 words are your account. Write them down and keep them offline. Anyone with them can read your messages, and without them nobody can recover your account, not even us.</p>
          <ol className="words">{words.map((w, i) => <li key={i}>{w}</li>)}</ol>
          <button className="primary" onClick={() => setStep('confirm')}>I wrote them down</button>
        </>
      )}
      {step === 'confirm' && (
        <>
          <h2>Check your copy</h2>
          {checks.map((i, k) => (
            <label key={i}>Word {i + 1}
              <input value={answers[k]} autoCapitalize="none" onChange={(e) => setAnswers(answers.map((a, j) => (j === k ? e.target.value.trim().toLowerCase() : a)))} />
            </label>
          ))}
          {err && <p className="error">{err}</p>}
          <button className="primary" onClick={() => (checks.every((i, k) => words[i] === answers[k]) ? (setErr(''), setStep('pass')) : setErr("Those words don't match. Check your copy."))}>Continue</button>
          <button className="link" onClick={() => setStep('phrase')}>Show the words again</button>
        </>
      )}
      {step === 'restore' && (
        <>
          <h2>Restore your account</h2>
          <textarea rows={5} placeholder="24 words, separated by spaces" value={mnemonic} onChange={(e) => setMnemonic(e.target.value.toLowerCase())} />
          {err && <p className="error">{err}</p>}
          <button className="primary" onClick={() => { const m = mnemonic.trim().split(/\s+/).join(' '); if (m.split(' ').length !== 24 || !validateMnemonic(m, wordlist)) return setErr('That is not a valid 24-word phrase.'); setMnemonic(m); setErr(''); setStep('pass'); }}>Continue</button>
          <button className="link" onClick={() => setStep('start')}>Back</button>
        </>
      )}
      {step === 'pass' && (
        <>
          <h2>Set a device passcode</h2>
          <p>It locks your keys on this device. If you forget it, restore with your recovery phrase.</p>
          <input type="password" autoComplete="new-password" placeholder={`Passcode (at least ${PASS_MIN} letters or numbers)`} value={pass} onChange={(e) => setPass(e.target.value)} />
          <input type="password" placeholder="Repeat passcode" value={pass2} onChange={(e) => setPass2(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && finish()} />
          {err && <p className="error">{err}</p>}
          <button className="primary" disabled={!!busy} onClick={finish}>Continue</button>
        </>
      )}
      {step === 'name' && (
        <>
          <h2>Getting your name</h2>
          {busy && <p className="progress"><span className="spinner" />{busy}</p>}
          <p className="muted">You get a free code name like @kv7f3q9x. Chosen names come with Pro.</p>
          {err && (
            <>
              <p className="error">{err}</p>
              <button className="primary" onClick={finish}>Try again</button>
            </>
          )}
        </>
      )}
      {step === 'notify' && <NotifyStep onDone={onDone} />}
    </div>
  );
}

// Asked once, right after sign-up: KaspaChat uses no Apple or Google push, so the app has to stay running to notice
// new messages.
function NotifyStep({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  async function allow() {
    setBusy(true);
    const ok = await notifyPermission(true).catch(() => false);
    if (ok && kind === 'android') await keepAlive(true).catch(() => {});
    engine.setNotify(ok, false);
    onDone();
  }
  return (
    <>
      <h2>Hear about new messages</h2>
      <p>{kind === 'ios' ? 'KaspaChat tells you itself while it runs. Push through Apple is your choice, in Account.' : "KaspaChat doesn't use Apple's or Google's push servers, because they would learn when your phone gets a message. So the app tells you itself, while it runs."}</p>
      {kind === 'android' && <p>Allow notifications, then allow KaspaChat to run in the background (Android asks about battery use). A small "KaspaChat is connected" notice stays in your notification bar so Android doesn't stop the app.</p>}
      {kind === 'ios' && <p>iPhones pause apps soon after you leave them. To hear about messages while KaspaChat is closed, turn on "Wake for new messages" in Account. It's off unless you turn it on.</p>}
      {kind === 'desktop' && <p>Keep the app open or minimised and it will tell you about new messages.</p>}
      {kind === 'web' && <p>Notifications appear while this tab is open.</p>}
      <p className="muted small">Notifications say "New message" and nothing else, unless you choose to show the sender's name in Account.</p>
      <button className="primary" disabled={busy} onClick={allow}>Allow notifications</button>
      <button className="link" onClick={() => { engine.setNotify(false, false); onDone(); }}>Not now</button>
    </>
  );
}

function Unlock({ onDone, onReset }: { onDone: () => void; onReset: () => void }) {
  const [pass, setPass] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [upgrade, setUpgrade] = useState(false);
  const [pass1, setPass1] = useState('');
  const [pass2, setPass2] = useState('');
  async function go() {
    setBusy(true);
    const ok = await engine.unlock(pass);
    setBusy(false);
    if (!ok) return setErr('Wrong passcode.');
    if (!engine.st.name) {
      setErr('This device has no name yet. Restore with your recovery phrase.');
      return;
    }
    if (pass.length < PASS_MIN) return setUpgrade(true);
    engine.start();
    onDone();
  }
  async function strengthen() {
    if (pass1.length < PASS_MIN) return setErr(`Use at least ${PASS_MIN} characters (letters, numbers or both).`);
    if (pass1 !== pass2) return setErr('The two passcodes differ.');
    setBusy(true);
    await engine.vault.rekey(pass1);
    setBusy(false);
    engine.start();
    onDone();
  }
  if (upgrade) return (
    <div className="onboard">
      <Brand />
      <h2>Choose a longer passcode</h2>
      <p>Your passcode protects your recovery phrase on this device, so it now needs at least {PASS_MIN} characters (letters, numbers or both).</p>
      <input type="password" autoFocus autoComplete="new-password" placeholder="New passcode" value={pass1} onChange={(e) => setPass1(e.target.value)} />
      <input type="password" autoComplete="new-password" placeholder="Repeat new passcode" value={pass2} onChange={(e) => setPass2(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && strengthen()} />
      {err && <p className="error">{err}</p>}
      <button className="primary" disabled={busy} onClick={strengthen}>Save passcode</button>
    </div>
  );
  return (
    <div className="onboard">
      <Brand />
      <h2>Unlock</h2>
      <input type="password" autoFocus placeholder="Device passcode" value={pass} onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} />
      {err && <p className="error">{err}</p>}
      <button className="primary" disabled={busy} onClick={go}>{busy ? 'Unlocking…' : 'Unlock'}</button>
      <button className="link" onClick={async () => { if (confirm('Erase this device’s copy and restore from your recovery phrase?')) { await Vault.wipe(); onReset(); } }}>Forgot the passcode?</button>
    </div>
  );
}

// ---------- main ----------
function Main({ onLock, onErase }: { onLock: () => void; onErase: () => void }) {
  useTick();
  const st = useEngine()!;
  const [open, setOpen] = useState<string | 'account' | 'new' | 'invite' | 'scan' | 'feedback' | null>(null);
  // An invite the app was opened with (also one that arrived before sign-up or unlock) opens New chat.
  const invite = useSyncExternalStore(onInvite, pendingInvite);
  useEffect(() => { if (invite) setOpen('new'); }, [invite]);
  useEffect(() => { void engine.refreshCredits(); }, [st?.tokens.length]);
  const openRef = useRef(open);
  openRef.current = open;
  useEffect(() => {
    void setupNotifications().catch(() => {});
    if (engine.st.notify?.on && kind === 'android') void keepAlive(true).catch(() => {});
    engine.onIncoming = (m) => {
      const n = engine.st.notify;
      if (!n?.on || (!document.hidden && openRef.current === m.convo)) return;
      const req = engine.st.convos[m.convo]?.request;
      void notify('KaspaChat', req ? 'New message request' : n.names && m.name ? `New message from @${m.name}` : 'New message').catch(() => {});
    };
    engine.onWatch = (t) => (engine.st.push?.token ? pushWatch(engine.st.push.token, t.buckets, t.tags) : Promise.resolve(false));
    return () => { engine.onIncoming = () => {}; engine.onWatch = null; };
  }, []);
  if (!st) return null;
  const convos = Object.values(st.convos).sort((a, b) => b.updated - a.updated);
  const showList = open === null;
  return (
    <div className={`main ${showList ? 'list-open' : 'detail-open'}`}>
      <aside>
        <header>
          <Brand />
          <button className="icon" title="Account" onClick={() => setOpen('account')}>⚙</button>
        </header>
        <div className="me" onClick={() => setOpen('account')}>
          <strong>@{st.name}</strong> {engine.myPlus ? <span className="pill plus">Pro</span> : <span className="pill">Free</span>}
          <div className="muted small">{engine.status.credits} message credits · {engine.status.online ? 'online' : 'offline'}</div>
        </div>
        {engine.testnet && <FreeCredits />}
        <button className="primary block" onClick={() => setOpen('new')}>New chat or group</button>
        <div className="row2">
          <button className="block" onClick={() => setOpen('invite')}>🔗 My invite QR</button>
          <button className="block" onClick={() => setOpen('scan')}>📷 Scan QR</button>
        </div>
        {engine.config?.feedback && <button className="block feedback" onClick={() => setOpen('feedback')}>💬 Send feedback</button>}
        <ul className="convos">
          {convos.length === 0 && <li className="muted small pad">No conversations yet. Start one with someone's @name, or invite someone with your QR code.</li>}
          {convos.map((c) => {
            const last = c.msgs[c.msgs.length - 1];
            return (
              <li key={c.id} className={open === c.id ? 'active' : ''} onClick={() => { setOpen(c.id); engine.markRead(c.id); }}>
                <div className="row"><strong>{c.kind === 'group' ? '👥 ' : ''}{c.title}</strong>{last && <span className="muted small">{time(last.t)}</span>}</div>
                <div className="row"><span className="muted small ellipsis">{c.request ? 'Message request' : last ? (last.from === 'me' ? 'You: ' : '') + last.text : ''}</span>{c.unread > 0 && <span className="badge">{c.unread}</span>}</div>
              </li>
            );
          })}
        </ul>
      </aside>
      <section>
        {open === 'account' && <Account onBack={() => setOpen(null)} onLock={onLock} onErase={onErase} />}
        {open === 'new' && <NewChat key={invite ? `${invite.name}.${invite.key}` : ''} invite={invite} onBack={() => { clearInvite(); setOpen(null); }} onOpen={(id) => { clearInvite(); setOpen(id); }} />}
        {open === 'invite' && <InvitePanel onBack={() => setOpen(null)} />}
        {open === 'scan' && <ScanPanel onBack={() => setOpen(null)} />}
        {open === 'feedback' && <FeedbackPanel onBack={() => setOpen(null)} />}
        {open && st.convos[open] && <Chat cv={st.convos[open]} onBack={() => setOpen(null)} />}
        {!open && <div className="center muted desktop-only">Pick a conversation, or start a new one.</div>}
      </section>
    </div>
  );
}

function NewChat({ invite, onBack, onOpen }: { invite: Invite | null; onBack: () => void; onOpen: (id: string) => void }) {
  const [mode, setMode] = useState<'dm' | 'group'>('dm');
  const [name, setName] = useState(invite ? `@${invite.name}` : '');
  const [members, setMembers] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  async function go() {
    setErr('');
    setBusy(true);
    try {
      // An invite link pasted into the box works like a scanned one.
      const inv = parseInvite(name) ?? (invite && name === `@${invite.name}` ? invite : null);
      if (mode === 'dm') onOpen(await engine.startChat(inv ? inv.name : name, inv?.key));
      else onOpen(await engine.createGroup(members.split(/[\s,]+/).filter(Boolean)));
    } catch (e) {
      setErr((e as Error).message);
    }
    setBusy(false);
  }
  return (
    <div className="panel">
      <header><button className="icon back" onClick={onBack}>←</button><h2>New conversation</h2></header>
      <div className="tabs">
        <button className={mode === 'dm' ? 'on' : ''} onClick={() => setMode('dm')}>Chat</button>
        <button className={mode === 'group' ? 'on' : ''} onClick={() => setMode('group')}>Group (up to 4)</button>
      </div>
      {invite && mode === 'dm' && <p>You were invited to chat with <strong>@{invite.name}</strong>. Start the chat to send them a message request.</p>}
      {mode === 'dm' ? (
        <input autoFocus placeholder="@name or invite link" autoCapitalize="none" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} />
      ) : (
        <input autoFocus placeholder="@name1, @name2, @name3" autoCapitalize="none" value={members} onChange={(e) => setMembers(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} />
      )}
      <p className="muted small">Names are looked up in the on-chain registry. The lookup fetches a whole bucket of names, so the server never learns which one you asked for.</p>
      {err && <p className="error">{err}</p>}
      <button className="primary" disabled={busy} onClick={go}>{busy ? 'Looking up…' : mode === 'dm' ? 'Start chat' : 'Create group'}</button>
    </div>
  );
}

// Your invite as a QR code and a link (lib/invite.ts). Scanned with a phone camera it opens KaspaChat's page, which has
// the downloads and opens the app straight into a new chat with you.
function InvitePanel({ onBack }: { onBack: () => void }) {
  const name = useEngine()!.name ?? '';
  const link = name ? inviteLink(name, engine.ownerHex) : '';
  const [qr, setQr] = useState('');
  const [msg, setMsg] = useState('');
  useEffect(() => { if (link) QRCode.toDataURL(link, { margin: 1, width: 240 }).then(setQr); }, [link]);
  async function share() {
    try {
      setMsg((await shareInvite(link, name)) === 'copied' ? 'Link copied.' : '');
    } catch {
      setMsg(''); // the share sheet was closed
    }
  }
  return (
    <div className="panel">
      <header><button className="icon back" onClick={onBack}>←</button><h2>Invite someone</h2></header>
      <p>Let someone scan this with their phone camera. It opens KaspaChat's page, where they get the app and can then start a chat with you without typing your name.</p>
      {!name && <p className="error">You don't have a name yet, so there is nothing to invite to.</p>}
      {qr && <img className="invite-qr" src={qr} alt={`Invite QR code for @${name}`} width={240} height={240} />}
      {name && <p className="invite-name"><strong>@{name}</strong></p>}
      <button className="primary" disabled={!name} onClick={share}>Share invite link</button>
      {msg && <p className="muted small">{msg}</p>}
      <p className="muted small">The code holds your name and the start of your public key, nothing else, so the app can check it reaches you even if your name changes hands one day. Anyone who has it can send you a message request; you decide whether to accept.</p>
    </div>
  );
}

// Scans a friend's invite QR code (lib/scan.ts) and opens New chat with them; a picked image works where there is no camera.
function ScanPanel({ onBack }: { onBack: () => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const [err, setErr] = useState('');
  const [cam, setCam] = useState(canCamera);
  const found = (text: string) => {
    const i = parseInvite(text);
    if (!i) return false;
    openInvite(i);
    return true;
  };
  useEffect(() => {
    if (!cam || !video.current) return;
    let stop = () => {};
    let gone = false;
    let wrong = false;
    startCamera(video.current, (text) => {
      if (found(text)) return;
      if (!wrong) { wrong = true; setErr('That QR code is not a KaspaChat invite.'); }
    }).then((f) => { if (gone) f(); else stop = f; }).catch(() => { setCam(false); setErr('The camera is not available. Allow camera access in your settings, or pick a picture of the code below.'); });
    return () => { gone = true; stop(); };
  }, [cam]);
  async function pick(f: File | undefined) {
    if (!f) return;
    setErr('');
    try {
      const text = await scanImage(f);
      if (!text) setErr('No QR code found in that picture.');
      else if (!found(text)) setErr('That QR code is not a KaspaChat invite.');
    } catch {
      setErr('That file could not be read as a picture.');
    }
  }
  return (
    <div className="panel">
      <header><button className="icon back" onClick={onBack}>←</button><h2>Scan a QR code</h2></header>
      <p>Point the camera at a friend's KaspaChat invite code. The chat with them opens as soon as it's read.</p>
      {cam && <video ref={video} className="scan-video" playsInline muted />}
      {err && <p className="error">{err}</p>}
      <label className="button-like">Pick a picture of a QR code<input type="file" accept="image/*" hidden onChange={(e) => { void pick(e.target.files?.[0]); e.target.value = ''; }} /></label>
      <p className="muted small">The code is read on this device. The picture and the camera image never leave it.</p>
    </div>
  );
}

// Testnet feedback: mailed to the KaspaChat team by the relay, which keeps no copy (relay/src/feedback.ts).
function FeedbackPanel({ onBack }: { onBack: () => void }) {
  const [what, setWhat] = useState<'bug' | 'idea' | 'other'>('bug');
  const [text, setText] = useState('');
  const [contact, setContact] = useState('');
  const [heard, setHeard] = useState('');
  const [state, setState] = useState<'edit' | 'sending' | 'sent'>('edit');
  const [err, setErr] = useState('');
  async function send() {
    setErr('');
    setState('sending');
    try {
      await engine.sendFeedback(what, text, contact, kind, heard);
      setState('sent');
    } catch (e) {
      setErr((e as Error).message);
      setState('edit');
    }
  }
  if (state === 'sent') {
    return (
      <div className="panel">
        <header><button className="icon back" onClick={onBack}>←</button><h2>Send feedback</h2></header>
        <p>Thank you! Your feedback is on its way to the KaspaChat team. This is exactly what the testnet is for.</p>
        <button onClick={() => { setText(''); setState('edit'); }}>Send more</button>
        <button className="primary" onClick={onBack}>Done</button>
      </div>
    );
  }
  return (
    <div className="panel">
      <header><button className="icon back" onClick={onBack}>←</button><h2>Send feedback</h2></header>
      <p>Found a bug, got stuck, or have an idea? Tell us. Every message is read.</p>
      <div className="tabs">
        <button className={what === 'bug' ? 'on' : ''} onClick={() => setWhat('bug')}>🐞 Something broke</button>
        <button className={what === 'idea' ? 'on' : ''} onClick={() => setWhat('idea')}>💡 Idea</button>
        <button className={what === 'other' ? 'on' : ''} onClick={() => setWhat('other')}>Other</button>
      </div>
      <textarea rows={6} maxLength={4000} autoFocus placeholder={what === 'bug' ? 'What happened, and what did you expect?' : 'Tell us…'} value={text} onChange={(e) => setText(e.target.value)} />
      <input placeholder="Email or @name if you'd like a reply (optional)" autoCapitalize="none" maxLength={200} value={contact} onChange={(e) => setContact(e.target.value)} />
      <select value={heard} onChange={(e) => setHeard(e.target.value)} aria-label="Where did you hear about KaspaChat?">
        <option value="">Where did you hear about KaspaChat? (optional)</option>
        <option value="x">X (Twitter)</option>
        <option value="telegram">Telegram</option>
        <option value="reddit">Reddit</option>
        <option value="discord">Discord</option>
        <option value="friend">A friend</option>
        <option value="kaspaguy.com">kaspaguy.com</option>
        <option value="other">Somewhere else</option>
      </select>
      <p className="muted small">Sent by email to the KaspaChat team with the app version and platform ({kind}). Nothing else is attached: not your name, messages or IP address. Never paste your recovery phrase.</p>
      {err && <p className="error">{err}</p>}
      <button className="primary" disabled={state === 'sending' || text.trim().length < 3} onClick={send}>{state === 'sending' ? 'Sending…' : 'Send feedback'}</button>
    </div>
  );
}

function Chat({ cv, onBack }: { cv: Convo; onBack: () => void }) {
  useTick();
  const st = engine.st;
  const [text, setText] = useState('');
  const [manage, setManage] = useState(false);
  const [emojis, setEmojis] = useState(false);
  const box = useRef<HTMLTextAreaElement>(null);
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }); engine.markRead(cv.id); }, [cv.msgs.length, cv.id]);
  const set = engine.settingsOf(cv);
  const g = cv.kind === 'group' ? st.groups.get(cv.groupId!) : null;
  const admin = g && Array.from(g.state.admin, (x) => x.toString(16).padStart(2, '0')).join('') === engine.ownerHex;
  const nameOf = (o: string) => (o === 'me' ? 'You' : '@' + (st.contacts[o]?.name ?? '?'));
  const bytes = new TextEncoder().encode(text).length;
  const [report, setReport] = useState(false);
  useEffect(() => {
    if (!set.screenshotProtection || !canProtectScreen) return;
    void setScreenProtection(true);
    let off = () => {};
    let gone = false;
    void onScreenEvent((e) => void engine.screenEvent(cv.id, e === 'screenshot' ? NOTICE_SCREENSHOT : e === 'recording' ? NOTICE_RECORDING : NOTICE_POSSIBLE_SCREENSHOT)).then((f) => { if (gone) f(); else off = f; });
    return () => { gone = true; off(); void setScreenProtection(false); };
  }, [set.screenshotProtection, cv.id]);
  const others = engine.membersOf(cv).filter((o) => o !== engine.ownerHex);
  const blockedPeer = cv.kind === 'dm' && engine.isBlocked(cv.peer!);
  if (set.screenshotProtection && !canProtectScreen) {
    return (
      <div className="panel"><header><button className="icon back" onClick={onBack}>←</button><h2>{cv.title}</h2></header>
        <p className="muted">This conversation has screenshot protection on. Open it in the KaspaChat app for Android, iPhone, Windows or Mac.</p></div>
    );
  }
  function send() {
    if (!text.trim()) return;
    void engine.sendText(cv.id, text);
    setText('');
    setEmojis(false);
  }
  // Puts the emoji where the cursor is and keeps the cursor after it, so several can be tapped in a row.
  function addEmoji(e: string) {
    const el = box.current;
    const at = el ? el.selectionStart : text.length;
    const to = el ? el.selectionEnd : text.length;
    setText(text.slice(0, at) + e + text.slice(to));
    requestAnimationFrame(() => { el?.setSelectionRange(at + e.length, at + e.length); });
  }
  return (
    <div className="chat">
      <header>
        <button className="icon back" onClick={onBack}>←</button>
        <div className="grow">
          <h2>{cv.title}</h2>
          <div className="muted small">{set.timerSeconds ? 'Messages disappear 30 hours after they arrive, on every device in this chat.' : 'Disappearing timer off (everyone here is Pro and chose it).'}</div>
        </div>
        {set.allPlus && <button className="small" onClick={() => engine.setTimerOff(cv.id, !cv.myPrefs?.timerOff)}>{cv.myPrefs?.timerOff ? 'Turn timer on' : 'Turn timer off'}</button>}
        {(engine.myPlus || cv.myPrefs?.screenshotProtection) && canProtectScreen && <button className="small" onClick={() => engine.setScreenshotProtection(cv.id, !cv.myPrefs?.screenshotProtection)}>{cv.myPrefs?.screenshotProtection ? 'Screenshot protection off' : 'Screenshot protection on'}</button>}
        {admin && <button className="small" onClick={() => setManage(!manage)}>Members</button>}
        <button className="small" onClick={() => setReport(!report)}>Report or block</button>
      </header>
      {report && <ReportPanel cv={cv} people={others} onClose={() => setReport(false)} onBlocked={() => { if (cv.kind === 'dm') onBack(); }} />}
      {blockedPeer && (
        <div className="request">You blocked this person. Their new messages are not shown. <button className="small" onClick={() => engine.unblock(cv.peer!)}>Unblock</button></div>
      )}
      {set.screenshotProtection && <div className="muted small sys">Screenshot protection is on in this chat.</div>}
      {manage && g && <Members cvId={cv.id} names={g.state.members.map((m) => m.name)} />}
      {cv.request && (
        <div className="request">
          This person isn't in your chats yet. <button className="small" onClick={() => engine.accept(cv.id)}>Accept</button>
          <button className="small" onClick={() => { void engine.block(cv.peer!); onBack(); }}>Block</button>
          <button className="small" onClick={() => setReport(true)}>Report</button>
          <button className="small" onClick={() => { engine.deleteConvo(cv.id); onBack(); }}>Delete</button>
        </div>
      )}
      <div className="msgs">
        {cv.msgs.filter((m) => m.from === 'me' || !engine.isBlocked(m.from)).map((m) => (
          m.note ? <div key={m.id} className="sys">{m.text}</div> :
          <div key={m.id + m.t} className={`msg ${m.from === 'me' ? 'mine' : ''}`}>
            {cv.kind === 'group' && m.from !== 'me' && <div className="who">{nameOf(m.from)}</div>}
            <div className="text">{m.text}</div>
            <div className="meta">{time(m.t)}{m.from === 'me' && (m.state === 'sending' ? ' · sending' : m.state === 'failed' ? ' · not sent' : ' · ✓')}</div>
          </div>
        ))}
        <div ref={end} />
      </div>
      {engine.status.lastError && <div className="error small pad">{engine.status.lastError}</div>}
      {emojis && (
        <div className="emojis" role="listbox" aria-label="Emojis">
          {EMOJIS.map((e) => <button key={e} className="emoji" onClick={() => addEmoji(e)} aria-label={e}>{e}</button>)}
        </div>
      )}
      <footer>
        <button className="icon" onClick={() => setEmojis(!emojis)} aria-label={emojis ? 'Close emojis' : 'Emojis'} aria-expanded={emojis}>{emojis ? '⌨️' : '🙂'}</button>
        <textarea ref={box} rows={1} placeholder="Message" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }} />
        <button className="primary" onClick={send} disabled={!text.trim()}>Send</button>
      </footer>
      {bytes > 1300 && <div className="muted small pad">{bytes} bytes: long messages are sent in parts, one credit each.</div>}
    </div>
  );
}

// The everyday set, as plain Unicode: they travel as text, so every KaspaChat device shows them.
const EMOJIS = [
  '😀', '😂', '🤣', '😊', '😍', '😘', '😎', '🤔', '😅', '😉', '🙂', '🙃',
  '😢', '😭', '😡', '😱', '😴', '🤗', '🙄', '😬', '🥳', '🤩', '😇', '🤯',
  '👍', '👎', '👏', '🙏', '👋', '💪', '👌', '✌️', '🤝', '🫶', '👀', '🤞',
  '❤️', '💔', '🔥', '⭐', '✨', '🎉', '💯', '✅', '❌', '⚡', '💰', '🚀',
];

const REASONS: [ReportReason, string][] = [['spam', 'Spam or scam'], ['harassment', 'Harassment or threats'], ['illegal', 'Illegal content'], ['impersonation', 'Pretending to be someone'], ['other', 'Something else']];

function ReportPanel({ cv, people, onClose, onBlocked }: { cv: Convo; people: string[]; onClose: () => void; onBlocked: () => void }) {
  const st = engine.st;
  const [who, setWho] = useState(people[0] ?? '');
  const [reason, setReason] = useState<ReportReason>('spam');
  const [note, setNote] = useState('');
  const [include, setInclude] = useState(true);
  const [also, setAlso] = useState(true);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const theirs = cv.msgs.filter((m) => m.from === who && !m.note).length;
  async function send() {
    setBusy(true);
    try {
      await engine.report(cv.id, who, reason, note, include);
      setMsg(also ? 'Reported and blocked. Thank you.' : 'Reported. Thank you.');
      if (also) setTimeout(() => void engine.block(who).then(onBlocked), 1500);
    } catch (e) {
      setMsg(`Could not send the report: ${(e as Error).message}`);
    }
    setBusy(false);
  }
  return (
    <div className="card report">
      {people.length > 1 && (
        <label>Who<select value={who} onChange={(e) => setWho(e.target.value)}>{people.map((o) => <option key={o} value={o}>@{st.contacts[o]?.name ?? '?'}</option>)}</select></label>
      )}
      <label>What's wrong<select value={reason} onChange={(e) => setReason(e.target.value as ReportReason)}>{REASONS.map(([k, t]) => <option key={k} value={k}>{t}</option>)}</select></label>
      <textarea rows={2} placeholder="Anything else we should know (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
      <label className="row"><span>Include their last messages in this chat ({Math.min(theirs, 20)}) and your replies</span><input type="checkbox" checked={include} onChange={(e) => setInclude(e.target.checked)} /></label>
      <label className="row"><span>Also block @{st.contacts[who]?.name ?? '?'}</span><input type="checkbox" checked={also} onChange={(e) => setAlso(e.target.checked)} /></label>
      <p className="muted small">Messages are end-to-end encrypted, so we only see what you send us here. Your name is not included. Blocking only affects this device and the other person isn't told.</p>
      {msg && <p className="small">{msg}</p>}
      <div className="row wrap">
        <button className="primary" disabled={busy || !who} onClick={send}>Send report</button>
        <button disabled={busy || !who} onClick={async () => { await engine.block(who); onBlocked(); onClose(); }}>Block without reporting</button>
        <button className="link" onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
}

function Members({ cvId, names }: { cvId: string; names: string[] }) {
  const [add, setAdd] = useState('');
  const [err, setErr] = useState('');
  return (
    <div className="members">
      {names.filter((n) => n !== engine.st.name).map((n) => (
        <span key={n} className="chip">@{n} <button className="link" onClick={() => engine.changeMembers(cvId, [], [n]).catch((e) => setErr(e.message))}>remove</button></span>
      ))}
      {names.length < 4 && (
        <span><input placeholder="add @name" value={add} onChange={(e) => setAdd(e.target.value)} />
          <button className="small" onClick={() => engine.changeMembers(cvId, [add], []).then(() => setAdd('')).catch((e) => setErr(e.message))}>Add</button></span>
      )}
      {err && <span className="error small">{err}</span>}
    </div>
  );
}

// ---------- account ----------
function PushToggle() {
  const p = engine.st.push ?? { on: false };
  const [busy, setBusy] = useState(false);
  return (
    <>
      <label className="row"><span>Wake for new messages while KaspaChat is closed</span>
        <input type="checkbox" checked={p.on} disabled={busy} onChange={async (e) => {
          setBusy(true);
          try {
            if (e.target.checked) {
              const token = await pushStart().catch(() => null);
              if (token) engine.setPush(true, token);
              else alert("KaspaChat couldn't turn this on. Check that notifications are allowed for KaspaChat in Settings.");
            } else {
              await pushStop(p.token);
              engine.setPush(false);
            }
          } finally {
            setBusy(false);
          }
        }} /></label>
      <p className="small">Off unless you turn it on. When it's on, Kaspaguy's push service asks Apple to wake your iPhone when a message may have arrived. Your phone checks whether the message is for you before it shows anything, and the notification says only "New message". Apple and the push service see when your phone is woken, never who wrote or what. <strong>With it on, it may be possible to link two people who message each other from the timing of their wake-ups.</strong> Message requests from new people still wait until you open the app.</p>
    </>
  );
}

function Notifications() {
  useTick();
  const n = engine.st.notify ?? { on: false, names: false };
  const [bg, setBg] = useState<boolean | null>(null);
  useEffect(() => { if (kind === 'android') void batteryExempt().then(setBg).catch(() => {}); }, [n.on]);
  return (
    <section className="card">
      <h3>Notifications</h3>
      <label className="row"><span>Tell me about new messages</span>
        <input type="checkbox" checked={n.on} onChange={async (e) => {
          const on = e.target.checked && (await notifyPermission(true).catch(() => false));
          engine.setNotify(on, n.names);
          if (kind === 'android') setBg(await keepAlive(on).catch(() => false));
        }} /></label>
      <label className="row"><span>Show the sender's name</span>
        <input type="checkbox" checked={n.names} disabled={!n.on} onChange={(e) => engine.setNotify(n.on, e.target.checked)} /></label>
      {kind === 'android' && n.on && bg === false && (
        <p className="small">Android may stop KaspaChat in the background to save battery. <button className="small" onClick={async () => setBg(await keepAlive(true))}>Allow background use</button></p>
      )}
      {canPush && <PushToggle />}
      <p className="muted small">{canRunInBackground ? 'KaspaChat checks for messages itself while it runs; no Apple or Google push service is involved.' : kind === 'ios' ? 'Without "Wake for new messages", messages arrive when you open KaspaChat, and no Apple push service is involved.' : 'Notifications appear while this tab is open.'}</p>
    </section>
  );
}

function Indexers() {
  const [list, setList] = useState(extraIndexers());
  const [text, setText] = useState('');
  const [bad, setBad] = useState(false);
  const save = (l: string[]) => { setExtraIndexers(l); setList(extraIndexers()); };
  return (
    <section className="card">
      <h3>Indexers</h3>
      <p className="muted small">An indexer stores the encrypted messages and serves them to you. KaspaChat uses its own first and moves to the next one if it can't be reached. Anyone can run one; the code is public. An indexer you add sees your requests, so add only ones you trust.</p>
      {list.map((u) => <div className="row" key={u}><span className="small">{u}</span><button className="small" onClick={() => save(list.filter((x) => x !== u))}>Remove</button></div>)}
      <div className="row">
        <input value={text} placeholder="https://… or http://….onion" onChange={(e) => { setText(e.target.value); setBad(false); }} />
        <button className="small" onClick={() => { const c = cleanIndexerUrl(text); if (!c) return setBad(true); save([...list, c]); setText(''); }}>Add</button>
      </div>
      {bad && <p className="small">That isn't an address KaspaChat can use. It must start with https://, or be an .onion address.</p>}
    </section>
  );
}

function Connection() {
  const t = useSyncExternalStore(onTorChange, torStatus);
  const [on, setOn] = useState(torWanted());
  if (!canTor) return null;
  const said = { off: 'Not started yet', connecting: 'Connecting to Tor…', ready: 'Connected through Tor', failed: "Tor can't connect" }[t.state];
  return (
    <section className="card">
      <h3>Connection</h3>
      <label className="row"><span>Connect through Tor</span>
        <input type="checkbox" checked={on} onChange={(e) => { setTorWanted(e.target.checked); setOn(e.target.checked); }} /></label>
      {on && <p className="small">{said}{t.state === 'failed' && t.error ? ` (${t.error}). KaspaChat keeps trying. If Tor is blocked where you are, you can turn this off to connect directly.` : ''}</p>}
      <p className="muted small">{on
        ? "KaspaChat reaches Kaspaguy's servers at their onion address, so they never see your IP address."
        : "Kaspaguy's servers see your IP address when you send or fetch messages. They don't log it, but you have to trust that."}</p>
    </section>
  );
}

function Blocked() {
  useTick();
  const b = Object.entries(engine.st.blocked ?? {});
  if (!b.length) return null;
  return (
    <section className="card">
      <h3>Blocked</h3>
      {b.map(([o, x]) => <div className="row" key={o}><span>@{x.name}</span><button className="small" onClick={() => engine.unblock(o)}>Unblock</button></div>)}
    </section>
  );
}

function Account({ onBack, onLock, onErase }: { onBack: () => void; onLock: () => void; onErase: () => void }) {
  useTick();
  const st = engine.st;
  const cfg = engine.config;
  const [showPhrase, setShowPhrase] = useState(false);
  const [order, setOrder] = useState<string | null>(null);
  const active = st.orders.find((o) => o.id === order) ?? st.orders.find((o) => o.status === 'pending' || o.status === 'paid');
  return (
    <div className="panel scroll">
      <header><button className="icon back" onClick={onBack}>←</button><h2>Account</h2></header>
      <section className="card">
        <h3>Your names</h3>
        {st.names.map((n) => (
          <div className="row" key={n.name}>
            <span>@{n.name} {n.expiry > 1 ? (isPlus(n.expiry, st.tipDaa) ? <span className="pill plus">Pro</span> : <span className="pill">expired</span>) : <span className="pill">free</span>}</span>
            {st.name === n.name ? <span className="muted small">in use</span> : <button className="small" onClick={() => engine.useName(n.name)}>Use</button>}
          </div>
        ))}
        <p className="muted small">Your name is how people find you. Messages never carry it on-chain.</p>
      </section>
      <section className="card">
        <h3>Message credits: {engine.status.credits}</h3>
        <p className="muted small">One credit sends one message. The network fee is paid from the treasury, so your wallet never appears next to your messages.</p>
        {engine.testnet && <FreeCredits />}
        {!storeBuild && <Topup onOrder={setOrder} />}
      </section>
      {storeBuild ? <StorePlus /> : <Plus cfg={cfg} onOrder={setOrder} />}
      {!storeBuild && <GetKas />}
      {!storeBuild && active && <Payment o={active} />}
      <section className="card">
        <h3>Cover traffic</h3>
        <label className="row"><span>Send dummy messages so real ones don't stand out</span>
          <input type="checkbox" checked={st.cover.on} onChange={(e) => engine.setCover(e.target.checked, st.cover.perDay)} /></label>
        <label className="row"><span>Per day</span>
          <input type="number" min={1} max={24} value={st.cover.perDay} onChange={(e) => engine.setCover(st.cover.on, Number(e.target.value))} style={{ width: 70 }} /></label>
        <p className="muted small">Paid by the treasury, not your credits.</p>
      </section>
      <Connection />
      <Indexers />
      <Notifications />
      <Blocked />
      <section className="card">
        <h3>Recovery phrase</h3>
        {showPhrase ? <ol className="words">{st.mnemonic.split(' ').map((w, i) => <li key={i}>{w}</li>)}</ol> : <button onClick={() => confirm('Show your recovery phrase on screen?') && setShowPhrase(true)}>Show</button>}
      </section>
      <section className="card">
        <h3>About</h3>
        <p className="small">KaspaChat runs the Kaspaveil protocol by Kaspaguy: end-to-end encrypted with post-quantum key exchange, every message padded to one size, routed by one-time tags so no server can map who talks to whom. The protocol and contracts are open source under AGPL-3.0.</p>
        <p className="small"><a href={`${SITE}/terms`} target="_blank" rel="noopener noreferrer">Terms of use</a> · <a href={`${SITE}/privacy`} target="_blank" rel="noopener noreferrer">Privacy policy</a> · <a href={`${SITE}/support`} target="_blank" rel="noopener noreferrer">Support</a></p>
        <TestnetNote />
        {cfg?.feedback && <p className="small">Something not right, or an idea? Use <strong>💬 Send feedback</strong> on the main screen.</p>}
      </section>
      <button onClick={onLock}>Lock this device</button>
      <section className="card">
        <h3>Delete account</h3>
        <p className="muted small">Erases your keys, chats and credits from this device. Kaspaguy holds no account to delete: there's no email, phone number or profile on our servers. Your name stays in the public registry (a free name keeps pointing at keys nobody holds any more; a Pro name lapses when its time runs out). With your recovery phrase you can come back; without it, nobody can.</p>
        <button className="danger" onClick={() => { if (confirm('Delete your account from this device? Without your recovery phrase it cannot be restored.') && confirm('Really delete? This cannot be undone.')) onErase(); }}>Delete account from this device</button>
      </section>
    </div>
  );
}

// App Store / Play builds: show what the account has, sell nothing, point nowhere (Apple 3.1.1 / 3.1.3).
function StorePlus() {
  const st = engine.st;
  const plusNames = st.names.filter((n) => n.expiry > 1 && isPlus(n.expiry, st.tipDaa));
  return (
    <section className="card">
      <h3>KaspaChat Pro</h3>
      {plusNames.length ? plusNames.map((n) => <p key={n.name}>@{n.name} <span className="pill plus">Pro</span></p>) : <p className="muted small">No Pro name on this account.</p>}
      <p className="muted small">Pro and message top-ups can't be bought in this version of the app.</p>
    </section>
  );
}

// KAS only: KaspaChat never swaps coins. These are independent services, listed alphabetically.
const SWAPS = [
  { name: 'ChangeNOW', url: 'https://changenow.io/currencies/kaspa' },
  { name: 'DuskSwap', url: 'https://duskswap.com/kas' },
  { name: 'Exolix', url: 'https://exolix.com/currencies/kas' },
  { name: 'SimpleSwap', url: 'https://simpleswap.io/coins/kas' },
];
function GetKas() {
  return (
    <section className="card">
      <h3>Get KAS</h3>
      <p className="small">KaspaChat takes KAS only. To swap another coin into KAS, use one of these independent services and send the KAS to your own wallet, then pay from there.</p>
      <div className="row wrap">
        {SWAPS.map((x) => <a key={x.name} className="chip link-out" href={x.url} target="_blank" rel="noopener noreferrer">{x.name} ↗</a>)}
      </div>
      <p className="muted small">On this testnet preview you don't need any: use the free test coins button when you pay.</p>
    </section>
  );
}

// Shared by every place the button shows, so a second tap elsewhere can't start a second order.
let freeCreditsBusy = false;
function FreeCredits() {
  useTick();
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  async function get() {
    if (freeCreditsBusy) return;
    freeCreditsBusy = true;
    setErr('');
    setMsg('Getting free test credits… about a minute.');
    try {
      await engine.freeTestCredits();
      setMsg('Done: free test credits added.');
    } catch (e) {
      setMsg('');
      setErr((e as Error).message);
    } finally {
      freeCreditsBusy = false;
    }
  }
  return (
    <div className="free-credits">
      <button className="block" disabled={freeCreditsBusy} onClick={() => void get()}>{freeCreditsBusy ? 'Getting free test credits…' : '🎁 Get free test credits'}</button>
      {msg && <div className="muted small">{msg}</div>}
      {err && <div className="error small">{err}</div>}
    </div>
  );
}

function Topup({ onOrder }: { onOrder: (id: string) => void }) {
  const [amount, setAmount] = useState(20);
  const [err, setErr] = useState('');
  const cfg = engine.config;
  const per = cfg ? Math.floor((amount * KAS * 0.75) / cfg.msgFee) : 0;
  return (
    <div className="row wrap">
      <input type="number" min={20} max={100} step={10} value={amount} onChange={(e) => setAmount(Number(e.target.value))} style={{ width: 90 }} /> KAS
      <span className="muted small">≈ {per.toLocaleString()} messages</span>
      <button onClick={() => engine.orderTopup(amount).then(onOrder).catch((e) => setErr(e.message))}>Top up</button>
      {err && <span className="error small">{err}</span>}
    </div>
  );
}

function Plus({ cfg, onOrder }: { cfg: any; onOrder: (id: string) => void }) {
  const st = engine.st;
  const [name, setName] = useState('');
  const [months, setMonths] = useState(1);
  const [check, setCheck] = useState<{ available: boolean; lapsed?: boolean; reason?: string } | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    setCheck(null);
    if (!/^[a-z]{1,7}-[0-9]{2,4}$/.test(name)) return;
    const t = setTimeout(() => engine.checkName(name).then(setCheck).catch(() => {}), 350);
    return () => clearTimeout(t);
  }, [name]);
  const plusNames = st.names.filter((n) => n.expiry > 1);
  if (!cfg) return null;
  return (
    <section className="card">
      <h3>KaspaChat Pro</h3>
      <ul className="small">
        <li>Choose your name, like @bob-123</li>
        <li>Up to ~{cfg.creditsPerMonth.toLocaleString()} one-to-one messages a month at today's Kaspa fees</li>
        <li>Turn off the disappearing timer in all-Pro chats</li>
      </ul>
      <p><strong>{kas(cfg.plusPrice)} KAS</strong> a month · 25% to Kaspaguy, 75% to the message treasury, split on-chain</p>
      {plusNames.map((n) => (
        <div className="row" key={n.name}><span>@{n.name}</span><button className="small" onClick={() => engine.renewPlus(n.name, 1).then(onOrder).catch((e) => setErr(e.message))}>Renew 1 month</button></div>
      ))}
      <div className="row wrap">
        <input placeholder="name-123" autoCapitalize="none" value={name} onChange={(e) => setName(e.target.value.toLowerCase())} style={{ width: 150 }} />
        <select value={months} onChange={(e) => setMonths(Number(e.target.value))}>{[1, 3, 6, 12].map((m) => <option key={m} value={m}>{m} month{m > 1 ? 's' : ''}</option>)}</select>
        <button className="primary" disabled={!check?.available} onClick={() => engine.orderPlus(name, months).then((id) => { setName(''); onOrder(id); }).catch((e) => setErr(e.message))}>Get Pro</button>
      </div>
      <p className="muted small">{name && !/^[a-z]{1,7}-[0-9]{2,4}$/.test(name) ? 'Letters, a hyphen, then 2 to 4 digits (at most 10 characters).' : check ? (check.available ? (check.lapsed ? `@${name} lapsed and is free to claim: first to pay gets it.` : `@${name} is available.`) : `@${name}: ${check.reason}`) : ' '}</p>
      {err && <p className="error small">{err}</p>}
    </section>
  );
}

function Payment({ o }: { o: Order }) {
  useTick();
  const [qr, setQr] = useState('');
  const [msg, setMsg] = useState('');
  useEffect(() => { QRCode.toDataURL(`${o.address}?amount=${o.amount / KAS}`, { margin: 1, width: 180 }).then(setQr); }, [o.address, o.amount]);
  useEffect(() => {
    const t = setInterval(() => void engine.pollOrdersNow(), 4000);
    return () => clearInterval(t);
  }, []);
  const what = o.kind === 'plus' || o.kind === 'claim' ? `Pro for @${o.name}, ${o.months} month${(o.months ?? 1) > 1 ? 's' : ''}` : o.kind === 'renew' ? `Renewal of @${o.name}` : 'Message top-up';
  return (
    <section className="card pay">
      <h3>{what}</h3>
      {o.status === 'pending' && (
        <>
          <p>Send exactly <strong>{kas(o.amount)} KAS</strong> (testnet), in one payment, within 2 hours, to this order's payment address. It's a contract with no keys: it can only split your payment, 75% to the message treasury and 25% to Kaspaguy.</p>
          <p className="muted small">Nothing you send here is lost. If less arrives in time, or you pay twice or too much, whatever arrives that the order doesn't use becomes message credits on your account.</p>
          {qr && <img src={qr} alt="Payment QR code" width={180} height={180} />}
          <code className="addr" onClick={() => navigator.clipboard?.writeText(o.address)}>{o.address}</code>
          {engine.config?.network?.startsWith('testnet') && <button className="primary" onClick={() => { setMsg('Paying from the Kaspaguy test faucet…'); engine.testPay(o.id).then(() => setMsg('Paid. Waiting for the network…')).catch((e) => setMsg(e.message)); }}>Testnet: pay with free test coins</button>}
          <p className="muted small">{msg || 'This page updates by itself once the payment arrives.'}</p>
        </>
      )}
      {o.status === 'paid' && <p className="progress"><span className="spinner" />Payment received. Registering on-chain…</p>}
      {o.status === 'done' && <p>Done. {o.kind === 'plus' || o.kind === 'claim' ? `You are now @${o.name}.` : 'Your credits are ready.'}</p>}
      {o.status === 'credited' && <p>This order wasn't paid in full within 2 hours, so nothing was bought. The {kas(o.extraSompi ?? 0)} KAS that arrived became message credits on your account.</p>}
      {o.status !== 'credited' && (o.extraSompi ?? 0) > 0 && <p className="muted small">{kas(o.extraSompi!)} KAS more reached this order and became message credits.</p>}
      {(o.status === 'expired' || o.status === 'failed') && <p className="error">This order {o.status}. {o.error}</p>}
    </section>
  );
}
