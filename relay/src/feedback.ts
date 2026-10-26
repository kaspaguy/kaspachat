// Tester feedback (testnet): the app's "Send feedback" form, mailed to the team's inbox and stored nowhere.
// The relay keeps no copy (no database, no log line); the mail carries only what the tester typed plus the app
// version, platform and network. No IP, no name unless the tester chose to add one in the text or contact field.
// SMTP over implicit TLS (port 465) as a send-only mailbox; the login comes from the environment (a file outside the repo).
import tls from 'node:tls';
import { randomBytes } from 'node:crypto';

export const KINDS = ['bug', 'idea', 'other'] as const;
// "Where did you hear about KaspaChat?": an optional fixed choice, so a tester's free text never lands in this line.
export const HEARD = ['x', 'telegram', 'reddit', 'discord', 'friend', 'kaspaguy.com', 'other'] as const;
export type Feedback = { kind: (typeof KINDS)[number]; text: string; contact: string; version: string; platform: string; network: string; heard: string };

export function parseFeedback(b: any, network: string): Feedback | string {
  if (!KINDS.includes(b?.kind)) return 'kind must be bug, idea or other';
  const text = typeof b.text === 'string' ? b.text.trim() : '';
  if (text.length < 3) return 'write a few words';
  if (text.length > 4000) return 'at most 4,000 characters';
  const short = (v: unknown, n: number) => (typeof v === 'string' ? v.replace(/[\r\n\t]+/g, ' ').trim().slice(0, n) : '');
  const heard = HEARD.includes(b.heard) ? (b.heard as string) : '';
  return { kind: b.kind, text, contact: short(b.contact, 200), version: short(b.version, 20), platform: short(b.platform, 20), network, heard };
}

// A tester's text never reaches a header: the subject is built from fixed parts only.
export function feedbackMail(f: Feedback, from: string, to: string, now = new Date()) {
  const id = `${randomBytes(12).toString('hex')}@kaspachat.com`;
  const body = [
    f.text,
    '',
    '--',
    `Kind: ${f.kind}`,
    `Reply to: ${f.contact || '(not given)'}`,
    `App: ${f.version || '?'} on ${f.platform || '?'} (${f.network})`,
    ...(f.heard ? [`Heard about us: ${f.heard}`] : []),
    'Sent from the KaspaChat app. The relay keeps no copy of this message.',
  ].join('\r\n');
  const headers = [
    `From: KaspaChat feedback <${from}>`,
    `To: ${to}`,
    `Subject: [KaspaChat ${f.network}] ${f.kind} - ${f.platform || 'app'} ${f.version}`.trim(),
    `Date: ${now.toUTCString()}`,
    `Message-ID: <${id}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
  ];
  // base64 keeps any text (emoji, a lone "." line) out of the SMTP framing.
  const b64 = Buffer.from(body, 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
  return headers.join('\r\n') + '\r\n\r\n' + b64 + '\r\n';
}

export type SmtpConf = { host: string; port: number; user: string; pass: string; to: string; ca?: string };

export function smtpSend(c: SmtpConf, mail: string, timeoutMs = 20_000): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host: c.host, port: c.port, servername: c.host, ca: c.ca });
    const timer = setTimeout(() => done(new Error('smtp timeout')), timeoutMs);
    let buf = '';
    let waiting: ((line: string) => void) | null = null;
    const done = (e?: Error) => {
      clearTimeout(timer);
      sock.destroy();
      e ? reject(e) : resolve();
    };
    sock.on('error', (e) => done(e));
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      // A reply ends at a line whose code is followed by a space ("250 ok"); "250-..." lines continue it.
      const m = buf.match(/(?:^|\r\n)(\d{3}) [^\r\n]*\r\n$/);
      if (m && waiting) {
        const w = waiting;
        waiting = null;
        const reply = buf;
        buf = '';
        w(reply);
      }
    });
    const step = (cmd: string | null, want: string) =>
      new Promise<void>((ok, bad) => {
        waiting = (reply) => (reply.trimEnd().split('\r\n').pop()!.startsWith(want) ? ok() : bad(new Error(`smtp: ${reply.trim().slice(0, 200)}`)));
        if (cmd !== null) sock.write(cmd + '\r\n');
      });
    (async () => {
      await step(null, '220');
      await step('EHLO relay.kaspachat.com', '250');
      await step('AUTH PLAIN ' + Buffer.from(`\0${c.user}\0${c.pass}`).toString('base64'), '235');
      await step(`MAIL FROM:<${c.user}>`, '250');
      await step(`RCPT TO:<${c.to}>`, '250');
      await step('DATA', '354');
      await step(mail + '.', '250');
      sock.write('QUIT\r\n');
      done();
    })().catch((e) => done(e));
  });
}
