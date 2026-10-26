// Feedback mail: parsing limits, a mail whose headers carry nothing the tester typed, and one SMTP session against a
// local TLS server (self-signed certificate made with openssl; skipped without it).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { feedbackMail, parseFeedback, smtpSend } from '../src/feedback.ts';

test('parseFeedback checks kind and length and flattens the short fields', () => {
  assert.equal(parseFeedback({ kind: 'rant', text: 'hello' }, 'testnet-10'), 'kind must be bug, idea or other');
  assert.equal(parseFeedback({ kind: 'bug', text: ' a ' }, 'testnet-10'), 'write a few words');
  assert.equal(parseFeedback({ kind: 'bug', text: 'x'.repeat(4001) }, 'testnet-10'), 'at most 4,000 characters');
  const f = parseFeedback({ kind: 'idea', text: 'dark mode please', contact: 'me@x.y\r\nBcc: evil@x.y', version: '0.5.7', platform: 'android' }, 'testnet-10');
  assert.deepEqual(f, { kind: 'idea', text: 'dark mode please', contact: 'me@x.y Bcc: evil@x.y', version: '0.5.7', platform: 'android', network: 'testnet-10', heard: '' });
});

test('feedbackMail keeps the text in a base64 body and out of the headers', () => {
  const f = parseFeedback({ kind: 'bug', text: 'Subject: hi\r\n.\r\nit broke 🙂', contact: 'reply@x.y', version: '0.5.7', platform: 'ios' }, 'testnet-10') as any;
  const m = feedbackMail(f, 'bot@kaspachat.com', 'testnet@kaspachat.com', new Date(0));
  const [head, body] = m.split('\r\n\r\n');
  assert.match(head, /^Subject: \[KaspaChat testnet-10\] bug - ios 0\.5\.7$/m);
  assert.doesNotMatch(head, /it broke|reply@/);
  const text = Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString('utf8');
  assert.match(text, /^Subject: hi\r\n\.\r\nit broke 🙂\r\n/);
  assert.match(text, /Reply to: reply@x\.y/);
  assert.ok(body.split('\r\n').every((l) => l.length <= 76));
});

let haveOpenssl = true;
try { execFileSync('openssl', ['version']); } catch { haveOpenssl = false; }

test('smtpSend speaks SMTP over TLS: login, envelope, data', { skip: !haveOpenssl && 'no openssl' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kv-smtp-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
  const cert = readFileSync(join(dir, 'c.pem'), 'utf8');
  const seen: string[] = [];
  let data = '';
  const srv = tls.createServer({ key: readFileSync(join(dir, 'k.pem')), cert }, (s) => {
    let inData = false, buf = '';
    s.write('220 test ESMTP\r\n');
    s.on('data', (d) => {
      buf += d.toString();
      if (inData) {
        if (buf.endsWith('\r\n.\r\n')) { data = buf; buf = ''; inData = false; s.write('250 queued\r\n'); }
        return;
      }
      while (buf.includes('\r\n')) {
        const line = buf.slice(0, buf.indexOf('\r\n'));
        buf = buf.slice(line.length + 2);
        seen.push(line);
        if (line.startsWith('EHLO')) s.write('250-test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n');
        else if (line.startsWith('AUTH PLAIN ')) s.write(Buffer.from(line.slice(11), 'base64').toString() === '\0bot@k.c\0pw' ? '235 ok\r\n' : '535 no\r\n');
        else if (line === 'DATA') { inData = true; s.write('354 go\r\n'); }
        else if (line === 'QUIT') s.end('221 bye\r\n');
        else s.write('250 ok\r\n');
      }
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const port = (srv.address() as any).port;
  try {
    await smtpSend({ host: 'localhost', port, user: 'bot@k.c', pass: 'pw', to: 'testnet@k.c', ca: cert }, 'Subject: x\r\n\r\nhello\r\n');
    assert.deepEqual(seen.slice(1, 4), ['AUTH PLAIN ' + Buffer.from('\0bot@k.c\0pw').toString('base64'), 'MAIL FROM:<bot@k.c>', 'RCPT TO:<testnet@k.c>']);
    assert.equal(data, 'Subject: x\r\n\r\nhello\r\n.\r\n');
    await assert.rejects(smtpSend({ host: 'localhost', port, user: 'bot@k.c', pass: 'wrong', to: 'testnet@k.c', ca: cert }, 'x\r\n'), /535/);
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('parseFeedback keeps only a listed "where did you hear" choice and the mail shows it', () => {
  const ok = parseFeedback({ kind: 'idea', text: 'hello there', heard: 'reddit' }, 'testnet-10') as any;
  assert.equal(ok.heard, 'reddit');
  assert.match(Buffer.from(feedbackMail(ok, 'b@k', 't@k').split('\r\n\r\n')[1].replace(/\r\n/g, ''), 'base64').toString(), /Heard about us: reddit/);
  const bad = parseFeedback({ kind: 'idea', text: 'hello there', heard: 'my blog\r\nBcc: x' }, 'testnet-10') as any;
  assert.equal(bad.heard, '');
  assert.doesNotMatch(Buffer.from(feedbackMail(bad, 'b@k', 't@k').split('\r\n\r\n')[1].replace(/\r\n/g, ''), 'base64').toString(), /Heard about us/);
});
