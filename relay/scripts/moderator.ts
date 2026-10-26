// Report reviewer that learns from Kaspaguy's decisions from the first one on (docs/STORE_SUBMISSION.md §2). It runs on
// the relay box and sends nothing anywhere. It suggests; a person decides, and every decision teaches it.
// Its memory is word counts per verdict, not the reports, so deleting reports doesn't make it forget, and the
// model never holds a message as written.
export type Verdict = 'valid' | 'dismiss';
export type Model = { _id: 'model'; docs: Record<Verdict, number>; feats: Record<Verdict, Record<string, number>> };
export type ReportLike = { reason: string; note: string; group: boolean; messages: { from: string; text: string }[] };
export type Suggestion = { verdict: Verdict; confidence: number; because: string[]; decisions: number };

const VERDICTS: Verdict[] = ['valid', 'dismiss'];
// Own keys only: report words like "constructor" must not read Object.prototype.
const count = (m: Model, v: Verdict, f: string) => (Object.hasOwn(m.feats[v], f) ? m.feats[v][f] : 0);
export const emptyModel = (): Model => ({ _id: 'model', docs: { valid: 0, dismiss: 0 }, feats: { valid: {}, dismiss: {} } });

// Each feature counts once per report, so one long rant doesn't outweigh many short reports.
export function features(r: ReportLike): string[] {
  const reported = r.messages.filter((m) => m.from === 'reported');
  const f = new Set([`reason:${r.reason}`, `group:${r.group}`, `note:${r.note.trim() !== ''}`, `reported-msgs:${Math.min(reported.length, 5)}`]);
  const text = [r.note, ...reported.map((m) => m.text)].join(' ').toLowerCase();
  for (const w of text.match(/[\p{L}\p{N}]{2,24}/gu) ?? []) f.add(w);
  if (/https?:\/\/|www\./i.test(text)) f.add('has:link');
  return [...f];
}

// Naive Bayes over the features, with add-one smoothing. Null until there is a first decision to learn from.
export function suggest(m: Model, r: ReportLike): Suggestion | null {
  const n = m.docs.valid + m.docs.dismiss;
  if (n === 0) return null;
  const fs = features(r);
  const p = (v: Verdict, f: string) => (count(m, v, f) + 1) / (m.docs[v] + 2);
  const score = Object.fromEntries(VERDICTS.map((v) => [v, Math.log((m.docs[v] + 1) / (n + 2)) + fs.reduce((s, f) => s + Math.log(p(v, f)), 0)])) as Record<Verdict, number>;
  const verdict: Verdict = score.valid >= score.dismiss ? 'valid' : 'dismiss';
  const other: Verdict = verdict === 'valid' ? 'dismiss' : 'valid';
  const confidence = 1 / (1 + Math.exp(score[other] - score[verdict]));
  const because = fs
    .map((f) => [f, Math.log(p(verdict, f) / p(other, f))] as const)
    .filter(([f, w]) => w > 0 && count(m, verdict, f) > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([f]) => f);
  return { verdict, confidence, because, decisions: n };
}

export function learn(m: Model, r: ReportLike, v: Verdict): Model {
  m.docs[v]++;
  for (const f of features(r)) m.feats[v][f] = count(m, v, f) + 1;
  return m;
}
