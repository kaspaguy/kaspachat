// Abuse reports sent from the apps (relay POST /v1/report). Moderation process: docs/STORE_SUBMISSION.md §2.
//   node relay/scripts/reports.ts                     open reports, oldest first, each with the reviewer's suggestion
//   node relay/scripts/reports.ts valid <id> <why…>   valid: 24-hour directory hold on the reported owner
//   node relay/scripts/reports.ts dismiss <id> <why…> not valid: no action
//   node relay/scripts/reports.ts holds               active holds;  lift <name>  ends one early
//   node relay/scripts/reports.ts agent               how often the reviewer agreed with the decisions made
// The hold starts only after review (Kaspaguy, 2026-10-16), so a report alone can never silence anyone. While it
// lasts, the official indexer doesn't serve the owner's public keys: nobody new can start a chat with them, and their
// own new first contacts don't open, because recipients' apps can't find their keys. Existing chats keep working.
// A decision deletes the report's message text and note at once; the relay deletes every report 90 days after it arrived.
import { MongoClient } from 'mongodb';
import { bundleTag, registryBucket } from '../../protocol/src/index.ts';
import { emptyModel, learn, suggest, type Model, type Verdict } from './moderator.ts';

const HOLD_MS = 24 * 3600_000;
const INDEXER = process.env.KASPAVEIL_INDEXER ?? 'http://127.0.0.1:5510';
const mongo = new MongoClient(process.env.MONGO_URL ?? 'mongodb://127.0.0.1:27017');
await mongo.connect();
const db = mongo.db(process.env.MONGO_DB ?? 'kaspaveil_tn10');
const reports = db.collection<any>('reports');
const holds = db.collection<any>('holds');
const decisions = db.collection<any>('report_decisions');
const models = db.collection<Model>('report_model');
const model = (await models.findOne({ _id: 'model' })) ?? emptyModel();
const pct = (x: number) => `${Math.round(x * 100)}%`;
const [cmd, id, ...rest] = process.argv.slice(2);

async function owner(name: string): Promise<string | null> {
  const r = await (await fetch(`${INDEXER}/v1/registry/bucket/${registryBucket(name)}`)).json();
  return r.entries?.find((e: any) => e.name === name)?.owner ?? null;
}

async function decide(v: Verdict) {
  const r = await reports.findOne({ _id: id, status: 'open' });
  if (!r) return console.log('no open report with that id');
  const s = suggest(model, r);
  let action = 'no action';
  if (v === 'valid') {
    const o = await owner(r.name);
    if (!o) return console.log(`@${r.name} isn't in the registry any more; nothing to hold. Dismiss it, or check the name.`);
    const until = new Date(Date.now() + HOLD_MS);
    const tag = Buffer.from(bundleTag(Buffer.from(o, 'hex'))).toString('hex');
    await holds.updateOne({ _id: tag }, { $set: { owner: o, name: r.name, until, report: r._id, at: new Date() } }, { upsert: true });
    action = `directory hold until ${until.toISOString().slice(0, 16)} UTC`;
  }
  const why = rest.join(' ');
  await reports.updateOne({ _id: r._id }, { $set: { status: 'done', verdict: v, why, action, closed: new Date(), messages: [], note: '' } });
  await decisions.insertOne({ at: new Date(), report: r._id, reason: r.reason, verdict: v, why, suggested: s?.verdict ?? null, confidence: s?.confidence ?? null, agreed: s ? s.verdict === v : null });
  await models.replaceOne({ _id: 'model' }, learn(model, r, v), { upsert: true });
  console.log(`${v}: ${action}.${s ? ` The reviewer suggested ${s.verdict} (${pct(s.confidence)}).` : ''} Learned from it (${model.docs.valid + model.docs.dismiss} decisions so far).`);
}

if (!cmd) {
  const open = await reports.find({ status: 'open' }).sort({ at: 1 }).toArray();
  for (const r of open) {
    const age = Math.round((Date.now() - r.at.getTime()) / 3600_000);
    console.log(`\n${r._id}  @${r.name}  ${r.reason}${r.group ? '  (group)' : ''}  ${age} h ago${age >= 24 ? '  OVERDUE' : ''}`);
    if (r.note) console.log(`  note: ${r.note}`);
    for (const m of r.messages) console.log(`  ${m.from === 'reported' ? '>' : ' '} ${new Date(m.t).toISOString().slice(0, 16)}  ${m.text.replace(/\s+/g, ' ').slice(0, 300)}`);
    const s = suggest(model, r);
    console.log(s ? `  reviewer: ${s.verdict} (${pct(s.confidence)}, from ${s.decisions} decisions)${s.because.length ? ` because of ${s.because.join(', ')}` : ''}` : '  reviewer: no suggestion yet; your first decision teaches it');
  }
  console.log(`\n${open.length} open`);
} else if ((cmd === 'valid' || cmd === 'dismiss') && id && rest.length) {
  await decide(cmd);
} else if (cmd === 'holds') {
  for (const h of await holds.find({ until: { $gt: new Date() } }).sort({ until: 1 }).toArray()) console.log(`@${h.name}  until ${h.until.toISOString().slice(0, 16)} UTC  (report ${h.report})`);
} else if (cmd === 'lift' && id) {
  const r = await holds.deleteMany({ name: id.replace(/^@/, '') });
  console.log(r.deletedCount ? 'lifted' : 'no hold on that name');
} else if (cmd === 'agent') {
  const all = await decisions.find({ agreed: { $ne: null } }).sort({ at: -1 }).toArray();
  const last = all.slice(0, 20);
  const agree = (l: any[]) => l.filter((d) => d.agreed).length;
  console.log(`${model.docs.valid + model.docs.dismiss} decisions learned (${model.docs.valid} valid, ${model.docs.dismiss} dismissed).`);
  console.log(all.length ? `Agreed with you ${agree(all)} of ${all.length} times overall, ${agree(last)} of ${last.length} in the latest ${last.length}.` : 'No suggestions compared yet.');
  for (const d of all.filter((d) => !d.agreed).slice(0, 5)) console.log(`  disagreed ${d.at.toISOString().slice(0, 10)}: it said ${d.suggested}, you said ${d.verdict} (${d.reason}): ${d.why}`);
} else console.log('usage: reports.ts [valid|dismiss <id> <why…> | holds | lift <name> | agent]');
await mongo.close();
