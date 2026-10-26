// Runs every published vector from its own input only (no generator, no shared state), the way a second
// implementation must. Proves the vector file is self-describing and complete.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { utf8 } from '../src/crypto.ts';
import {
  bundlePayload, bundleTag, buildFirstContact, coverFirstContact, crossingKeeps, onFirstContactFromKnownPeer, receiveFirstContact, defaultName, decodePrefs, decrypt, effectiveSettings, encodePrefs, encrypt, identityFromMnemonic,
  identityFromSeed, inboxBucket, kemOffer, makeBundle, makeGroupState, makeGroupText, openFirstContact, parseBundle, receiveGroupState,
  PAYLOAD_LEN, receiveGroupText, registryBucket, signedPrekey, tagBucket, withBucket,
} from '../src/index.ts';
import type { Groups, Identity, SignedPrekey } from '../src/index.ts';
import { hex, replay, sessionFromJson, sessionToJson, unhex } from '../scripts/vector-format.ts';

const file = JSON.parse(readFileSync(new URL('../vectors/v1.json', import.meta.url), 'utf8'));
const str = (b: Uint8Array) => new TextDecoder().decode(b);
const r = (o: Record<string, string> = {}) => replay(Object.values(o));
const idOf = (o: any) => ({ ownerSk: o.owner_sk && unhex(o.owner_sk), ownerPub: o.owner_pub && unhex(o.owner_pub), idXSk: o.id_x25519_sk && unhex(o.id_x25519_sk),
  idXPub: o.id_x25519_pub && unhex(o.id_x25519_pub) }) as Identity;
const prekeysOf = (ps: any[]) => ps.map((p) => {
  const kem = ml_kem768.keygen(unhex(p.mlkem_keygen_seed));
  return { spkId: p.spk_id, xSk: unhex(p.x25519_sk), xPub: x25519.getPublicKey(unhex(p.x25519_sk)), kemSk: kem.secretKey, kemPub: kem.publicKey } as SignedPrekey;
});
const lookupOf = (reg: any) => (n: string) => (reg[n] ? { ownerPub: unhex(reg[n].owner_pub), idXPub: unhex(reg[n].id_x25519_pub) } : null);

const run: Record<string, (i: any, e: any, v: any) => void> = {
  keys(i, e) {
    if (i.mnemonic) {
      const id = identityFromMnemonic(i.mnemonic);
      assert.deepEqual({ seed: hex(id.seed), owner_sk: hex(id.ownerSk), owner_pub: hex(id.ownerPub), id_x25519_sk: hex(id.idXSk), id_x25519_pub: hex(id.idXPub) }, e);
    } else {
      const spk = signedPrekey(identityFromSeed(unhex(i.seed)), i.spk_id);
      assert.equal(hex(spk.xSk), e.spk_x25519_sk); assert.equal(hex(spk.xPub), e.spk_x25519_pub);
      assert.equal(hex(spk.kemPub), e.spk_mlkem_pub); assert.equal(hex(spk.kemSk), e.spk_mlkem_sk);
      assert.equal(hex(ml_kem768.keygen(unhex(e.mlkem_keygen_seed)).publicKey), e.spk_mlkem_pub);
    }
  },
  bundle(i, e, v) {
    if (v.id === 'bundle-bob-1') {
      const b = makeBundle(idOf(i), { spkId: i.spk_id, xPub: unhex(i.spk_x25519_pub), kemPub: unhex(i.spk_mlkem_pub) } as SignedPrekey, BigInt(i.created), [], unhex(i.rand.schnorr_aux));
      assert.equal(hex(b), e.bundle);
    } else if (v.id === 'bundle-payload') {
      assert.equal(hex(bundleTag(unhex(i.owner_pub))), e.bundle_tag); assert.equal(hex(bundlePayload(unhex(i.bundle))), e.payload);
    } else {
      assert.equal(parseBundle(unhex(i.bundle), unhex(i.expected_owner_pub)) ? 'accept' : 'reject', e.result);
    }
  },
  registry(i, e) {
    assert.deepEqual(i.owner_pubs.map((o: string) => [0, 1, 2].map((n) => defaultName(unhex(o), n))), e.names);
  },
  buckets(i, e, v) {
    if (v.id === 'cover-first-contact') return assert.equal(hex(coverFirstContact(i.bucket, r(i.rand))), e.payload);
    if (i.tags) assert.deepEqual(i.tags.map((t: string) => tagBucket(unhex(t))), e.buckets);
    else if (i.names) assert.deepEqual(i.names.map(registryBucket), e.buckets);
    else if (i.id_x25519_pubs) assert.deepEqual(i.id_x25519_pubs.map((k: string) => inboxBucket(unhex(k))), e.buckets);
    else assert.equal(hex(withBucket(unhex(i.tag), i.bucket)), e.tag, v.id);
  },
  'first-contact'(i, e) {
    if (i.steps) {
      const seen = new Map<string, number>();
      const got = i.steps.map((s: any) => {
        const x = receiveFirstContact(seen, idOf(i.recipient), prekeysOf(i.recipient.prekeys), unhex(s.payload), lookupOf(i.registry), r(s.rand), 0);
        if (x === 'replay') return { result: 'replay' };
        return x ? { result: 'accept', from: x.from, kind: x.kind, text: str(x.text), session: sessionToJson(x.session) } : { result: 'reject' };
      });
      assert.deepEqual(got, e.results);
      return assert.deepEqual([...seen].map(([tag, spk_id]) => ({ tag, spk_id })), e.seen_after);
    }
    if (i.cases) return assert.deepEqual(i.cases.map((c: any) => onFirstContactFromKnownPeer(sessionFromJson(c.session), unhex(c.current_first_contact_tag), unhex(c.received_tag))), e.results);
    if (i.alice_to_bob_tag) {
      const [ta, tb] = [unhex(i.alice_to_bob_tag), unhex(i.bob_to_alice_tag)];
      assert.equal(crossingKeeps(ta, tb), e.alice_keeps); assert.equal(crossingKeeps(tb, ta), e.bob_keeps);
      return assert.equal(crossingKeeps(ta, tb) === 'sent' ? 'alice-to-bob' : 'bob-to-alice', e.keep);
    }
    if (i.alice) {
      const fc = buildFirstContact(idOf(i.alice), i.alice.name, parseBundle(unhex(i.bob_bundle), unhex(i.bob_bundle).subarray(1, 33))!, utf8(i.text), r(i.rand), 0);
      assert.equal(hex(fc.payload), e.payload); assert.deepEqual(sessionToJson(fc.session), e.session);
      return;
    }
    const got = openFirstContact(idOf(i.recipient), prekeysOf(i.recipient.prekeys), unhex(i.payload), lookupOf(i.registry), r(i.rand), 0);
    if (e.result === 'reject') return assert.equal(got, null);
    assert.equal(got!.from, e.from); assert.equal(got!.kind, e.kind); assert.equal(str(got!.text), e.text);
    assert.deepEqual(sessionToJson(got!.session), e.session);
  },
  groups(i, e, v) {
    if (i.sessions) return run.ratchet(i, e, v);
    if (v.id === 'group-state-encode') {
      const members = i.members.map((m: any) => ({ ownerPub: unhex(m.owner_pub), idXPub: unhex(m.id_x25519_pub), name: m.name }));
      const admin = identityFromSeed(new Uint8Array(64));
      admin.ownerSk = unhex(i.admin_owner_sk);
      admin.ownerPub = members[0].ownerPub;
      return assert.equal(hex(makeGroupState(admin, unhex(i.group_id), i.epoch, members, r(i.rand))), e.content);
    }
    if (v.id === 'group-text-encode') return assert.equal(hex(makeGroupText(unhex(i.group_id), i.epoch, unhex(i.msg_id), utf8(i.text))), e.content);
    const g: Groups = new Map();
    const got = i.steps.map((s: any) => {
      const from = unhex(i.senders[s.from]);
      if (s.op === 'group_state') { const x = receiveGroupState(g, unhex(i.me_owner_pub), from, unhex(s.content)); return x ? { event: x.event, epoch: x.epoch } : { reject: true }; }
      const x = receiveGroupText(g, unhex(i.me_owner_pub), from, unhex(s.content));
      return x === 'pending' ? { pending: true } : x ? { text: str(x.text), epoch: x.epoch, older_epoch: x.olderEpoch } : { reject: true };
    });
    assert.deepEqual(got, e.results);
  },
  ratchet(i, e) {
    const sessions = Object.fromEntries(Object.entries(i.sessions).map(([k, s]) => [k, sessionFromJson(s as any)]));
    const results = i.steps.map((s: any) => {
      const S = sessions[s.session];
      if (s.op === 'encrypt') return { payload: hex(encrypt(S, s.kind, unhex(s.content), r(s.rand))) };
      if (s.op === 'kem_offer') return { content: hex(kemOffer(S, r(s.rand), 0)) };
      const d = decrypt(S, unhex(s.payload), r(s.rand), 0);
      return d ? { kind: d.kind, content: hex(d.content), ...(d.kemAnswer ? { kem_answer: hex(d.kemAnswer) } : {}) } : { reject: true };
    });
    assert.deepEqual(results, e.results);
    for (const [k, s] of Object.entries(sessions)) assert.deepEqual(sessionToJson(s), e.sessions_after[k], `session ${k} after`);
  },
  'kem-step'(i, e, v) { run.ratchet(i, e, v); },
  'conversation-settings'(i, e, v) {
    if (v.id === 'settings-encode') {
      return assert.deepEqual(i.prefs.map((p: any) => hex(encodePrefs({ version: 1, epoch: p.epoch, groupId: null, timerOff: p.timer_off, screenshotProtection: p.screenshot_protection }))), e.contents);
    }
    if (v.id === 'settings-encode-v2' || v.id === 'settings-encode-group') {
      const b = encodePrefs({ version: 2, epoch: i.epoch, groupId: i.context === 1 ? unhex(i.group_id) : null, timerOff: (i.flags & 1) === 1, screenshotProtection: (i.flags & 2) === 2 });
      assert.equal(hex(b), e.bytes); assert.equal(b.length, e.length);
      return assert.equal(hex(encodePrefs(decodePrefs(b)!)), e.bytes);
    }
    if (v.id === 'settings-reject-v2') {
      for (const c of i.cases) assert.equal(c.content, '02' + c.epoch.toString(16).padStart(8, '0') + c.context.toString(16).padStart(2, '0') + c.context_data + '00');
      return assert.deepEqual(i.cases.map((c: any) => (decodePrefs(unhex(c.content)) ? 'accept' : 'reject')), e.results);
    }
    if (v.id === 'settings-reject') return assert.deepEqual(i.contents.map((c: string) => (decodePrefs(unhex(c)) ? 'accept' : 'reject')), e.results);
    const got = i.cases.map((c: any) => {
      const x = effectiveSettings(c.members.map((m: any) => ({ plus: m.plus, prefs: m.prefs && { version: 1, epoch: 1, groupId: null, timerOff: m.prefs.timer_off, screenshotProtection: m.prefs.screenshot_protection } })));
      return { timer_seconds: x.timerSeconds, screenshot_protection: x.screenshotProtection };
    });
    assert.deepEqual(got, e.results);
  },
  transaction(i, e) {
    assert.equal(i.version, 1); assert.equal(i.subnetwork_id, '4b564c0100000000000000000000000000000000'); assert.equal(i.gas, 0);
    assert.equal(i.payload.length, 2 * PAYLOAD_LEN);
    assert.equal(i.inputs.length, 1); assert.equal(i.outputs.length, 1);
    const bound = i.outputs[0].covenant;
    if (bound) {
      // The spending pot (WIRE_FORMAT §5): its continuation carries the input's covenant ID, authorized by input 0.
      assert.equal(bound.authorizing_input, 0);
      assert.equal(bound.covenant_id, i.inputs[0].utxo_covenant_id, 'output bound to the pot covenant');
      assert.ok(i.lock_time < 500_000_000_000 && i.inputs[0].sequence !== '18446744073709551615', 'a DAA-score lock time that consensus enforces');
    } else {
      assert.equal(i.outputs[0].script_public_key, i.inputs[0].utxo_script_public_key, 'output back to the retired hot wallet');
    }
    assert.equal(e.min_fee, 100 * Math.max(e.compute_mass, Math.ceil(e.transient_mass / 2)));
    assert.ok(e.fee_paid >= e.min_fee && e.fee_paid <= 100_000_000);
    const conv = file.vectors.find((x: any) => x.id === 'ratchet-conversation');
    assert.equal(i.payload, conv.expected.results[0].payload, 'carries ratchet-conversation step 0');
  },
};

test('vector file declares its format', () => {
  assert.ok(file.format.encoding && file.format.randomness && file.format.session_state);
  assert.equal(new Set(file.vectors.map((v: any) => v.id)).size, file.vectors.length, 'ids are unique');
});

for (const v of file.vectors) {
  test(`vector ${v.id} (${v.kind}) runs from its own input`, () => {
    for (const f of ['id', 'kind', 'description', 'input', 'expected']) assert.ok(v[f] !== undefined, `${v.id}: missing ${f}`);
    run[v.kind](v.input, v.expected, v);
  });
}
