# Ambiguities in Kaspaveil v1 (run 3)

Third independent Rust implementation, written from `WIRE_FORMAT.md`, `PROTOCOL_SPEC.md`, `docs/SPEC_CHANGELOG.md` and
`protocol/vectors/v1.json`. **All 41 vectors reproduce byte for byte** (43 tests in `tests/vectors.rs`: one per vector id,
a completeness check, and a mnemonic-rejection test), plus 19 behaviour tests in `tests/behaviour.rs` for rules no vector
reaches. Every vector passed the first time the suite ran, including the seven added after run 2.

---

## Red flags

**No high-impact finding. Nothing from run 1 or run 2 is still open. I found no case where I read the *current*
text differently from how run 2 read it.**

### "Resolved differently" (13): the spec now pins the opposite of a prior run's recorded decision

In every case the current text is explicit, I followed it, and the fix itself is not ambiguous. They are flagged
because **a prior crate left unchanged would now deviate from the spec**, mostly on paths the vectors don't reach.

| ID | Prior run's decision | The spec now says | Vector that catches a stale crate |
|---|---|---|---|
| A-008 | run 1 rejected non-zero trailing header bytes | "`flags` and the 3 trailing bytes are reserved in v1: senders write 0; receivers ignore them" | `ratchet-receiver-edge-cases` |
| A-012 | run 1 rejected non-zero name padding | "receivers reject another `len` and ignore the padding" | none |
| A-013 | run 1 skipped the padding check and rejected unknown kinds | "rejects a body whose `length` overruns it or whose padding isn't all zero. **Every kind is accepted as received**" | `ratchet-receiver-edge-cases` |
| A-016 | run 1 capped at 1,000 per session | "more than 1,000 message keys skipped in one chain is rejected" | none |
| A-019 | run 1 answered offers in every state | decapsulated state: "ignore (stale)" | none |
| A-020 | run 1 rejected duplicate identity keys and names; called the event `readded` | "no two with the same `ownerPub`"; "a re-add is an update" | `group-state-duplicate-identity-key` |
| A-022 | run 1 guessed other JSON shapes | the WIRE_FORMAT appendix gives `skipped`, `pq_offer`, `pq_secret`, `tag_key_in_next` and `previous_in` | `ratchet-skipped-key-state`, `kem-step-offer-pending`, `kem-step-full` |
| A-023 | run 1 put storage mass in the fee | "storage mass has its own limit and doesn't enter the fee" | none (storage mass is 0 there) |
| A-025 | run 1 accepted all-zero X25519 results and skipped the ML-KEM check | both are errors (§1) | `ratchet-reject-low-order-ratchet-key`, `first-contact-reject-low-order`, `kem-step-malformed-offer` |
| B-007 | run 2 drew `mlkem_encaps_m` only *after* the FIPS 203 check passed | format block: "consumes mlkem_encaps_m once it passes the epoch and state checks … and reaches encapsulation, **even if its public key then fails the FIPS 203 check**" | only with a sequential RNG (my harness asserts every given value is consumed) |
| B-009 | run 2 discarded group texts with invalid UTF-8 | "displayed with U+FFFD replacement characters; the message still counts as received. The same applies to group text (0x04)" | none |
| B-011 | run 2 didn't check the publication's tag | "Indexers and clients ignore a publication whose marker differs, whose tag isn't `BLAKE2b-128(… ‖ ownerPub)` …" | none |
| B-019 | run 2 never evicted skipped keys | "deleted 7 days after they were stored" | none (vectors run with a fixed clock) |

(The nine A-entries are the same nine run 2 reported against run 1, with A-022 added now that the appendix states
the shapes. My reading of each matches run 2's.)

### Still open: none

### New findings worth acting on (all medium, no high)

- **C-001: crossing first contacts versus a re-contact.** The lower-tag rule has no trigger condition. Applied to
  a peer who is re-contacting after a restore from the phrase (ratchet sessions can't be restored), it keeps the
  old, dead session half of the time, and messages are then lost without any sign.
- **C-003: §4.1's numbered receive procedure leaves out the skipped-key lookup.** Read literally, a late message
  from an *older* peer ratchet key starts a DH step instead of using its stored key. **No vector delivers such a
  message**, though PROTOCOL_SPEC §5 lists it as tested.
- **C-002: conversation settings (0x06) carry no conversation identifier.** In groups (pairwise fan-out), a
  receiver can't tell which conversation a preference is for, which breaks the §7 promise that "every app computes
  the same effective settings".

---

## Part 1 — Comparison with runs 1 and 2

Status key for **Run 3**: *resolved* = the spec states the answer and I read it as the prior runs did;
*resolved differently* = the spec states an answer that is the opposite of a prior run's recorded decision (which
run is in the note); *still open* = the spec doesn't say. Run 1's column gives run 1's impact rating; run 2's gives
run 2's status (for B-items, its impact).

| ID | Title | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| A-001 | Owner-key label format and validity | low | resolved | resolved: §2 "decimal ASCII without leading zeros … in [1, n − 1]" |
| A-002 | KDF default `len` / `salt` | low | resolved | resolved: §1 "`len` = 32 and `salt` is absent" |
| A-003 | ML-KEM seed split, secret-key encoding | high | resolved | resolved: §1 "`d ‖ z` … KeyGen_internal … 2,400-byte FIPS 203 encoding" |
| A-004 | X25519 secrets raw or clamped | low | resolved | resolved: §1 "raw 32 bytes … clamping happens inside the X25519 function" |
| A-005 | BIP-39 passphrase | medium | resolved | resolved: §2 "with an empty passphrase, always" |
| A-006 | Bundle limits and field meanings | low | resolved | resolved: §3 (nDevices ≤ 20, exact length, Unix seconds, v1 writes 0) |
| A-007 | What the Schnorr signature signs | low | resolved | resolved: §1 "the message `m`, signed as is (not hashed again)" |
| A-008 | Header `flags` byte | medium | resolved differently | resolved differently (vs run 1; = run 2): receivers ignore flags and trailing bytes |
| A-009 | `KDF_RK` split; message key used directly | low | resolved | resolved: §4.1 "(rk = bytes 0..32, ck = bytes 32..64)" |
| A-010 | Eager ratchet key; responder start | medium | resolved | resolved: §4.1 steps (1)–(5), §4.2 Bob's start (see C-003 for the omitted skipped-key step) |
| A-011 | First contact's tag index / N | high | resolved | resolved: §4.2 "message N = 0 … uses no tag index … tag index 0 and header N = 1" |
| A-012 | Name field encoding | medium | resolved differently | resolved differently (vs run 1; = run 2): 1 ≤ len ≤ 20, padding ignored |
| A-013 | Body checks, unknown kinds | medium | resolved differently | resolved differently (vs run 1; = run 2): padding checked, every kind received |
| A-014 | Prekey order, `spkId` check | low | resolved | resolved: §4.2 "current … then his previous one … `spkId` inside must equal" (retention: C-013) |
| A-015 | Tag window size, replays | low | resolved | resolved: §4.1 "at least the next 64 … Interoperability is guaranteed within 64 … Replays are rejected by the window" (counting: C-004) |
| A-016 | Skipped-key limit | low | resolved differently | resolved differently (vs run 1; = run 2): per chain, per message (two-chain case: C-008) |
| A-017 | Offerer's mix point after a new ratchet key | high | resolved | resolved: §4.5 "Where each side mixes" + 7-step sequence |
| A-018 | `pqEpoch` checks | medium | resolved | resolved: §4.5 "Receive rule for `pqEpoch`" |
| A-019 | Re-offers, re-answers, tag-key source | medium | resolved differently | resolved differently (vs run 1; = run 2): state table (malformed offer while pending: C-006) |
| A-020 | Group receive rules | low | resolved differently | resolved differently (vs run 1; = run 2): owner keys only, a re-add is an update |
| A-021 | Settings epoch, latest, default, timer | medium | resolved | resolved: §7 (epoch is now Unix seconds, highest wins, default "timer on", 108,000 s); scope: C-002 |
| A-022 | Harness session-state shapes | low | still open | resolved differently (vs run 1's guessed shapes): now in the WIRE_FORMAT appendix; run 2's "still open" is closed |
| A-023 | Transaction consensus fields | medium | resolved differently | resolved differently (vs run 1; = run 2): Kaspa rules by normative reference, fee excludes storage mass |
| A-024 | Constant marker vs "nothing constant" | low | resolved | resolved: PROTOCOL_SPEC §5 "the one deliberate exception is a bundle publication" |
| A-025 | All-zero X25519, ML-KEM key checks | low | resolved differently | resolved differently (vs run 1; = run 2): both are errors (bundle-key timing: C-012) |
| B-001 | Simultaneous first contacts | — | new (medium) | resolved: §4.2 lower tag kept, loser receive-only for 7 days, never sends. Residual trigger question: **C-001** |
| B-002 | "Rejected" content vs message received | — | new (medium) | resolved: §7 "'Rejected' … refers to the content … the ratchet message itself still counts as received" |
| B-003 | `spkId` = prekey number | — | new (medium) | resolved: §2 "The bundle's `spkId` is this `n`. The first prekey is n = 1" |
| B-004 | Current bundle; future-dated bundles | — | new (low) | resolved: §3 "highest `created` (ties: highest `spkId`); … more than 24 hours in the future are ignored" |
| B-005 | Texts at the removal epoch after a re-add | — | new (low) | resolved: §4.6 "accepted only if the receiver saw the state of the text's epoch and that state lists both" |
| B-006 | KEM due policy | — | new (low) | resolved: §4.5 "counting messages sent and received since this side last offered or answered, and time since then, or since the session started" |
| B-007 | Randomness rule for ignored/malformed offers | — | new (low) | resolved differently (vs run 2's draw order): the format block says a malformed offer consumes `m` |
| B-008 | Relay output covenant; epoch start | — | new (low) | resolved: §5 "no covenant binding"; "epoch E starts at DAA score E × 25,920,000" |
| B-009 | Invalid UTF-8 | — | new (low) | resolved differently (vs run 2's group-text discard): U+FFFD, message received |
| B-010 | Device entries in v1 | — | new (low) | resolved: §3 "v1 senders write `nDevices` = 0; receivers accept 0–20 entries and ignore them" |
| B-011 | Publication tag checked | — | new (low) | resolved differently (vs run 2, which didn't check it): ignored on a wrong tag |
| B-012 | Settings epoch start and "+1" | — | new (low) | resolved: epoch = Unix seconds of the change; first preferences kept whatever their epoch |
| B-013 | Dummy first contact format | — | new (low) | resolved: §4.4 "Dummy first contact" + vector `cover-first-contact` |
| B-014 | Files the spec relies on are missing | — | new (low) | resolved for its two asks (changelog ships; signature script "opaque to clients"). Other referenced files are still absent: C-010 |
| B-015 | rusty-kaspa reference not self-contained | — | new (low) | resolved: commit pinned, "⌈transient mass × 0.5⌉", and "The ID and size layouts are Kaspa's … aren't restated here". I fetched the pinned commit's files; the vector reproduces |
| B-016 | Default-name `n` encoding | — | new (low) | resolved: PROTOCOL_SPEC §3.4 "n ∈ {0, 1, 2} as one byte" |
| B-017 | BIP-39 wordlist, length | — | new (low) | resolved: §2 "English BIP-39 wordlist and has exactly 24 words" |
| B-018 | `root-pq` tied to the re-keyed tag chain? | — | new (low) | resolved: §4.5 "checked independently … receivers don't cross-check them" |
| B-019 | Skipped keys never evicted | — | new (low) | resolved differently (vs run 2's no eviction): deleted 7 days after storage (boundary: C-007) |

**Still open from run 1: 0.**
**Still open from run 2: 0.**
**New in run 3: 14** (0 high, 3 medium, 11 low).

---

## Part 2 — Pins that live only in the vectors

**No wire-format byte is pinned only by the vectors.** Every byte I produce follows from the text, and every
vector matched my reading of it the first time. What the vectors alone settle is harness layout, plus Kaspa
details that the spec delegates to rusty-kaspa:

| Question the text leaves open | Pinned by |
|---|---|
| Harness op names and their result shapes: `encrypt` → `{payload}`, `kem_offer` → `{content}`, `group_state` → `{event, epoch}`, `group_text` → `{text, epoch, older_epoch}` / `{pending: true}`, and `{reject: true}` for group content (the format block's `results` describes only decrypt results; §4.6 leaves reporting to the app) | every session vector; `group-receive-rules` (C-011) |
| Session JSON fields `ad` (= `aliceIdXPub ‖ bobIdXPub` on both sides) and `initiator`, which aren't in the format block's field list | every session vector (C-011) |
| Vectors run with a fixed clock (`now` = 0), so harness `skipped` entries carry no storage time. This is stated only in SPEC_CHANGELOG, not in the spec or the format block | `ratchet-skipped-key-state`, `ratchet-receiver-edge-cases` (C-007) |
| The Kaspa transaction ID is shown in the hash's natural byte order (not reversed) | `transaction-relay-paid` (C-014) |
| The relay input's compute budget (21) and signature script | `transaction-relay-paid` input (the spec calls the script opaque to clients) |

**Rules no vector exercises** (implemented from the text; covered by my `tests/behaviour.rs`). A vector for each
would catch a stale or divergent crate:
- a late message from an older peer ratchet key, decrypted from a skipped key (C-003);
- the 1,000-key skip limit, and skipped-key expiry;
- crossing first contacts as full sessions (the vector checks only the tag comparison), the receive-only window,
  and re-contact (C-001);
- lost answer and re-offer, a late answer to a replaced offer, and late messages across the tag switch;
- a first contact on the previous prekey;
- bundles with devices, `nDevices` > 20, and current-bundle selection;
- a publication with a wrong tag or marker;
- invalid UTF-8 in a group text;
- the KEM due policy;
- a `pqEpoch` jump rejected on a DH step;
- a group removal followed by a re-add.

---

## Part 3 — New findings

### C-001: Crossing first contacts: when does the rule apply, and what happens on a re-contact?

**Spec section:** WIRE_FORMAT §4.2 (crossing), §2

**What the spec says:**
> When two peers each send a first contact at the same time, both end up with two sessions. Both keep the session whose first-contact tag is lower …

and §2:
> the phrase alone must restore everything in any client

**The ambiguity:**
No operational test defines "at the same time". A client that opens a first contact from a peer it already has a
session with can't tell a crossing from a *re-contact*. Ratchet sessions, group states and skipped keys can't be
derived from the phrase, so a client restored from its phrase has to send new first contacts to everyone. If the
peer applies the lower-tag rule to every second session, it keeps the old session whenever the old tag is lower
(about half the time when both first contacts went in the same direction). The restored client no longer has that session, so everything the peer sends is silently
lost, and the new session is "never used to send". The spec also never says how a restored client re-establishes
conversations.

A side note: first-contact tags start with the *recipient's* inbox bucket, so for a given pair the winner is fixed
by which inbox bucket is lower. That is deterministic and fine, but not obvious.

**What I decided:**
It is a crossing only if our current session with that peer is one we initiated and has received nothing yet
(`PeerSessions::on_first_contact_received`). Otherwise the new first contact replaces our session, and the old one
stays receive-only for the 7-day window. Tested: `crossing_first_contacts`,
`recontact_after_restore_replaces_the_old_session`.

**What would make it certain:**
"The crossing rule applies when a first contact arrives from a peer to whom we sent a first contact and from whom
we have received nothing on it. Any other first contact from a known peer replaces the existing session (the old one
is receive-only for 7 days)." Add a restore/re-contact vector.

**Impact:** medium. Both behaviours are honest readings, and mixing them loses messages silently after a restore.

---

### C-002: Conversation settings (0x06) carry no conversation or group identifier

**Spec section:** WIRE_FORMAT §7 (0x06), §4.6; PROTOCOL_SPEC §8.1

**What the spec says:**
> Conversation settings (each member's own preferences): `version=1 u8 ‖ epoch u32 ‖ flags u8` … a receiver keeps, per member, only the preferences with the highest epoch … Every app computes the same effective settings: the timer … is off only if every member is Plus and every member wants it off

**The ambiguity:**
"Every member" implies conversations with more than two members, meaning groups. But groups travel over pairwise
sessions (§4.6), and a 0x06 body has no `groupId`. A receiver that gets Bob's preferences over their pairwise
session can't tell whether they apply to the 1:1 conversation, to group G, or to every conversation shared with Bob.
One app may apply them to groups and another only to the 1:1 chat. Their effective timers then differ, which is
exactly what §7 says can't happen, and the timer is a deletion guarantee (PROTOCOL_SPEC §8.1).

**What I decided:**
A 0x06 body applies to the 1:1 conversation of the session it arrives on. v1 defines no group settings carrier.
`settings::effective` takes whatever member list the app supplies.

**What would make it certain:**
Either "0x06 applies only to the pairwise conversation; group conversations use …", or a v1 group variant (for
example `groupId (16)` after `version`, marked with a new version value).

**Impact:** medium.

---

### C-003: §4.1's receive procedure omits "try skipped keys first"

**Spec section:** WIRE_FORMAT §4.1 (eager steps, skipped keys), §4.5 (`pqEpoch` receive rule)

**What the spec says:**
> On a header whose `ratchetPub` differs from the current peer key, the receiver (1) stores the skipped keys of the current receiving chain up to `PN`, (2) sets `PN = Ns, Ns = Nr = 0`, (3) derives the receiving chain … (4) generates a new ratchet key pair at once and (5) derives the sending chain …

and §4.5:
> headers on known chains and from skipped keys are not checked

**The ambiguity:**
A late message from the peer's *previous* DH chain has a `ratchetPub` that differs from the current peer key. Read
literally, the numbered rule then runs a DH step. Signal's algorithm (which §4.1 names) tries the stored skipped
key first. The only textual hint of that order is the aside in §4.5. An implementation that follows the numbered
rule literally computes a wrong chain, the AEAD fails, and the message is rejected with the session unchanged. Its
late messages are lost, while a Signal-order peer delivers them. **No vector exercises this.** I instrumented every
vector: the only skipped key any vector uses is on the current chain (`ratchet-out-of-order`), even though
PROTOCOL_SPEC §5 test 4 says "including a late message from a previous ratchet chain".

**What I decided:**
Signal's order: look up (ratchetPub, N) among the skipped keys first, then the DH step, then skip within the chain.
Tested in `kem_late_message_across_tag_switch`.

**What would make it certain:**
Add step (0) to §4.1: "If (ratchetPub, N) is a stored skipped key, use it (no other state changes)", and add a vector
with a late message from an older peer ratchet key.

**Impact:** medium. Nothing breaks permanently, but out-of-order delivery (a stated feature) differs between
readings, and no vector catches it.

---

### C-004: Does the 64-index window count only unreceived indices?

**Spec section:** WIRE_FORMAT §4.1 (tag window)

**What the spec says:**
> receivers MUST watch at least the next 64 unreceived tag indices of each incoming chain … Interoperability is guaranteed within 64.

**The ambiguity:**
Take `tag_in` = 0 with indices 1–10 already received. Is the watched set {0, 11, …, 73}, the next 64 *unreceived*
indices, or {0, …, 63} minus the received ones (54 indices)? A sender at index 70 is inside the window under the
first reading and outside it under the second.

**What I decided:**
The literal reading: 64 unreceived indices, skipping received ones (`session::window`, test
`tag_window_is_64_unreceived_indices`).

**What would make it certain:**
"the 64 lowest indices ≥ `tag_in` that have not been received".

**Impact:** low (it matters only after gaps and out-of-order arrival).

---

### C-005: What counts as "Plus" when computing effective settings

**Spec section:** WIRE_FORMAT §7 (0x06); PROTOCOL_SPEC §8.1, §8.2

**What the spec says:**
> the timer … is off only if every member is Plus and every member wants it off; screenshot protection is on if any Plus member switched it on. … Tiers come from the registry, never from the message.

**The ambiguity:**
The registry stores an expiry in DAA score, and a name keeps a 30-day grace period (§8.2). The spec doesn't say
whether a member in grace counts as Plus, or which clock decides (the local clock, or the DAA score of the latest
block). Two apps checking at the same moment can disagree.

**What I decided:**
The caller passes `plus: bool` per member (as the vector does). No expiry policy lives in the library.

**What would make it certain:**
"A member is Plus while the current DAA score is below its expiry (grace excluded / included)."

**Impact:** low.

---

### C-006: Responder with a pending offer receives a *malformed* offer

**Spec section:** WIRE_FORMAT §4.5 (state table)

**What the spec says:**
> offer pending | … | responder: drop our offer and answer it

and
> An offer whose ML-KEM public key fails the FIPS 203 check is a malformed step: received, ignored, no answer.

**The ambiguity:**
If the peer's crossing offer is malformed, does the responder still drop its own pending offer (the table's action
runs first), or is the malformed offer ignored entirely, so its own offer stays? The harness rule (`m` is consumed
"once it passes the epoch and state checks") suggests the state checks come before the FIPS check.

**What I decided:**
"Ignored" means no state change: the responder keeps its own offer. `m` is still drawn, per the harness rule.

**What would make it certain:**
One sentence: "a malformed offer changes no state (a pending offer is kept)."

**Impact:** low (a peer that sends malformed offers is non-conforming).

---

### C-007: Skipped-key expiry: the boundary, the clock, when it runs, and the harness clock

**Spec section:** WIRE_FORMAT §4.1; SPEC_CHANGELOG 2026-09-29

**What the spec says:**
> Skipped keys are kept … until used, **and deleted 7 days after they were stored**

**The ambiguity:**
- Is a key used at exactly 7 days still valid?
- Which clock stamps it (local receipt time)?
- When does deletion run?
- The vectors' fixed clock (`now` = 0) is stated only in the changelog ("vectors run with a fixed clock"). Neither
  the spec nor the format block says it, and harness `skipped` entries have no time field.

**What I decided:**
Local Unix time at storage. The key is deleted once `now − stored_at ≥ 604,800`. Expiry runs at every decrypt.
The harness uses `now` = 0 and `stored_at` = 0.

**What would make it certain:**
State the boundary. Move the fixed-clock rule into the format block.

**Impact:** low.

---

### C-008: The skip limit when one message skips on two chains; no total cap

**Spec section:** WIRE_FORMAT §4.1

**What the spec says:**
> a message that would need more than 1,000 message keys skipped in one chain is rejected

**The ambiguity:**
A message that starts a DH step skips on the old chain (up to `PN`) *and* on the new chain (up to `N`). Is the
limit per chain (up to 2,000 for one message) or per message? There's also no cap on the total number of stored
keys (only the 7-day expiry), so a peer can make a receiver store about 1,000 keys per DH step.

**What I decided:**
Per chain, as written: each of the two skips may be up to 1,000. No total cap.

**What would make it certain:**
"… in either chain" or "in total", plus an optional total cap.

**Impact:** low.

---

### C-009: Unknown version and type bytes outside 0x06

**Spec section:** WIRE_FORMAT §3, §4, §4.5, §4.6

**What the spec says:**
> Every payload starts `ver=0x01` … Clients may support several versions side by side.

and §7 (0x06 only):
> any other length or version is rejected

**The ambiguity:**
The spec says only for settings what a receiver does with an unknown version: bundle `ver`, group state/text
`ver=1`, KEM step type bytes other than 0x01/0x02, and payload `ver` ≠ 0x01. For payloads, "reject" and "ignore"
differ only in wording. For a KEM step, an unknown type is plausibly "malformed: received, ignored".

**What I decided:**
Bundles and group bodies with `ver` ≠ 1 are invalid (content discarded). A KEM body of any other type or length
is a malformed step (received, ignored). A payload with `ver` ≠ 0x01 isn't processed.

**What would make it certain:**
One line per structure, or a general rule: "unknown versions are ignored like unknown kinds".

**Impact:** low.

---

### C-010: Files the spec points at that the package doesn't include

**Spec section:** WIRE_FORMAT header, §5; PROTOCOL_SPEC §3.3, §8.4, §10

**What the spec says:**
> Reference implementation: `protocol/src/`. … `node --test protocol/test/*.test.ts` checks ours

and
> the redeem script of `contracts/treasury_hot.sil` (published with the contracts)

**The ambiguity:**
These files are named but not shipped: `protocol/src/`, `protocol/test/`, `contracts/treasury_hot.sil`,
`contracts/registry_shard.sil`, `contracts/reservoir.sil`, `tools/lanecheck/`, `tools/ceremony`,
`docs/LESSONS_AND_RISKS.md`, `docs/MARKETING_NOTES.md`, `registry/reserved/*`, `bouncer/*`. None is needed for
messaging interop. The relay's signature script is called opaque, and the vector supplies it.

**What I decided:**
Built from the six files. I didn't look for the missing ones.

**What would make it certain:**
Mark which referenced files are informative only.

**Impact:** low.

---

### C-011: Harness `format` block gaps

**Spec section:** WIRE_FORMAT appendix; vectors `format`

**What the spec says:**
> It defines the encoding …, the vector shape …, the names and consumption order of every random input, the session-state layout, and the result shapes.

**The ambiguity:**
- The block describes only decrypt results. It never names the ops (`encrypt`, `decrypt`, `kem_offer`,
  `group_state`, `group_text`) or their result shapes.
- Its session-state field list omits `ad` and `initiator`.
- The order of `skipped` entries (insertion or sorted) isn't given, and no vector has more than one entry.

**What I decided:**
Inferred everything from the vectors (Part 2). `skipped` is kept in insertion order (the order keys are derived).

**What would make it certain:**
List the ops and result shapes, add `ad` and `initiator`, and state the `skipped` order.

**Impact:** low (harness only).

---

### C-012: When is a bundle's ML-KEM key checked?

**Spec section:** WIRE_FORMAT §1, §3

**What the spec says:**
> Encapsulation keys are checked as FIPS 203 §7.2 requires; a key that fails is an error.

and §3:
> **The current bundle** of an owner is the valid bundle with the highest `created`

**The ambiguity:**
Is a bundle whose `spkKemPub` fails the check invalid, so that "current bundle" falls back to an older valid one?
Or does it verify (signature and registry) and only fail at encapsulation, so the sender can't make contact? The
two give different outcomes for the same published data.

**What I decided:**
Checked at encapsulation (`first_contact::send` fails). `Bundle::accept` checks structure, owner and signature,
as §3 lists.

**What would make it certain:**
"A bundle whose ML-KEM key fails the FIPS 203 check is invalid (§3)."

**Impact:** low (only the owner can sign a bundle).

---

### C-013: How long a previous prekey is honoured

**Spec section:** WIRE_FORMAT §2, §4.2; PROTOCOL_SPEC §3.1

**What the spec says:**
> He tries his current signed prekey, then his previous one

and PROTOCOL_SPEC §3.1:
> rotated about every 7 days

**The ambiguity:**
Only n − 1 is tried, and the rotation interval isn't normative. A first contact made to a bundle that is two
rotations old, for example one fetched just before two quick rotations within the 7-day delivery window, fails
silently. It's also not said whether a client may rotate faster than the delivery window.

**What I decided:**
Try exactly the current prekey and n − 1.

**What would make it certain:**
"Clients rotate no more often than every 7 days", or "keep every prekey whose successor is younger than 7 days".

**Impact:** low.

---

### C-014: Transaction vector: `previous_txid` byte order and fee wording

**Spec section:** WIRE_FORMAT §5; vector `transaction-relay-paid`

**What the spec says:**
> minimum fee: 100 sompi × max(compute mass, normalized transient mass = ⌈transient mass × 0.5⌉)

The vector description says "normalized transient mass = transient_mass / 2".

**The ambiguity:**
- The input's `previous_txid` is all 0x11, so the vector can't show whether hex txids are in natural or reversed
  byte order on input. The output ID shows natural order.
- The two fee formulas agree, because transient mass (4 × size) is always even.

**What I decided:**
Natural byte order throughout (Kaspa's `Hash`), and the spec's ceiling.

**What would make it certain:**
Use an asymmetric `previous_txid` in the vector, and align its description with §5.

**Impact:** low (relay builders use Kaspa's libraries; messaging clients never need this).

---

## Summary

**Totals:** 14 new findings: 0 high, 3 medium (C-001, C-002, C-003), 11 low. Still open from run 1: 0. Still open
from run 2: 0. Resolved differently: 13 (9 vs run 1, the same as run 2's reading; 4 vs run 2), each because the
text now pins the opposite of a prior decision, never because the text is ambiguous.

**The three that worry me most:**
1. **C-001:** the crossing rule has no trigger. After a restore from the phrase, a peer that applies it literally
   can keep the dead session (about half the time), and messages vanish without error.
2. **C-003:** §4.1's receive steps omit the skipped-key lookup, and no vector delivers a late message from an older
   peer ratchet key. That is the one out-of-order path with no byte-level check.
3. **C-002:** 0x06 has no conversation identifier, so group apps can compute different deletion timers.

**Where I trusted the vectors over the spec:** nowhere. No vector contradicted the text, and every vector passed the
first time. The closest cases:
- For the transaction ID, size and masses, which the spec deliberately delegates to rusty-kaspa, I implemented from
  the rusty-kaspa sources (the pinned commit) and the vector confirmed them.
- For the fee wording (C-014), I followed the spec's ceiling. The number is the same.
- Harness layout (op names, result shapes, `ad` and `initiator`) comes from the vectors only (Part 2).

**Places where the spec contradicts itself or is in tension:**
- §2 "the phrase alone must restore everything in any client" versus sessions, group states and skipped keys, which
  can't be restored from the phrase. This is the root of C-001.
- §4.1's literal eager-step rule versus §4.5's "headers … from skipped keys are not checked" and "Signal double
  ratchet" (C-003).
- PROTOCOL_SPEC §4 "Old keys are deleted immediately" versus WIRE_FORMAT §4.1, which keeps skipped keys up to 7 days.
  This is a softened tension, now bounded.
- PROTOCOL_SPEC §5's payload layout "`ver(1) ‖ tag(16) ‖ ephemeral(32) ‖ ciphertext(…) ‖ pad`" versus §4.1, where an
  ongoing message has no padding and the 32-byte field is "random". The naming is loose; no bytes differ.
- The vector description's "transient_mass / 2" versus §5's "⌈transient mass × 0.5⌉" (identical results).
