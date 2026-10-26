# Kaspaveil wire format — protocol version 1 (draft)

Byte-exact rules for interoperable clients and indexers. The package is this file, `PROTOCOL_SPEC.md`, `docs/SPEC_CHANGELOG.md` and `protocol/vectors/v1.json`; every other file either document names (reference code, contracts, tools, other docs) is informative only and not needed to implement messaging. Every change to this document or to the vectors is recorded in `docs/SPEC_CHANGELOG.md`, which ships with this document and the vectors as one package. Reference implementation: `protocol/src/`. Test vectors: `protocol/vectors/v1.json` (every implementation must reproduce them byte for byte; `node --test protocol/test/*.test.ts` checks ours).

All integers are big-endian. `‖` is concatenation. `BLAKE2b(x)` is BLAKE2b-256 (32-byte output). `BLAKE2b-128(x)` is BLAKE2b with its **output-length parameter set to 16 bytes**. That is a different hash, not the first 16 bytes of BLAKE2b-256 (BLAKE2b's output length is part of its parameter block). `X[0..n]` is truncation.

## 1. Primitives

| Use | Primitive |
|---|---|
| Owner key (registry, bundle signatures) | secp256k1 Schnorr (BIP-340), 32-byte x-only public key — the same scheme Kaspa covenants check |
| Key agreement | X25519 (RFC 7748). Secret keys are the raw 32 bytes as derived or drawn; clamping happens inside the X25519 function, never in stored keys. An all-zero X25519 result (a low-order peer key) is an error: the payload or step using it is rejected. |
| Post-quantum KEM | ML-KEM-768 (FIPS 203): public key 1,184 B, ciphertext 1,088 B. A 64-byte seed means `d ‖ z` (32 bytes each) for `ML-KEM.KeyGen_internal(d, z)` (FIPS 203 Alg. 16); a secret key is the 2,400-byte FIPS 203 encoding; encapsulation takes the 32-byte `m` of `ML-KEM.Encaps_internal`. Encapsulation keys are checked as FIPS 203 §7.2 requires; a key that fails is an error. |
| AEAD | XChaCha20-Poly1305, **24-byte zero nonce** (every key is used exactly once) |
| KDF | `KDF(ikm, label, len, salt) = HKDF-SHA-256(ikm, salt, "kasveil/v1/" ‖ label, len)`. When omitted, `len` = 32 and `salt` is absent (HKDF's default: 32 zero bytes). |
| Hash | BLAKE2b |
| Signatures | BIP-340: the 32-byte digest named in each section is the message `m`, signed as is (not hashed again); `aux_rand` is 32 fresh random bytes (vectors give it explicitly). |

**Label prefix (Kaspaguy, 2026-09-29).** The labels use the protocol's working name, `kasveil`, and keep it permanently: they are internal constants, and renaming them would change every derived byte (a new protocol version). The protocol itself is called Kaspaveil.

**Label versioning policy.** Every KDF label, hash domain string and bundle/tag label starts with `kasveil/v1/`. A v1 label is never reused with a different meaning or input layout. Any change to a derivation, layout or primitive is a new protocol version: payload version byte `0x02` and labels prefixed `kasveil/v2/`. Clients may support several versions side by side. **Test vectors (Kaspaguy, 2026-09-29):** once a v1 test-vector set is published, it is frozen and never regenerated. Before publication, a draft may add new sections as long as every existing entry stays byte-identical; any change to an existing entry is a new protocol version.

## 2. Keys from the recovery phrase

- `seed` = BIP-39 seed (64 bytes) of the 24-word phrase, **with an empty passphrase, always**: the phrase alone must restore the identity and every key in any client. (Sessions, group states and skipped keys are not derivable from the phrase: a restored client re-establishes conversations with new first contacts, §4.2.) The phrase uses the English BIP-39 wordlist and has exactly 24 words; clients reject any other length or a failed checksum.
- `ownerSk` = first `KDF(seed, "owner/i")`, i = 0, 1, …, that is a valid secp256k1 secret key: `i` is written in decimal ASCII without leading zeros (`owner/0`, `owner/1`, …), and a candidate is valid if, read as a big-endian integer, it is in [1, n − 1].
- `idX` = X25519 key with secret `KDF(seed, "id-x25519")`.
- Signed prekey number `n`: X25519 secret `KDF(seed, "spk-x25519", 32, u32(n))`; ML-KEM-768 keypair from the 64-byte seed `KDF(seed, "spk-mlkem", 64, u32(n))` (`d ‖ z`, §1). **The bundle's `spkId` is this `n`.** The first prekey is n = 1; each rotation increments it; the "previous" prekey (§4.2) is n − 1. A client restored from the phrase reads its current `spkId` from its latest published bundle and derives both keys.
- There is **no identity ML-KEM key**: as in Signal's PQXDH, only the signed prekey carries a KEM key. (A 1,184-byte identity KEM key would also stop the bundle fitting in one message.)

## 3. Key bundle

```
ver=1 (1) ‖ ownerPub (32) ‖ idXPub (32) ‖ spkId u32 (4) ‖ spkXPub (32) ‖ spkKemPub (1184)
‖ created u64 (8) ‖ nDevices u8 (1) ‖ devices (32 × n) ‖ signature (64)
```
Signature = Schnorr over `BLAKE2b("kasveil/v1/bundle" ‖ everything before the signature)`. 1,358 bytes with no devices; up to 4 devices fit in one payload. `created` is a Unix time in seconds. Each device entry is a 32-byte key reserved for linked devices (PROTOCOL_SPEC §7): v1 senders write `nDevices` = 0; receivers accept 0–4 entries and ignore them, and reject `nDevices` > 4. A bundle whose `ver` isn't 1, or whose ML-KEM key fails the FIPS 203 check (§1), is invalid (vector `bundle-reject-bad-mlkem-key`). **The current bundle** of an owner is the valid bundle with the highest `created` (ties: highest `spkId`); bundles dated more than 24 hours in the future are ignored. A standalone bundle is exactly `1,358 + 32 × nDevices` bytes; inside a §4.3 payload its length comes from `nDevices`, and the zero padding after it is ignored.

Clients accept a bundle only if `ownerPub` equals the owner the registry maps the name to and the signature verifies. **The bundle tag (§4.3) is only a routing hint** so indexers can find bundles; it authenticates nothing, since anyone can publish a payload with any tag. Authentication comes solely from the signature and the registry's owner key.

## 4. Payloads (always exactly 1,536 bytes, on the Kaspaveil lane)

Every payload starts `ver=0x01 ‖ tag (16) ‖ field (32)`. The rest depends on type; to an observer every type is 1,536 random-looking bytes.

### 4.1 Ongoing message (double ratchet)
```
0x01 ‖ tag (16) ‖ random (32) ‖ headerCt (64) ‖ bodyCt (1935)
```
- `tag = BLAKE2b-128(tagKey ‖ u32(i))`, where `tagKey` is the sender's direction key and `i` is the sender's tag counter (0, 1, 2, …).
- `random`: 32 fresh bytes from a cryptographically secure random generator. **Receivers ignore it.** It must never be derived from any key, counter or session state (that could link messages or leak secrets); it exists only so every payload type has the same shape.
- Header plaintext (48 B): `ratchetPub (32) ‖ PN u32 ‖ N u32 ‖ flags u8 ‖ pqEpoch u32 ‖ 3 zero bytes`, where `pqEpoch` is the latest KEM epoch mixed into the root key behind the sender's current sending chain (0 until the first KEM step, §4.5). **`flags` and the 3 trailing bytes are reserved in v1: senders write 0; receivers ignore them.** (The optional "signed" flag of PROTOCOL_SPEC §4 is not in the v1 wire format yet.) The header is sealed with `KDF(tagKey, "header", 32, u32(i))`, AD = `tag`.
- Body plaintext (1,407 B): `kind u8 ‖ length u16 ‖ content ‖ zero padding`, sealed with the ratchet message key, AD = `sessionAD ‖ headerCt`. Maximum content: **1,404 bytes**. A receiver rejects a body whose `length` overruns it or whose padding isn't all zero. **Every kind is accepted as received** (the tag window moves on); kinds a client doesn't know, including 0x00, 0x02 and 0x09–0xFF, are ignored by the app, never rejected, so a future kind can't stall an older receiver.
- Ratchet: Signal double ratchet. `KDF_RK(rk, dh) = KDF(dh, "root", 64, rk)` → (rk = bytes 0..32, ck = bytes 32..64); `KDF_CK(ck)`: next chain key `HMAC-SHA256(ck, 0x02)`, message key `HMAC-SHA256(ck, 0x01)`. The 32-byte message key is the XChaCha20-Poly1305 key itself (no further derivation).
- **Receive order:** (0) if (`ratchetPub`, `N`) names a stored skipped key, decrypt with it and delete it; nothing else in the session changes (this is how a late message from an older peer ratchet key is read; vector `ratchet-late-from-older-ratchet-key`). Otherwise:
- **Ratchet steps are eager.** On a header whose `ratchetPub` differs from the current peer key, the receiver (1) stores the skipped keys of the current receiving chain up to `PN`, (2) sets `PN = Ns, Ns = Nr = 0`, (3) derives the receiving chain `KDF_RK(rk, X25519(ourRatchet, theirNewPub))`, (4) **generates a new ratchet key pair at once** and (5) derives the sending chain `KDF_RK(rk, X25519(ourNewRatchet, theirNewPub))`, then skips to `N` and decrypts. The responder's session starts the same way (§4.2).
- **Skipped keys:** a message that would need more than 1,000 message keys skipped in either chain it touches (the old chain up to `PN`, the new chain up to `N`) is rejected (session unchanged); there is no cap on the total stored, which the 7-day expiry bounds. Skipped keys are kept, keyed by (sender ratchet key, N), until used, **and deleted 7 days after they were stored** (the delivery window, PROTOCOL_SPEC §8.1; stamped with the receiver's local clock when stored; a key is gone once 7 days or more have passed, so it can't be used at exactly 7 days; expiry runs at least before every decrypt): a message that hasn't arrived by then can't be fetched any more, and a key kept longer would only help someone who later compromises the device. An expired key is deleted with no other effect; a message that needed it is rejected like any other that can't be decrypted.
- **Tag window:** receivers MUST watch the indices `tag_in` … `tag_in` + 63 of each incoming chain that haven't been received yet (the current chain; after a KEM secret is known, the peer's re-keyed chain from index 0; and the previous chain, §4.5), and MAY widen the window up to 1,000 (the skipped-key limit) to recover after a gap. Interoperability is guaranteed for a sender whose index is below `tag_in` + 64; a receiver MAY watch further. **Replays are rejected by the window:** once an index is received it is no longer watched. **Tag counters** run per direction across DH ratchet steps; they restart at 0 only when a KEM step re-keys the chain. Senders MUST NOT advance their tag counter without broadcasting: a failed broadcast is retried with the *same* payload, so a sender never leaves a hole the receiver can't see across.

### 4.2 First contact (PQXDH-style)
```
0x01 ‖ tag (16) ‖ ephemeralPub (32) ‖ kemCt (1088) ‖ sealedCt (399)
```
Alice → Bob, with Bob's bundle:
- `DH1 = X25519(aliceIdX, bobSpkX)`, `DH2 = X25519(eph, bobIdX)`, `DH3 = X25519(eph, bobSpkX)`, `(kemCt, SS) = ML-KEM.Encaps(bobSpkKem)`.
- `tag = BLAKE2b-128("kasveil/v1/fc-tag" ‖ DH2)` with its first 12 bits replaced by Bob's **inbox bucket** `= first 12 bits of BLAKE2b("kasveil/v1/inbox" ‖ bobIdXPub)`.
- `sealedCt` = AEAD under `KDF(DH2 ‖ SS, "fc-outer")`, AD = `tag`, of 383 bytes (the name field is `len u8 ‖ UTF-8 name ‖ 0x00 × (20 − len)`, 1 ≤ len ≤ 20; receivers reject another `len` and ignore the padding):
  `0x01 ‖ name field (1 + 20) ‖ aliceOwnerPub (32) ‖ aliceIdXPub (32) ‖ spkId u32 ‖ aliceRatchetPub (32) ‖ innerCt (261)`.
- `SK = KDF(0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ SS, "pqxdh")`; session AD = `aliceIdXPub ‖ bobIdXPub`.
- Alice's ratchet starts with `(rk, ck) = KDF_RK(SK, X25519(aliceRatchet, bobSpkX))`; message 0 is `innerCt` (245-byte body, max content **242 bytes**) under that chain's first message key, AD = `sessionAD ‖ aliceRatchetPub`. **The first contact is message N = 0 of Alice's first sending chain and uses no tag index**: afterwards Alice has `Ns = 1` and her first ongoing message has tag index 0 and header N = 1.
- Bob's ratchet starts with his signed prekey's X25519 key as his first ratchet key: receiving chain `KDF_RK(SK, X25519(bobSpkX, aliceRatchetPub))` (message 0 decrypts `innerCt`, so `Nr = 1`), then at once a new ratchet key pair and his sending chain `KDF_RK(rk, X25519(bobNewRatchet, aliceRatchetPub))`.
- Tag keys: initiator→responder `KDF(SK, "tag-i2r")`, responder→initiator `KDF(SK, "tag-r2i")`.
- The inner body's kind must be 0x01 (text), 0x03 (group state) or 0x04 (group text): a group member reaches a fellow member it has no session with by a first contact carrying the group message, or, when the message doesn't fit, by a first contact opening the session followed by the message (§4.6). Receivers reject any other kind. **A text of length 0 in a first contact only opens the session**: apps don't show it.
- Clients rotate their signed prekey no more often than every 7 days (the delivery window), so the current and previous prekeys together cover every first contact still being delivered.
- Bob scans his inbox bucket: `X25519(bobIdX, eph)` must reproduce the tag. He tries his current signed prekey, then his previous one, and takes the first whose `sealedCt` opens with record type 0x01; the `spkId` inside must equal that prekey's id, or the first contact is rejected. He then checks the claimed name against the registry (owner key and bundle identity key must both match), and only then decrypts `innerCt`.
- **Crossing first contacts, and re-contact after a restore (Kaspaguy, 2026-09-30).**
  - The lower-tag rule applies only when both sides have a pending outgoing first contact to each other — that is, we sent a first contact to that peer and have received nothing on it yet (our current session with that peer is one we initiated and its receiving chain doesn't exist yet). In that case, both sides keep the session whose first-contact tag is lower (the 16-byte tags compared bytewise as unsigned big-endian numbers, computable independently by both sides), and the other session becomes receive-only for 7 days, then discarded entirely (keys included). Vector `first-contact-crossing`.
  - Any other first contact from a known peer (one we hold a session with) replaces our session. This covers the case of a peer that restored its device from the recovery phrase: it has no sessions, so it sends a new first contact, and the receiving side cannot distinguish that from a crossing. The receiving side treats it as a re-contact: the new session becomes the active one, and the old session becomes receive-only for 7 days, then discarded. Messages the peer sent from its old device before the restore can still arrive on the old session, which is why it stays receive-only, so nothing in flight to us is lost. (The restored peer has no copy of the old session: the phrase restores identity and keys, not sessions, so anything we sent on the old session that its old device never received can't be read.) Vector `first-contact-recontact`.
  - A receive-only session is never used to send (including KEM offers and answers). Messages received on it are attributed to the conversation as normal. It is discarded, keys included, when the 7-day delivery window ends.
- **Replayed first contacts (Kaspaguy, 2026-09-30).** A receiver remembers the tag of every first contact it has processed, for as long as it keeps the prekey that opened it. A first contact whose tag has already been seen is dropped without changing any state. A re-posted first contact carries the same tag (it is derived from the ephemeral key and the recipient's identity key, both unchanged), so a third party re-posting an old first contact on-chain cannot cause the receiver to replace a working session with one the sender does not have. Retention is bounded by the prekey's retention: when the prekey is rotated out, the tag is forgotten, and a first contact that old can no longer be decrypted anyway. "Processed" means opened: every check above passed. A payload that carries a first contact's tag but fails a check is not remembered, so a forged payload copying a genuine first contact's tag (which is visible on-chain) can't get the genuine one dropped. Vector `first-contact-replay`.
- **Scan cost.** Bob can't tell a first contact from any other payload in his inbox bucket, so he runs one X25519 per payload there; ML-KEM decapsulation (at most two) runs only on a tag match. The inbox bucket carries about 1/4,096 of all lane traffic. Measured on 2026-09-29 in pure JavaScript (`@noble`, server CPU): X25519 ≈ 1.7 ms, ML-KEM-768 decapsulation ≈ 1.0 ms. So:
  - 1 million lane messages/day → ~244 per bucket → **~0.4 s of work a day**;
  - 100 million/day → ~24,400 per bucket → **~41 s a day** (a few minutes on a slow phone in JavaScript; native code is several times faster).
  - If traffic ever outgrows that, v2 can widen the inbox bucket to 16 bits (65,536 buckets).

**Stated openly:** first-contact *routing* (the tag and inbox bucket) is classical X25519. The sender's identity, the name and the text sit inside `sealedCt`, which needs the ML-KEM secret too, so they stay confidential against a future quantum computer. A quantum attacker could learn only that *someone* sent a first contact to a given recipient.

### 4.3 Bundle publication
```
0x01 ‖ BLAKE2b-128("kasveil/v1/bundle-tag" ‖ ownerPub) ‖ BLAKE2b("kasveil/v1/bundle-marker") ‖ bundle ‖ zero padding
```
Bundles are public directory data, so this payload is recognisable on purpose. Indexers and clients ignore a publication whose marker differs, whose tag isn't `BLAKE2b-128("kasveil/v1/bundle-tag" ‖ ownerPub)` for the bundle inside it, or whose bundle doesn't verify (§3).

### 4.4 Cover traffic
`0x01 ‖ 1,535 random bytes`. Nobody can read it; indistinguishable from 4.1.

**Dummy first contact** (cover traffic into an inbox bucket, PROTOCOL_SPEC §1): `0x01 ‖ withBucket(16 random bytes, bucket) ‖ X25519 public key of a random secret ‖ 1,487 random bytes`, where `withBucket` replaces the first 12 bits with the bucket. Nobody can read it; shaped like §4.2 (vector `cover-first-contact`).

### 4.5 Post-quantum KEM ratchet step (body kind 0x05)
Two ordinary ratchet messages (§4.1) whose body kind is `0x05`. The body content is one of:
```
offer:  0x01 ‖ epoch u32 ‖ mlkemPub (1184)                                  1,189 B
answer: 0x02 ‖ epoch u32 ‖ offerId (16) ‖ mlkemCt (1088)                     1,109 B
offerId = BLAKE2b-128("kasveil/v1/kem-offer" ‖ mlkemPub)
```
- **Offer.** Either side, when a step is due (at least every 50 messages or 24 hours: counting messages sent and received since this side last offered or answered, and time since then, or since the session started), generates an ML-KEM-768 key pair from 64 fresh random bytes (`d ‖ z`, §1) and sends the public key with `epoch = pqEpoch + 1`. Re-sending an offer (e.g. after a lost answer) replaces the previous one; `offerId` makes an answer to a replaced offer recognisable, and it is ignored.
- **Answer.** The receiver of a valid offer (`epoch = its pqEpoch + 1`) encapsulates to the public key and returns the ciphertext. **Crossing offers:** if both sides offer the same epoch, the session initiator's offer wins; the responder discards its own offer and answers, and the initiator ignores the responder's offer.
- **Tag chains re-keyed.** As soon as a side knows the shared secret `SS` (the answerer at encapsulation, the offerer at decapsulation), it also watches the peer's re-keyed tag chain `tagKey' = KDF(tagKey ‖ SS, "pq-tag")`, starting at index 0. A side switches its own outgoing tag key the same way (and restarts its counter at 0) at the moment it mixes `SS` into its root key. The first message received on the new chain retires the old one to "previous", which stays watched for late messages until the next step.
- **Root key.** `SS` enters the root key exactly once, at a step both sides can identify: the **first sending chain the offerer creates after it has decapsulated** uses `KDF(dh ‖ SS, "root-pq", 64, rk)` in place of the usual `KDF(dh, "root", 64, rk)`, and messages on it carry `pqEpoch = epoch` in the header.
  - **Where each side mixes (Kaspaguy, 2026-09-29):** when the offerer receives the answer on a message that also carries a new ratchet key, the sending chain created by that message's DH step is normal. `SS` is mixed into the next sending chain the offerer creates, which is the one produced by the next DH ratchet step. The answerer applies `root-pq` to the receiving chain created when the offerer's first re-keyed message arrives.
  - **In short (Kaspaguy, 2026-09-29):** `pqEpoch` advances only when a party mixes `SS` into a chain, not when it sends an offer or encapsulates an answer. Until it mixes, its headers carry the old epoch. When a party mixes, it re-keys its outgoing tag chain; the peer does the same on its side. **Each party starts watching the peer's re-keyed chain as soon as it knows `SS`** (the answerer on encapsulating, the offerer on decapsulating), not at its own mix: the answerer's mix is triggered by the first message on the offerer's re-keyed chain, so it must already be watching that chain.
  - **The full sequence** (Alice offers, Bob answers; both start at `pqEpoch = E − 1`, and **`pqEpoch` changes only at the moment a side mixes `SS`**; checked against `kem-step-full`, where Alice mixes at step 8 and Bob at step 10):
    1. **Offer.** Alice sends the offer for epoch E. She keeps the ML-KEM seed as a pending offer; her `pqEpoch` stays E − 1, her root key and tag chains are unchanged.
    2. **Answer.** Bob receives the offer, encapsulates (`mlkemCt`, `SS`) and sends the answer. He holds `SS` to mix on receive; his `pqEpoch` stays E − 1. From now on he also watches Alice's re-keyed tag chain `KDF(tagKeyIn ‖ SS, "pq-tag")` from index 0. His own outgoing tag chain is unchanged.
    3. **Alice receives the answer.**
       - 3a. *No new ratchet key:* she decrypts on her current receiving chain and decapsulates. She now holds `SS` to mix on send. Nothing is mixed yet.
       - 3b. *New ratchet key:* the DH step runs first (§4.1) and creates a **normal** receiving chain and a **normal** sending chain, because `SS` isn't known yet. Then the body is decrypted and she decapsulates: she now holds `SS` to mix on send.
       - Either way she now also watches Bob's re-keyed tag chain from index 0, and deletes her ML-KEM seed.
    4. **Alice keeps talking.** Her messages stay on her current sending chain, with her old tag chain and `pqEpoch = E − 1` in the header.
    5. **Alice's next DH step** (on Bob's next new ratchet key): the receiving chain is normal; the new sending chain uses `KDF(dh ‖ SS, "root-pq", 64, rk)`. Her `pqEpoch` becomes E, her outgoing tag key becomes `KDF(tagKeyOut ‖ SS, "pq-tag")` with the counter at 0, and `SS` is deleted. Every message on this chain carries `pqEpoch = E` and a re-keyed tag.
    6. **Bob receives Alice's first message on that chain.** He recognises it on the re-keyed chain he has watched since step 2; that chain becomes his current incoming chain (the old one is kept as "previous" for late messages). The header starts a new receiving chain with `pqEpoch = E` = his + 1, and he holds `SS` for E, so the receiving chain uses `root-pq`. Then, in the same step, he creates a **normal** sending chain (from the now-mixed root key), sets `pqEpoch = E`, re-keys **his outgoing** tag chain (`KDF(tagKeyOut ‖ SS, "pq-tag")`, counter at 0) and deletes `SS`. His headers now carry `pqEpoch = E`.
    7. **Alice receives Bob's first message on his re-keyed chain** (she has watched it since step 3); it becomes her current incoming chain. Both sides now share a root key that includes `SS`, and all four tag chains (two per side) are re-keyed.
  - **Receive rule for `pqEpoch`** (checked only on a header that starts a new receiving chain; headers on known chains and from skipped keys are not checked): equal to ours → ordinary step; ours + 1 and we are the answerer holding that epoch's `SS` → `root-pq` step; anything else, lower or higher → reject. Senders always write their session's current `pqEpoch`.
  - The tag chain a message arrives on and its `pqEpoch` are checked independently; a conforming peer can't mismatch them (it re-keys its tags and its root at the same moment), and receivers don't cross-check them.
  - `SS`, the KEM secret key and the seed are deleted once used. A side never offers while it holds an `SS`; it may replace its own pending offer.
- **State per side** (at most one step in flight):
  | State | Held | On a valid offer (epoch = ours + 1) | On a valid answer to our offer |
  |---|---|---|---|
  | idle | nothing | encapsulate, answer, hold `SS` (mix on receive), watch the peer's re-keyed chain | ignore |
  | offer pending | our KEM seed | responder: drop our offer and answer it; initiator: ignore the peer's offer | decapsulate, hold `SS` (mix on send), watch the peer's re-keyed chain, delete the seed |
  | answered (holding `SS`, mix on receive) | `SS` | answer again, **replacing** `SS` and the watched chain (a re-offer after a lost answer) | ignore |
  | decapsulated (holding `SS`, mix on send) | `SS` | ignore (stale) | ignore |

  Each re-keyed tag key is derived from the tag key of that direction at the moment `SS` becomes known (the peer's incoming key) or is mixed (our outgoing key); these are the same key, because only one step is in flight. A newer retirement replaces the "previous" chain. An offer whose ML-KEM public key fails the FIPS 203 check is a malformed step: received, ignored, no answer, and **it changes no state** (a responder's own pending offer is kept; vector `kem-step-responder-keeps-offer-on-malformed`). A KEM body of any other type byte or length is malformed the same way.
- **Timing.** A KEM step protects messages from the first re-keyed chain onward; messages already in flight are covered by the next step. Tags also re-key at each step, so tag recognition heals at the same interval as message keys. (Healing completes one round trip after the answer arrives.) A stale or malformed step message is still counted as received (its tag must not stall the window); only its step is ignored.
- **Security property (tested):** an attacker who records everything and later breaks X25519 (a future quantum computer), but not ML-KEM, can follow the conversation only up to the step; from the first re-keyed chain on she can neither read messages nor recognise their tags, in both directions.

### 4.6 Groups (body kinds 0x03, 0x04; cap 4 members)
No group key: every group message is sent as an ordinary ratchet message (§4.1) over each other member's pairwise session, one payload per recipient, or as a first contact (§4.2) to a member with no session yet. A first contact holds at most 242 bytes of content, so a group state (288 bytes for 2 members) never fits one, and a group text fits only up to 205 bytes of text: then the sender sends a first contact with an empty text (kind 0x01, length 0), which opens the session, and the group message right after it as the first ratchet message on that session (message N = 1 of the sender's first chain, tag index 0). Two payloads instead of one, in that order; the receiver opens the first contact first and finds the message on the new session's tag chain.
```
group state (0x03): ver=1 ‖ groupId (16) ‖ epoch u32 ‖ adminOwnerPub (32) ‖ n u8
                    ‖ n × (ownerPub (32) ‖ idXPub (32) ‖ name field (1 + 20)) ‖ signature (64)     118 + 85n B (458 for 4)
signature = Schnorr (BIP-340) by the admin's owner key over BLAKE2b("kasveil/v1/group-state" ‖ everything before it)
group text (0x04):  ver=1 ‖ groupId (16) ‖ epoch u32 ‖ msgId (16) ‖ UTF-8 text                  max text 1,367 B (205 in a first contact)
```
- **Group state** rules at the receiver: the signature must verify against `adminOwnerPub`; it must arrive over the pairwise session with the admin (never forwarded); 1–4 members, no two with the same `ownerPub`, the admin among them; each name field as in §4.2. A new group is joined only if the state lists the receiver; for a known group the admin must be unchanged and the epoch strictly higher. A state that no longer lists the receiver means it was removed; a later state that lists it again re-adds it.
- **Group text** rules: the sender must be a member at the text's epoch, as known to the receiver; an epoch the receiver never saw (before it joined) is rejected. An epoch above the receiver's current one, or an unknown group, is held and retried after the next group state. An epoch below the current one is shown with a notice. **A text is accepted only if the receiver saw the state of the text's epoch and that state lists both the sender and the receiver**; so after a removal nothing from the removal epoch on is accepted, and after a re-add only epochs from the re-add on.
- `groupId`: 16 random bytes chosen by the admin. `msgId`: 16 random bytes, identical in every copy of one message (for de-duplication and replies).
- The admin sends each new state to every member of the **previous** epoch and every member of the new one, so a removed member learns it was removed.
- How an app reports these events (joined, updated, removed; a re-add is an update) and how it retries held texts is up to the app.

**Unknown versions.** A payload whose version byte isn't `0x01` isn't processed (ignored, like cover traffic). A bundle, group state or group text whose `ver` isn't 1 is invalid content (discarded, §7). A KEM body with an unknown type byte is a malformed step (§4.5).

## 5. The Kaspa transaction carrying a payload

**Batches (SC-0020, 2026-10-14):** a relay-paid transaction's payload is 1 to 5 messages of exactly 1,536 bytes, concatenated; each part is a complete message as defined in §4 and is read on its own. Self-paid transactions may do the same. Readers must accept 1–5 parts and file each part separately.
Every Kaspaveil payload travels in exactly one Kaspa transaction, one payload per transaction:
- **Version:** `1` (`TX_VERSION_TOCCATA`, required for user lanes).
- **Subnetwork (lane):** the 20 bytes `4b 56 4c 01` followed by 16 zero bytes ("KVL" 0x01).
- **Gas:** `0`.
- **Payload field:** exactly the 1,536-byte Kaspaveil payload, nothing before or after it.
- **Sent by the Kaspaguy relay** (the default; SC-0012):
  - **Input:** exactly one, the treasury spending pot's UTXO, which carries the pot's covenant ID.
  - **Output:** exactly one, the pot again with its new state (so its script differs from the input's), **with a covenant binding: authorizing input 0 and the same covenant ID**.
  - **Fee:** input − output, at most 1 KAS; the interval's total is limited by the pot's throttle (spec §8.3).
  - **`lock_time`:** a recent DAA score (below 500,000,000,000, so not a timestamp) that has already passed. The input's sequence must not be `u64::MAX`, so consensus enforces the lock time. The pot takes the 1-hour interval from it (lock time ÷ 36,000).
  - **Signature script:** the Silverscript ABI encoding of `step(relaySig)` followed by the redeem script of `contracts/treasury_hot.sil` compiled with the pot's current state.
  - **Covenant bindings in Kaspa's rules:** in a v1 transaction ID an output is hashed as value, script version and length-prefixed script, then one byte (1 if it has a covenant binding, 0 if not) and, if bound, the authorizing input (u16, little-endian) and the 32-byte covenant ID. A binding adds 34 bytes to the estimated serialized size, and 32 bytes to a UTXO's storage size for storage mass.
  - The relay-paid shape before SC-0012 (the retired certificate-based hot wallet: output back to the same script with no binding, lock time at an epoch start) is retired; its two vectors were removed in SC-0013.
- **Sent from the user's own wallet** (fallback): any of the sender's UTXOs as inputs, change back to the sender, `lock_time` 0. The sender's address is visible on-chain in this mode (spec §1).
- Indexers read the lane, check version, lane and payload length, and ignore anything else.
- **Kaspa's own rules apply, by reference.** The transaction ID, serialized size, masses and minimum fee are defined by Kaspa consensus, normatively rusty-kaspa v2.1.0 (commit `01b532e8b553523216471682649693af92f0fd16`): `consensus/core/src/hashing/tx.rs` (IDs; v1 transactions hash a payload digest), `consensus/core/src/mass/mod.rs` (size, compute and transient mass; 100 grams per compute-budget unit) and `mining/src/mempool/check_transaction_standard.rs` (minimum fee: 100 sompi × max(compute mass, normalized transient mass = ⌈transient mass × 0.5⌉); storage mass has its own limit and doesn't enter the fee). The ID and size layouts are Kaspa's, not this spec's, and they aren't restated here: messaging clients never need them (indexers check only version, lane and payload length), and a relay or wallet builder uses Kaspa's own libraries. The relay's signature script is supplied by the relay operator and opaque to clients (see the relay bullet above; the contracts are published); messaging clients never build it.
- **Verified on testnet-10 (2026-09-29):** public nodes relay and accept these transactions; payloads come back byte-identical from the block (`1b3cffbec8bee05bb2b298b4901675e1ab34fe38c2dff3c9f066de9a60300378`, block `b3f5572e…50d2`). Minimum fee for a self-paid 2 KB message: 462,800 sompi (normalized transient mass 4,628 × 100). Note: the public TN10 explorer's transaction index was behind at the time (it didn't list even the faucet payment), so clients and indexers must read the chain from a node, never rely on a public explorer.
- **Relay-paid (spending pot) spends, verified on testnet-10 (2026-09-30):**
  - **Shape:** v1, Kaspaveil lane, 1 input (the pot, compute budget 11) → 1 output (the pot with its new state, covenant-bound); `lock_time` a recent DAA score; input sequence 0; signature script = `step(relaySig)` plus the redeem script (747 bytes).
  - **Size and fee:** 3,104 bytes in all; minimum fee 620,800 sompi (620,799 rejected). Vector `transaction-relay-paid-pot`.
  - Transaction IDs exclude signature scripts.
  - The certificate-based hot wallet measured 2,635 bytes and 527,000 sompi (2026-09-29, retired).
- **Relay-paid 1,536-byte messages (SC-0013, SC-0014), verified on testnet-10 (2026-10-11)** through our own node: 2,597 bytes in all, compute mass 4,067, transient mass 10,388, **minimum fee 519,400 sompi (0.005194 KAS)**; 519,399 rejected as non-standard. Messages accepted and read back byte-identical (e.g. block `56842e93…1374` at exactly the minimum); the seven attack modes rejected; top-up, root replacement of the relay key (old key then rejected) and a 20-message chain into the mempool all passed. Vector `transaction-relay-paid-pot`.

## 6. Buckets (indexers must use exactly these)
- Message bucket: `(tag[0] << 4) | (tag[1] >> 4)` — 4,096 buckets.
- Registry bucket: `BLAKE2b(name)[0]` — 256 buckets.
- Inbox bucket (first contacts): first 12 bits of `BLAKE2b("kasveil/v1/inbox" ‖ idXPub)`.

## 7. Body kinds
**"Rejected" in this section and in §4.6 refers to the content:** the app discards it, but the ratchet message itself still counts as received (§4.1). Only failures in §4.1–§4.2 (tag, header, AEAD, ratchet, first-contact checks) leave a session unchanged.

| Kind | Meaning |
|---|---|
| 0x01 | Text (UTF-8). Content that isn't valid UTF-8 is displayed with U+FFFD replacement characters; the message still counts as received. The same applies to group text (0x04). |
| 0x02 | Reserved, never assigned (cover traffic is not a body kind, §4.4). Senders never use it; receivers ignore it like any unknown kind (§4.1). |
| 0x03 | Group state (§4.6): admin-signed member list + epoch. **[PROTO]** |
| 0x04 | Group text (§4.6): group ID, epoch, message ID, text. **[PROTO]** |
| 0x05 | Post-quantum KEM ratchet step (§4.5): an ML-KEM-768 offer or answer; the shared secret is mixed into the root key and re-keys both tag chains. **[PROTO]** |
| 0x06 | Conversation settings. Carries a member's own preferences for a conversation (§7.1). **[PROTO]** |
| 0x07 | Conversation notice: something that happened on the sender's device that the chat should see, such as a detected screenshot (§7.2). **[PROTO]** |
| 0x08 | Name in use: the name the sender now goes by (§7.3). **[PROTO]** |

### 7.1 Conversation settings (kind 0x06) — Kaspaguy, 2026-09-30
Carries a member's own preferences for a conversation. The receiver computes the effective settings from all members' preferences. Two versions:

```
version 0x01 (1:1 only):  version u8 = 0x01 ‖ epoch u32 ‖ flags u8                              (6 bytes)
version 0x02:             version u8 = 0x02 ‖ epoch u32 ‖ context u8 ‖ contextData ‖ flags u8
```
- **Both versions are accepted; version 0x02 is preferred for new settings.** A version 0x01 body means the same as version 0x02 with context 0x00. A client that understands only 0x01 ignores 0x02 messages.
- `epoch` is the time of the change, in Unix seconds. Not a counter: a client restored from the recovery phrase cannot know its old counter, so a counter that restarts low would make its new preferences ignored forever.
- Version 0x02 `context = 0x00` means the settings apply to the 1:1 session, and `contextData` is empty (7 bytes in all). `context = 0x01` means they apply to a group, and `contextData` is the 16-byte group ID (the same ID the group-state message carries, §4.6; 23 bytes in all). Any other context value is rejected.
- `flags`: bit 0 = wants the timer off, bit 1 = screenshot protection on. Other bits must be 0.
- Any other version, or a length that doesn't match the version and context, is rejected. Vectors: `settings-encode`, `settings-reject` (0x01); `settings-encode-v2`, `settings-encode-group`, `settings-reject-v2` (0x02).
- **Sending:** 1:1 settings go over that 1:1 session. Group settings go to every other current member over each pairwise session, like a group text (§4.6).
- **Receiving:** a receiver keeps, per member and per context, only the preferences with the highest epoch, whichever version carried them (equal or lower epochs are ignored; the first preferences received are kept whatever their epoch). Group settings count only while the sender is a current member of that group in the receiver's latest group state; settings for a group whose state the receiver doesn't have yet are held and retried after the next group state, like a group text. A member who hasn't sent preferences for a context yet counts as "timer on, no screenshot protection" there.
- Every app computes the same effective settings for a given context (the members of the 1:1 session, or the group's current members): the timer (30 hours = 108,000 seconds after arrival) is off only if every member is Plus and every member wants it off; screenshot protection is on if any member switched it on, whatever their tier (SC-0022: apps offer the switch to Plus members only, but a receiver never second-guesses it, so a stale or wrong view of someone's tier can't leave a protected chat unprotected). Tiers come from the registry, never from the message (a name in its grace period counts as Plus, `PROTOCOL_SPEC.md` §8.1).

### 7.2 Conversation notices (kind 0x07) — Kaspaguy, 2026-10-16
Sent by an app, never typed by a person, when its device detects something the other members should know about. Shown as a line in the chat, not as a message.

```
version u8 = 0x01 ‖ context u8 ‖ contextData ‖ event u8 ‖ time u32      (7 bytes 1:1, 23 bytes in a group)
```
- `context` and `contextData` as in §7.1 version 0x02: 0x00 = the 1:1 session (no data), 0x01 = a group (16-byte group ID). Any other context is rejected.
- `event`: **0x01** screenshot detected (the operating system reported one: iPhone, Android 14 and later); **0x02** possible screenshot (a screenshot shortcut was pressed but the capture itself can't be seen: desktop); **0x03** screen recording or mirroring started (iPhone). Unknown events are rejected rather than shown, so an older app never words a newer event wrongly.
- `time`: when the event happened on the sender's device, Unix seconds (big-endian).
- Any other version, or a length that doesn't match the context, is rejected.
- **Sending:** apps send a notice only in a conversation whose effective screenshot protection is on (`PROTOCOL_SPEC.md` §8.2), at most once per event per conversation every 30 seconds. 1:1 notices go over that session; group notices go to every other current member over each pairwise session. A notice never opens a session (it isn't allowed in a first contact, §4.2), so a member the sender has no session with yet isn't told, and the sender's app says so.
- **Receiving:** a group notice counts only while the sender is a current member of that group in the receiver's latest group state. Notices from a blocked sender are dropped.

### 7.3 Name in use (kind 0x08) — Kaspaguy, 2026-10-16
Tells the other side of a session which of the sender's names it now goes by, for example after switching from a free name to a Plus name. Without it, a contact keeps the name it first knew, reads the tier from that name's registry entry and so sees a Plus member as free (wrong timer, wrong name).

```
version u8 = 0x01 ‖ length u8 ‖ name      (3 to 22 bytes)
```
- `name`: 1 to 20 characters `a`–`z`, `0`–`9`, `-` (the registry's name alphabet), `length` = its byte count. Any other version, a length that doesn't match the body, or a character outside the alphabet is rejected.
- **Sending:** whenever the name the account goes by changes, the app sends one to every peer it has an established session with, once per peer per name. Not sent to a peer whose message request hasn't been accepted, nor to a blocked peer. A session opened by the sender's own first contact already carries the name (§4.2), so it isn't told again. Never sent in a first contact.
- **Receiving:** the receiver looks the name up in the registry and adopts it only if the registry maps it to the sender's owner key; otherwise the body is ignored. The tier comes from that registry entry, never from the message. A name the receiver already shows is ignored. Group titles use the adopted name too.

## 8. Status
Implemented and tested (TypeScript 77/77, 49 vectors; the independent Rust implementation passes all 49): keys from the phrase, bundles, first contact, double ratchet with encrypted headers and tag chains, out-of-order delivery, replay/tamper/impersonation rejection, cover traffic, buckets, conversation settings, **KEM ratchet step** (full step, healing against a broken-X25519 attacker, crossing offers, lost answer and re-offer, late messages across the tag switch, stale steps, due policy), **groups** (4 strangers reaching each other by first contact, with an opener when the message doesn't fit, removal and re-adding without re-keying, older-epoch notices, forged/forwarded/replayed states, non-member texts, held texts), vectors (including a full KEM step and a group state + text).

## Appendix: test-vector harness
`protocol/vectors/v1.json` is self-describing: its top-level `format` block is normative **for the harness** (it is not wire format). It defines the encoding (lowercase hex), the vector shape (`id`, `kind`, `description`, `input`, `expected`), that arrays are ordered, the names and consumption order of every random input, the session-state layout, and the result shapes. The session-state fields that only some vectors populate have these shapes:
- `skipped`: `[{their_ratchet_pub, n, message_key}]` (vector `ratchet-skipped-key-state`);
- `pq_offer`: `{epoch, mlkem_keygen_seed}` or null (the offer is held as its 64-byte seed);
- `pq_secret`: `{epoch, shared_secret, mix_on_send}` or null; `mix_on_send` is true for the offerer and false for the answerer (vector `kem-step-offer-pending`);
- `tag_key_in_next`: the peer's re-keyed incoming tag key, or null;
- `previous_in`: `{tag_key_in, tag_in, seen_in}` or null (vector `kem-step-full`).

