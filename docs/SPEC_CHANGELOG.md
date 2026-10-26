# Kaspaveil spec changelog

Entries from SC-0006 on are numbered; earlier ones are dated only. Every change to `WIRE_FORMAT.md`, `PROTOCOL_SPEC.md` (where it affects bytes or behaviour on the wire) or `protocol/vectors/v1.json` gets an entry here, newest first, so existing implementations can audit what changed and whether they must follow. Each entry says: what changed, which sections, whether earlier vectors changed, and what an existing implementation must do.

## SC-0024 — Payments: nothing sent to an order address is ever lost

**Date:** 2026-10-22
**Files changed:** `contracts/payment.sil` (new entry `settleLate`), `contracts/tools/gen_payment_tests.py`, `contracts/payment.test.json`; `tools/chaind`, `relay`, `app`
**Source:** owner (Kaspaguy, 2026-10-22: "if a user sends 50 KAS when the order is 100 KAS, or sends 100 KAS twice, their money is gone with no recourse")
**Status:** applied; payment 20/20 on the script engine (8 new cases), relay 16/16, app stack 7/7. New orders use the new contract.

### What changed

Before, `settle()` needed the order's full amount in one settlement, so a payment that never made it up, or arrived after the order was settled, could never be spent: it was locked in a keyless address forever. Now `settleLate()` settles any amount, to the same fixed 75/25 split, once every payment it spends is 3 days old (`require(this.ageDaa >= 2592000)`: a relative lock time, so the network refuses the spend earlier). `settle()` is unchanged, so nobody can settle part of an open order early.

Off-chain, the relay credits every payment an order doesn't use (an underpayment when the order expires, a second or late payment, for 30 days) as top-up message credits in the order's extras account, secret `HMAC-SHA256(key = account secret, "kaspachat/v1/extra")`, which the app derives from the recovery phrase.

### What an implementation must do

Settle late payments with `settleLate` and input sequence ≥ 2,592,000. No wire format or vector is affected.

## SC-0023 — Released names: claim signatures of their own, with the leaf nonce

**Date:** 2026-10-22
**Files changed:** `contracts/registry_shard.sil` (`claimReleasedDirect`, `claimReleasedPrepaid`), `contracts/tools/gen_registry_tests.py`, `contracts/registry_shard.test.json`, `tools/chaind/src/main.rs`; `PROTOCOL_SPEC.md` §8.5
**Source:** code audit, 2026-10-22
**Status:** applied; registry suite 83/83 on the script engine (2 new replay cases; both pass on the old contract, i.e. the replay was accepted). Needs a new registry deployment to take effect.

### What changed

The doorman's signature for claiming a released name was the same message as for registering a new one (`reg-direct` / `reg-prepaid` + name + owner + months + DAA), with no nonce. Every registration signature is public on-chain, so once a name was released anyone could replay its original registration: on the prepaid path that hands the name back to its old owner for nothing, already past its expiry, ready to be reclaimed into another 6-month hold — a released name could be kept off the market indefinitely, and each replay inflated the public `prepaidRegs` / `prepaidMonths` counters.

Now `claimReleasedDirect` signs `BLAKE2b(domain("claim-direct") ‖ name ‖ newOwner ‖ months u64 LE ‖ nowDaa u64 LE ‖ leafNonce u64 LE)` and `claimReleasedPrepaid` the same with `claim-prepaid`. A registration signature can't match a claim, and a claim signature works once (the claim bumps the leaf nonce).

### What an implementation must do

Doormans: sign claims of released names with the new messages. Nothing else changes; no wire format or vector is affected.


**Date:** 2026-10-16
**Files changed:** `WIRE_FORMAT.md` §4.1, §7, §7.1, new §7.3; `PROTOCOL_SPEC.md` §3, §8.1, §8.2; `protocol/src/settings.ts`, new `nameUse.ts`, `constants.ts`, `index.ts`; `protocol/test/settings.test.ts`, new `nameUse.test.ts`; `protocol/scripts/gen-vectors.ts`, `protocol/vectors/v1.json` (`settings-effective`); `rust-impl/src/settings.rs`
**Source:** owner (Kaspaguy, 2026-10-16: "B for screenshot protection now, plus A to fix names and the timer")
**Status:** applied; TypeScript 84/84, Rust 51/51; tested on testnet-10 (two web users: name switch adopted in 2–3 s, a forged name ignored, protection from a free member honoured)

### What changed

1. **Screenshot protection is on if any member switched it on**, whatever tier the receiver sees for them. Before: only a Plus member's switch counted. Apps still offer the switch to Plus members only.
2. **New body kind 0x08, name in use:** `version 0x01 ‖ length ‖ name`. Sent once per established session whenever the name the account goes by changes; adopted only after the registry maps the name to the sender's key; the tier comes from the registry.

### Why

A bug found on 2026-10-16: after switching from a free name to a Plus name, contacts who knew the free name kept reading the tier from it and saw a Plus member as free. Their apps ignored that member's screenshot protection (the web app opened a protected chat) and kept the timer on. Change 1 closes the protection gap whatever any app believes about tiers; change 2 fixes the name and the tier, which the timer needs.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | **yes, one entry:** `settings-effective` case 7 (a free-looking member asks for protection) now expects `true`, and its name changed; case 4's protection result also becomes `true`. Every other entry is byte-identical. v1 is still marked draft (the pages on kaspaveil.com are pre-launch), so the entry is corrected in place, as SC-0013 did; once v1 is declared final this would need a new version |
| Requires contract recompilation? | no |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | yes for change 1: an implementation following the old rule shows a chat as unprotected where official apps protect it. Change 2: no, 0x08 was an unknown kind |
| Affects the threat model? | slightly: a modified free client can now force protection on (worst case: the chat won't open in the web app). A name-in-use message is an ordinary padded ratchet message, indistinguishable on-chain |

## SC-0021 — Conversation notices (body kind 0x07): screenshot detected

**Date:** 2026-10-16
**Files changed:** `WIRE_FORMAT.md` §4.1, §7, new §7.2; `PROTOCOL_SPEC.md` §7, §8.2; `protocol/src/notice.ts`, `constants.ts`, `index.ts`; `protocol/test/notice.test.ts`
**Source:** owner (Kaspaguy, 2026-10-16: "the app is supposed to display a message on the chat screen that says 'screenshot detected' or 'possible screenshot detected'"; spec §8.2 already said the sender is notified)
**Status:** applied; tested on testnet-10 (Android emulator to the web app)

### What changed

New body kind 0x07, a notice an app sends by itself: `version 0x01 ‖ context ‖ contextData ‖ event ‖ time u32`. Events: 0x01 screenshot detected, 0x02 possible screenshot, 0x03 screen recording started. Sent only in conversations with screenshot protection on, at most once per event per conversation per 30 seconds, never in a first contact.

### Why

Screenshot protection promised that the other members learn about a detected screenshot, and no message kind could carry that.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no (no vector added yet; the encoding is covered by `notice.test.ts`) |
| Requires contract recompilation? | no |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | no: 0x07 was an unknown kind, which receivers already ignore (§4.1). An implementation that wants to show notices decodes §7.2 |
| Affects the threat model? | no: a notice is an ordinary padded ratchet message, indistinguishable on-chain |

## SC-0020 — Relay-paid transactions carry up to 5 messages

**Date:** 2026-10-14
**Files changed:** `WIRE_FORMAT.md` §5; `PROTOCOL_SPEC.md` §5; `indexer`; `relay`; `tools/chaind`
**Source:** owner requirement (Kaspaguy, 2026-10-14: at least 100 messages a second)
**Status:** applied on testnet-10

### What changed

A Kaspaveil lane transaction's payload is 1 to 5 messages of exactly 1,536 bytes, concatenated (the pot already accepted payloads up to 8,192 bytes, so no contract change). Each 1,536-byte part is an independent message with its own tag; indexers file each part on its own (`txid:index`). The relay groups whatever arrives within 25 ms, up to 5, into one transaction on a free pot lane.

### Why

The fixed part of a relay-paid transaction (pot script, signature, input, output: about 1,060 bytes) is paid once per transaction, so 5 messages per transaction cost about a third less each (0.0035 KAS instead of 0.0052 measured on testnet-10), and each lane carries 5 times as many messages.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no (message bytes unchanged; the single-message transaction vector stays valid) |
| Requires contract recompilation? | no |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | indexers and clients reading the chain must split payloads into 1,536-byte parts |
| Affects the threat model? | an observer sees which messages left the relay within the same 25 ms; tags stay unlinkable and the relay already sees submission times. Consecutive messages are spread over lanes |

## SC-0019 — Spending pot in lanes, hourly floor a constructor argument

**Date:** 2026-10-14
**Files changed:** `contracts/treasury_hot.sil`; `contracts/tests/treasury_engine_tests.rs`; `tools/hotwallet`; `tools/chaind`; `PROTOCOL_SPEC.md` §8.3
**Source:** owner requirement and decision (Kaspaguy, 2026-10-14: at least 100 messages a second; hourly floor 200 KAS)
**Status:** applied; engine tests 11/11; deployed on testnet-10 (32 lanes, covenant `215dccce…8242`)

### What changed

- **Lanes:** the pot's genesis transaction creates several lane UTXOs under one covenant ID. The existing one-input/one-output check means every spend moves exactly one lane: lanes can't be merged or split (new engine test). Reservoirs recognise the pot by covenant ID, so they top up any lane without change.
- **Floor per pot:** `FLOOR` is now a constructor argument `floor`, set per lane to the pot's hourly floor divided by the number of lanes, so all lanes together can spend at most the pot's floor plus what real usage has earned (5 × each lane's SMMA). **Pot floor 200 KAS per hour (Kaspaguy, 2026-10-14; was 20)**: 32 lanes × 6.25 KAS.
- One root signature replaces the relay key on every lane (it binds the covenant ID and the lane's own key nonce).

### Why

With one pot UTXO every message spent the previous one's output, and Kaspa confirms such a chain at about one step per block-template round: measured 6.6 messages/s unloaded and 0.7/s under load on testnet-10, while 300 independent messages confirmed in one second. Lanes remove the chain.

### Measured on testnet-10 (2026-10-14, 32 lanes, 5 messages per transaction)

| Run | Into the mempool | Confirmed on-chain | Failed | Fee per message |
|---|---|---|---|---|
| 6,000 messages, 200 in flight | 820/s | 529/s | 0 | 0.00351 KAS |
| 30,000 messages, 400 in flight (64 lane top-ups during the run) | 796/s | 671/s | 0 | 0.00421 KAS (fee estimate rose under our own load) |

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no |
| Requires contract recompilation? | yes — `treasury_hot.sil` (new constructor argument), new pot, so new reservoir addresses and a new registry deployment |
| Requires registry migration (if deployed)? | testnet registry redeployed (nothing on mainnet) |
| Affects existing implementations? | relays may run several lanes; the pot's state includes its floor |
| Affects the threat model? | a stolen relay key can spend up to the pot's floor per hour (200 KAS) across all lanes, plus 5 × recent usage, until the root replaces the key; before this change the floor was 20 KAS |

## SC-0018 — Payment covenant: one keyless address per order, fixed 25/75 split

**Date:** 2026-10-14
**Files changed:** `contracts/payment.sil` (new); `contracts/tools/gen_payment_tests.py` (new, + `payment.test.json`); `tools/chaind`; `relay`; `PROTOCOL_SPEC.md` §8.5a
**Source:** owner decision (Kaspaguy, 2026-10-14: build the payment covenant; KAS only)
**Status:** applied; debugger 12/12; deployed on testnet-10

### What changed

- **New contract `Payment(order, devSpk, reservoirSpk, minTotal)`** with one entry, `settle()`: anyone may spend it, and only into two outputs: output 0 to `reservoirSpk` with at least 75% of the total, output 1 to `devSpk` with the rest less at most 0.01 KAS network fee. Every input must be this same script (at most 8), so several payments to one order add up; `settle` needs the total to reach `minTotal`.
- **One address per order:** `order` (32 bytes) makes each order's address unique, so a payment needs no memo and works from any wallet or exchange withdrawal. The reservoir is chosen per order: one-month (Plus, 1 month; claims), prepayment (2–12 months), never-sweep (top-ups, `minTotal` at least 20 KAS).
- **Credit path:** after settlement the doorman registers, renews or hands over the name (`registerPrepaid`, `renewPrepaid`, `settleAuctionPrepaid`, `claimReleasedPrepaid`) and the relay issues the month's blind tokens. The public prepaid counters in the registry can be compared with what the payment covenants received.

### Why

Replaces the testnet stand-in (a doorman-held deposit key that forwarded 25/75 by policy). Now nobody, Kaspaguy included, can take a payment any other way than the fixed split.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no |
| Requires contract recompilation? | new contract; registry, pot and reservoirs unchanged by this entry |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | wallets pay a P2SH address; payments are KAS only (no swaps in the app) |
| Affects the threat model? | the payer's wallet is linked to the order on-chain (as before); the blind tokens still unlink the credits from the payment. An order paid below its amount waits for the rest; it can't be refunded (no keys) |

## SC-0017 — Transfers and sales closed until the root opens them (one way)

**Date:** 2026-10-14
**Files changed:** `contracts/registry_shard.sil`; `contracts/tools/gen_registry_tests.py` (+ regenerated tests); `PROTOCOL_SPEC.md` §3.3, §8.2
**Source:** owner decision (Kaspaguy, 2026-10-14: transfers not allowed for now, built but disabled, so a name is not an NFT or a store of value; one-way root switch)
**Status:** applied; registry 81/81; signature checks 13 of 15

### What changed

- New state field `transfersOpen` (0 at genesis). `transfer` and `sell` require `transfersOpen == 1`.
- New entry `openTransfers(rootSig)`: the root key signs `open-transfers ‖ keyNonce` (domain-separated per registry and shard); it sets `transfersOpen = 1` and bumps `keyNonce`. Nothing sets it back to 0, and it can't run twice.
- Lapsed names stay as they were in code: after expiry + 30 days' grace anyone may `reclaim`; **policy (Kaspaguy): the first claimant who pays gets it**, at one month's price (`settleAuctionPrepaid` at the reserve), with no auction. The doorman reclaims every name at grace end.

### Why

Before, the doorman's hold bound only Kaspaguy's services: an owner could still call `transfer` or `sell` directly on-chain (plan §8, open question). Now the chain enforces it.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no |
| Requires contract recompilation? | yes — `registry_shard.sil` (new state field and entry) |
| Requires registry migration (if deployed)? | testnet registry redeployed 2026-10-14 (nothing on mainnet) |
| Affects existing implementations? | registry state has one more field; apps don't offer transfers or sales |
| Affects the threat model? | the root key gains one power, opening transfers once; it still can't take or move any name |

## SC-0016 — Registry shards stay one covenant (singleton check)

**Date:** 2026-10-14
**Files changed:** `contracts/registry_shard.sil` (`keepValue`); `contracts/tools/gen_registry_tests.py` (+ regenerated tests); `PROTOCOL_SPEC.md` §3.3
**Source:** found while preparing the registry's testnet deploy (Phase 2)
**Status:** applied; registry 75/75 (4 new attack tests). Control: the same 4 attacks pass on the previous contract

### What changed

Every registry entry ends in `keepValue()`, which now also requires that exactly one input and one output carry the shard's covenant ID, and that this output is output 0 (`OpCovInputCount`, `OpCovOutputCount`, `OpAuthOutputCount`, `OpAuthOutputIdx`, the same checks as the spending pot's `singleton()`). No signature checks added (still 12 of 15).

### Why

`validateOutputState` checks the continuation's script, not its covenant binding. Before this change, anyone making a valid registry spend could leave output 0 without the covenant binding, or bind a second output to the same covenant. `reclaim` and `release` need no signature and `renewDirect` needs only a payment, so anyone could do it. Clients pin each shard's covenant-ID lineage (§3.3 "Canonical registry"), so an unbound continuation would have ended the canonical shard: every name in it frozen, recoverable only by a registry migration. A forked shard would have given two live copies of the same state.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no |
| Requires contract recompilation? | yes — `registry_shard.sil` (bytecode 51,261 bytes) |
| Requires registry migration (if deployed)? | no (nothing deployed before this change) |
| Affects existing implementations? | registry spends must bind output 0 to the shard's covenant ID (the reference tools always did) |
| Affects the threat model? | closes a permissionless denial of service against the registry |

### Cross-references

SC-0012 (the pot's `singleton()`, the pattern reused here).

## SC-0015 — Unused message credits expire every month and are swept to Kaspaguy

**Date:** 2026-10-11
**Files changed:** `PROTOCOL_SPEC.md` §8.2, §8.3; `contracts/reservoir.sil`; `contracts/registry_shard.sil`; `contracts/tests/treasury_engine_tests.rs`; `contracts/tools/gen_registry_tests.py` (+ regenerated tests); `tools/hotwallet`; `tools/lanecheck`
**Source:** owner decision (Kaspaguy, 2026-10-11)
**Status:** applied; engine tests 10/10, registry 71/71; sweep verified on testnet-10 2026-10-11. Amended the same day, before any deployment: first drafted with one rollover month (sweep ages 60 and 390 days); Kaspaguy chose a monthly reset (30 and 360 days)

### What changed

- **Credits:** a Plus month's message credits are valid for that month only; unused credits expire when the month renews and the new month's credits replace them. Top-up credits don't expire. Public wording: "Unused credits are swept out every month at the time of replenishment."
- **Reservoir:** new constructor arguments `sweepAgeDaa` and `sweepSpk`, and a new entry `sweep()`: once a reservoir UTXO is `sweepAgeDaa` old (relative DAA lock), anyone may move it, whole, to `sweepSpk` (fee at most 0.01 KAS). `sweepAgeDaa = 0` never sweeps. `topUp()` is unchanged.

| Reservoir | Receives | Sweep age |
|---|---|---|
| one-month | one-month payments, an auction win's first month | 25,920,000 DAA (30 days) |
| prepayment | 2–12 month prepayments | 311,040,000 DAA (360 days) |
| never-sweep | top-ups (payment covenant, not yet written) | none |

- **Registry:** new constructor argument `reservoirLongSpk`; `payDirect` requires a one-month payment to go to `reservoirSpk` and a longer one to `reservoirLongSpk`.

### Why

Kaspaguy (2026-10-11): unused credits should not stay in the treasury forever. Before this change unspent treasury funds could never leave except as message fees. A Plus month's 75 KAS covers about 14,400 messages at today's fee, far more than most users send, so the surplus would have grown without limit.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no |
| Requires contract recompilation? | yes — `reservoir.sil` (new arguments and entry), `registry_shard.sil` (new argument and rule) |
| Requires registry migration (if deployed)? | no (nothing deployed; deploy order stays pot → reservoirs → registry) |
| Affects existing implementations? | relay: token keys per day, accepted for 30 days; app: drop a month's unused credits when it renews; tools: the reservoir needs the sweep age and address |
| Affects the threat model? | the "nobody can take the treasury" line changes: funds older than their sweep age go to one fixed Kaspaguy address, by anyone's call; nobody can sweep early or elsewhere. The treasury keeps at most the last 30 days of one-month payments (360 for prepayments) as its buffer against fee spikes |

### Cross-references

SC-0012 (pot and reservoir), SC-0014 (pot constants). Also fixed: `tools/lanecheck` modelled the pot with N = 42 after SC-0014 set 168; its testnet runs all stayed inside one interval, so it never showed. An interval roll with N = 168 was accepted on testnet-10 on 2026-10-11 (`1a1e1235…57f6`, SMMA 12,366 = 2,077,600 / 168).

## SC-0014 — Spending pot: 1-hour intervals, one-week SMMA over 168, payloads from 256 bytes

**Date:** 2026-10-11
**Files changed:** `PROTOCOL_SPEC.md` §8.3, `WIRE_FORMAT.md` §5; `contracts/treasury_hot.sil`; `contracts/tests/treasury_engine_tests.rs`; `tools/lanecheck`; `tools/ceremony/RUNBOOK.md`
**Source:** owner decision (Kaspaguy, 2026-10-10)
**Status:** applied; engine tests 8/8; verified on testnet-10 2026-10-11 (interval 16,492 = lock time ÷ 36,000)

### What changed

The spending pot's constants (SC-0012), before mainnet genesis, when they can
still change for free:

| Constant | Before | Now |
|---|---|---|
| `INTERVAL_DAA` | 144,000 (4 hours) | **36,000 (1 hour)** |
| `N` (SMMA length) | 42 (one week) | **168 (one week)** |
| `K` (burst factor) | 5 | 5 |
| `FLOOR` | 20 KAS per 4-hour interval | **20 KAS per 1-hour interval** |
| `MIN_PAYLOAD` | 1,024 bytes | **256 bytes** |
| `MAX_PAYLOAD`, `MAX_FEE`, `ADMIN_FEE`, `MIN_TOPUP` | 8,192 B, 1 KAS, 0.01 KAS, 1 KAS | unchanged |

- The interval is the lock time ÷ 36,000.
- SMMA ← (167 × SMMA + last interval's fees) / 168 at a new interval, then a
  linear decay of 1/168 per empty interval (zero after 168).
- A relay-key thief can raise the allowance by at most ×(1 + 4/168) an
  interval: about **1.76× a day** (engine test: 40 → 123 KAS over two days;
  it was ~1.73× with 4-hour intervals).
- `MIN_PAYLOAD` 256 keeps a future smaller message size possible without a new
  pot (the payload size itself is SC-0013).

### Why

Kaspaguy (2026-10-10): very few users are expected at launch, so a shorter interval
reacts faster to real traffic, and a one-week average is kept by raising N to
168. The pot's constants are fixed per pot after genesis, and the reservoir is
bound to the pot's covenant ID, so any later change means a new pot and a new
reservoir; now is the time.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | yes — `transaction-relay-paid-pot` regenerated (new pot script, 1-hour interval) |
| Requires contract recompilation? | yes — `treasury_hot.sil` (pot bytecode changes; the reservoir is unchanged but binds to the new pot's covenant ID) |
| Requires registry migration (if deployed)? | no (nothing deployed; deploy order stays pot → reservoir → registry) |
| Affects existing implementations? | relay and indexer only: the interval is lock time ÷ 36,000 |
| Affects the threat model? | yes — at the floor a stolen relay key can burn 20 KAS an hour (480 KAS a day, was 120) until replaced; growth above the floor is ~1.76× a day |

### Cross-references

SC-0012 (the pot), SC-0013 (payload size).

## SC-0013 — One payload size of 1,536 bytes (was 2,048)

**Date:** 2026-10-11
**Files changed:** `WIRE_FORMAT.md` §3, §4 (all), §4.6, §5, §8; `PROTOCOL_SPEC.md` §2, §4, §5, §8.2, §9; `protocol/` (constants, `group.ts` `reachByFirstContact`, tests); `rust-impl/`; `protocol/vectors/v1.json`; `tools/lanecheck`, `tools/r1evidence`
**Source:** owner decision (Kaspaguy, 2026-10-10: padding option C at 1,536)
**Status:** applied; TypeScript 77/77, Rust 51/51 + 19/19; verified on testnet-10 2026-10-11

### What changed

Every payload is now exactly **1,536 bytes**. Version byte, labels and lane are
unchanged (`0x01`, `kasveil/v1/…`, KVL): nothing has been published, so v1 is
re-cut rather than versioned.

| Field | 2,048 | 1,536 |
|---|---|---|
| ongoing message body plaintext / max content | 1,919 / 1,916 | **1,407 / 1,404** |
| first contact `sealedCt` / sealed plaintext | 911 / 895 | **399 / 383** |
| first contact `innerCt` / inner body / max content | 773 / 757 / 754 | **261 / 245 / 242** |
| group text max (in a first contact) | 1,879 (717) | **1,367 (205)** |
| bundle devices per payload | 0–20 | **0–4** (receivers reject `nDevices` > 4) |
| cover traffic random tail; dummy first contact tail | 2,047; 1,999 | **1,535; 1,487** |

- **Groups:** a first contact can no longer carry a group state (288 bytes
  for 2 members, 458 for 4). When a group message doesn't fit a first
  contact, the sender sends a first contact with an **empty text** (kind
  0x01, length 0), which only opens the session, and then the group message as
  the first ratchet message on that session (N = 1, tag index 0). Apps don't
  show an empty first-contact text. Reference: `reachByFirstContact`.
  Receivers need no change beyond not showing the empty text.
- **Transaction vectors:** `transaction-relay-paid` and
  `transaction-relay-paid-asymmetric-txid` (the retired certificate hot
  wallet, 2,048-byte payload) were removed: they described a contract retired
  in SC-0012 and a payload size that no longer exists. 49 vectors remain.
- **Cost:** a relay-paid message is 2,597 bytes, minimum fee **519,400 sompi
  (0.005194 KAS)**, measured on testnet-10 on 2026-10-11 (519,399 rejected;
  was 0.006208 KAS, −16%).

### Why

Kaspaguy (2026-10-10) chose option C: one smaller size for everything, so size
still reveals nothing (option A's two sizes would mark first contacts and
key steps), at about 16% lower cost.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | yes — every payload-carrying vector changed; all regenerated (49) and reproduced by the independent Rust implementation with only its size constants changed |
| Requires contract recompilation? | no for the size itself (the pot accepts 256–8,192 bytes, SC-0014) |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | yes — payload length, every derived length, the bundle device limit and the group opener rule |
| Affects the threat model? | no change to size privacy (still one size); reaching a stranger with a group state now takes 2 payloads, the second on the new session's tag chain |

### Cross-references

padding option C, SC-0014 (pot minimum payload).
Published message line: the new figure (~14,000 / ~4,800) awaits Kaspaguy's
approval (`PROTOCOL_SPEC.md` §8.2).

## SC-0012 — Treasury: a throttled spending pot replaces the monthly relay certificate

**Date:** 2026-09-30
**Files changed:** `PROTOCOL_SPEC.md` §2, §8.1, §8.2, §8.3, §8.5, §9, §10; `WIRE_FORMAT.md` §5; `contracts/treasury_hot.sil`, `contracts/reservoir.sil`; `tools/ceremony` and its `RUNBOOK.md`; `protocol/vectors/v1.json`
**Source:** owner decision (Kaspaguy, option B)
**Status:** applied; proven on testnet-10

### What changed

**The throttle replaces the monthly signing, not the relay key.** The relay key
still does admission control: it signs the relay-paid messages of users who paid,
and nothing else is paid for. The root key (2-of-3 FROST, unchanged) no longer
certifies the relay key every 30 days; its only job in the treasury is to
replace the relay key when it is lost or stolen. In normal operation it is never
needed, but it is still needed.

- **Spending pot** (`treasury_hot.sil`): one covenant (one covenant ID) whose
  state is the relay key, the current 4-hour interval, the fees paid in it, a
  smoothed moving average (SMMA) of fees per interval, and a key nonce.
  - Each relay-paid message must be signed by the relay key, pay a fee of at
    most 1 KAS, and keep the interval's fees within
    **max(20 KAS, 5 × SMMA)**.
  - SMMA over N = 42 intervals (one week): at a new interval,
    SMMA ← (41 × SMMA + last interval's fees) / 42, then a linear decay of 1/42
    for each empty interval in between (zero after 42 empty intervals).
  - The next transaction in a new interval applies the update and resets the
    counter.
  - The interval comes from the transaction's lock time, which must be a DAA
    score (below 500,000,000,000) that consensus enforces (input sequence not
    final).
  - The continuation must carry the pot's covenant binding.
- **Reservoir** (`reservoir.sil`): keyless, as before, but it no longer drips
  1/30 per day. It **tops the pot up** in a two-input transaction (pot, one
  reservoir UTXO), and only into the genuine pot, which it recognises by its
  covenant ID. The pot allows a top-up only:
  - when it holds at most half of the interval's allowance;
  - never above the allowance;
  - and only if the top-up either fills the pot exactly or uses the reservoir
    UTXO up while adding at least 1 KAS.
- **Root key:** one entry, `replaceRelay`. It signs
  BLAKE2b-256("kasveil/v1/relay-replace" ‖ pot covenant ID ‖ new relay key ‖
  nonce as 8 LE bytes), and the nonce makes every signature single-use. The
  epoch/certificate machinery is gone from the treasury. The ceremony tool
  signs replacements instead of certificates.
- **Relay-paid transaction shape** (`WIRE_FORMAT.md` §5):
  - the output now carries a covenant binding (authorizing input 0, the pot's
    covenant ID);
  - its script differs from the input's (new state);
  - the lock time is a recent DAA score, no longer an epoch start;
  - the signature script is `step(relaySig)` plus the pot's redeem script.
- **Cost:** a relay-paid 2 KB message is now 3,104 bytes, with a minimum fee
  of **620,800 sompi (0.006208 KAS)**, measured on testnet-10 (620,799 was
  rejected). The old one was 2,635 bytes and 0.00527 KAS.
  - The treasury's 75 KAS a month covers ~12,000 one-to-one messages
    (~4,000 to full groups), instead of ~14,000 (~4,700).
  - 10 KAS of top-up covers ~1,200 instead of ~1,400.
  - **The published line needs the owner's re-approval.**

### Why

Before this change, the certificate needed two of the three root-key holders
every 30 days, and the design gave much less protection than the spec claimed:
- The hot wallet had no balance cap, so unspent drips piled up there, all of it
  burnable by a stolen relay key until each UTXO was respent under a new
  certificate (the spec's "at most about a day's drip" was wrong).
- Deposits under 100 KAS (every one-month payment and every top-up) were
  released whole after one day, so the drip rarely applied.

The throttle bounds a stolen relay key by rate instead. A thief spending
everything the throttle allows can raise the limit only about 1.7× a day
(engine-tested: 40 → 119 KAS over two days from 8 KAS/interval normal use; day
one's theft ≈ 6 normal days of spending). A plain "5× the last interval" rule
would have allowed ≈15,000× a day, which is why the average is smoothed. The
small pot is defence in depth.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no — every existing entry byte-identical except the descriptions of `transaction-relay-paid` and `transaction-relay-paid-asymmetric-txid`, which now say they carry the retired certificate-based hot wallet (they remain valid examples of Kaspa's transaction ID and masses); new vector `transaction-relay-paid-pot` |
| Requires contract recompilation? | yes — both treasury contracts replaced; the registry is compiled with the reservoir's address, which now depends on the pot's covenant ID (deploy order: pot genesis → reservoir → registry) |
| Requires registry migration (if deployed)? | no — nothing is deployed |
| Affects existing implementations? | relay and transaction builders only: covenant-bound output, lock-time rule, new signature script. Messaging clients are unaffected. Implementations that compute transaction IDs or masses must handle covenant bindings (+34 bytes of size, flag + authorizing input + ID in the ID hash, +32 bytes of UTXO storage) |
| Affects the threat model? | yes — a stolen relay key is bounded by the throttle; losing the root key no longer stops relay sending (it only means a stolen or lost relay key can't be replaced) |

### Cross-references

`PROTOCOL_SPEC.md` §8.3 (rewritten). Retired contracts and their tests: `contracts/retired/` (removed from the tree 2026-10-22; in git history at 87da5e7). Engine tests: `contracts/tests/treasury_engine_tests.rs` (8 tests). Testnet: `tools/lanecheck` `pot-*` commands. Split pots at 70% consumption: v2 option (§8.3).

## SC-0011 — Replayed first contacts are dropped

**Date:** 2026-09-30
**Files changed:** `WIRE_FORMAT.md` §4.2
**Source:** third-run follow-up (owner decision)
**Status:** applied

### What changed

A receiver now remembers the tag of every first contact it has processed, for
as long as it keeps the prekey that opened it. A first contact whose tag has
already been seen is dropped without changing any state.

"Processed" means opened (every §4.2 check passed). A payload that carries a
first contact's tag but fails a check is not remembered, so a forged payload
copying a genuine first contact's tag, which is visible on-chain, can't get the
genuine one dropped.

### Why

The re-contact rule (SC-0006) says "any other first contact from a known peer
replaces our session." Nothing rejected duplicates, so anyone could re-post an
old first contact on-chain — the payload is public — and the receiver would
replace a working session with one the sender does not have. Messages sent on
the new (dead) session would be lost silently.

The tag is deterministic from the first contact's contents, so a re-post
carries the same tag. Remembering processed tags is free: the receiver already
stores the prekey that opened the first contact. Retention is bounded by the
prekey's lifetime, and a first contact older than the prekey can't be
decrypted anyway, so there is no window where a replay slips through.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no — a new vector covers the replay case |
| Requires contract recompilation? | no |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | yes — receivers must track processed first-contact tags |
| Affects the threat model? | yes — closes a session-disruption vector |

### Cross-references

SC-0006 (the re-contact rule this closes the hole in).
New vector: `first-contact-replay`.

## SC-0010 — Reference-code fixes from run 3 (2026-09-29)
- **Changed:** the reference only; the spec already said this. A malformed KEM offer that crosses the responder's own offer no longer cancels the responder's pending offer: the FIPS 203 key check now runs before any state change (C-006, `WIRE_FORMAT.md` §4.5, "a malformed offer changes no state"). A bundle whose ML-KEM public key fails the FIPS 203 check is now invalid on arrival, instead of failing only when someone first contacts its owner (C-012, §3).
- **Vectors:** every existing entry byte-identical; added `kem-step-responder-keeps-offer-on-malformed` and `bundle-reject-bad-mlkem-key`.
- **Existing implementations must:** check the offer's key before touching session state, and reject such bundles.

## SC-0009 — Late messages must use a stored skipped key first (2026-09-29)
- **Changed:** `WIRE_FORMAT.md` §4.1 receive order gains step (0): if a stored skipped key matches the message, it is used first, before any chain or DH-ratchet step. The reference always did this, but the numbered steps didn't say so, and followed literally they lost late messages sent under the peer's older ratchet key (C-003). PROTOCOL_SPEC's claim of a test for this case now points at a real vector.
- **Vectors:** every existing entry byte-identical; added `ratchet-late-from-older-ratchet-key`.
- **Existing implementations must:** try stored skipped keys before anything else.

## SC-0008 — Grace period counts as Plus for timer and screenshot rules (Kaspaguy, 2026-09-30; C-005)
- **Changed:** `PROTOCOL_SPEC.md` §8.1 and §8.2: a name in its 30-day grace period counts as Plus for the timer and screenshot rules, so a late renewer's timer doesn't flip mid-grace. The check compares the expiry the registry stores (DAA score) with the DAA score of the latest block the app knows, whether or not a `reclaim` has landed yet. `WIRE_FORMAT.md` §7.1 points to it.
- **Vectors:** unchanged (the tier is an input to `settings-effective`, which already takes it from the registry).
- **Existing implementations must:** treat expiry + 30 days, not expiry, as the end of Plus when computing effective settings.

## SC-0007 — Conversation settings: version 0x02 adds a context byte

**Date:** 2026-09-30
**Files changed:** `WIRE_FORMAT.md` §7.1
**Source:** third-run follow-up (owner decision)
**Status:** applied

### What changed

Kind 0x06 now has two versions:

- **Version 0x01** — the original 1:1-only form: `version u8 ‖ epoch u32 ‖
  flags u8`. Byte-identical to the existing vectors (nothing has been
  published yet); unchanged.
- **Version 0x02** — adds a context byte: `version u8 ‖ epoch u32 ‖
  context u8 ‖ contextData ‖ flags u8`. `context = 0x00` means the settings
  apply to the 1:1 session and `contextData` is empty; `context = 0x01`
  means they apply to a group and `contextData` is the 16-byte group ID.

Both versions are accepted; version 0x02 is preferred for new settings.
A client that understands only 0x01 ignores 0x02 messages.

Receivers keep preferences per member and per context, whichever version
carried them (a 0x01 body counts as context 0x00). Group settings are sent to
every other member like a group text, count only while the sender is a
current member, and are held until the group's state arrives (§7.1).

### Why

Without a context, a member's timer and screenshot preferences arrived over
their 1:1 session with no way to tell whether they applied to the 1:1 chat or
to a group. Two apps could compute different deletion timers, contradicting
the spec's promise that "every app computes the same effective settings."

The format was versioned rather than changed in place, to keep the
test-vector freeze rule intact: the version 0x01 vectors stay byte-identical.

### Impact

| Question | Answer |
|---|---|
| Invalidates v1 test vectors? | no — 0x01 unchanged; three new 0x02 vectors added |
| Requires contract recompilation? | no |
| Requires registry migration (if deployed)? | no |
| Affects existing implementations? | yes — implementations must dispatch on the version byte |
| Affects the threat model? | no |

### Cross-references

Third-run ambiguity C-002. Group ID format: `WIRE_FORMAT.md` §4.6.
New vectors: `settings-encode-v2`, `settings-encode-group`, `settings-reject-v2`.
This replaces an earlier draft of SC-0007 (same day) that put the context byte
into version 0x01 and changed `settings-encode` and `settings-reject` in place;
that draft was never published and both vectors are back to their original bytes.
`settings-reject`'s description was then corrected (Kaspaguy, 2026-09-30): it
called `020000000701` a "wrong version", but version 0x02 is now valid; that
body is rejected for being one byte too short for any 0x02 context. Its
contents and results are unchanged; only the description text differs, as with
the `transaction-relay-paid` description fix in run 3.

## SC-0006 — Crossing first contacts, and re-contact after a restore (Kaspaguy, 2026-09-30; C-001)
- **Changed:** `WIRE_FORMAT.md` §4.2. The lower-tag rule now applies only when our current session with that peer is a first contact we sent and have received nothing on (we're the initiator and have no receiving chain yet). Any other first contact from a known peer replaces our session: the new one becomes active, the old one receive-only for 7 days, then discarded, keys included. This covers a peer that restored from its phrase, which can't be told apart from a crossing. Kaspaguy's sentence "the same treatment applies to the session the restored peer had" was replaced: the restored peer has no copy of its old session (the phrase restores identity and keys, not sessions), so the text now says what the receive-only period actually protects (messages from the peer's old device still in flight) and what it can't (anything we sent that the old device never received). Kept from B-001: tags compared bytewise as unsigned big-endian; a receive-only session sends nothing, KEM offers and answers included; what arrives on it is attributed to the conversation as normal.
- **Reference:** added `pendingFirstContact(session)` and `onFirstContactFromKnownPeer(current, currentTag, receivedTag)` → `keep-current` | `use-new`.
- **Vectors:** every existing entry byte-identical; added `first-contact-recontact` (both crossing views, and two re-contacts where the lower-tag rule alone would have kept the dead session). 46 in all.
- **Existing implementations must:** check whether their first contact is still pending before applying the lower-tag rule.

## 2026-09-29 — Run 3 findings resolved (independent Rust implementation, 41/41 vectors; still open from run 1: 0, from run 2: 0; 14 new: 0 high, 3 medium, 11 low)
- **Reference fixes:** see SC-0010. **Late messages (C-003):** see SC-0009.
- **Pinned:** the tag window is the not-yet-received indices `tag_in` … `tag_in` + 63, which is what the reference watches, receivers may watch further (C-004; the text said "at least 64 unreceived", which the reference didn't do); skipped-key expiry boundary and clock (C-007); skip limit per chain touched, no total cap (C-008); unknown version bytes (C-009); which files are informative (C-010); prekeys rotate no more often than every 7 days (C-013); the phrase restores identity and keys, not sessions (the §2 tension); PROTOCOL_SPEC §4 key-deletion wording, §5 payload names, and its test-4 claim corrected.
- **Vector file:** `format` gains the fixed clock, the op names and result shapes, `ad` and `initiator`, and the order of `skipped` entries (C-011, C-007); `transaction-relay-paid` description now says ⌈transient × 0.5⌉ (C-014). Every existing vector entry byte-identical; added `ratchet-late-from-older-ratchet-key`, `kem-step-responder-keeps-offer-on-malformed`, `bundle-reject-bad-mlkem-key`, `transaction-relay-paid-asymmetric-txid` (45 in all).
- **Decided by Kaspaguy on 2026-09-30:** C-001 (SC-0006), C-002 (SC-0007), C-005 (SC-0008).
- **Existing implementations must:** apply the above and reproduce the 4 new vectors.

## 2026-09-29 — Crossing first contacts (B-001) and skipped-key expiry (B-019), decided by Kaspaguy
- **Changed:** `WIRE_FORMAT.md` §4.2: when two peers each send a first contact at the same time, both keep the session whose first-contact tag is lower (bytewise, unsigned); the other is receive-only for 7 days (the delivery window), then discarded entirely, keys included; messages received on it are attributed to the conversation as normal; it is never used to send (including KEM offers and answers). §4.1: skipped message keys are deleted 7 days after they were stored, alongside the skipped-key limit.
- **Reference:** `crossingKeeps(sentTag, receivedTag)`; skipped keys now carry a local storage time and `expireSkipped()` runs at every decrypt (the storage time is local state, not part of the vector harness).
- **Vectors:** every existing vector byte-identical; added `first-contact-crossing` (41 in all). Expiry isn't in a vector: vectors run with a fixed clock (`now` = 0), so it is covered by the reference's unit tests.
- **Existing implementations must:** implement both rules and reproduce `first-contact-crossing`.

## 2026-09-29 — Run 2 findings resolved (independent Rust implementation, fixed spec: 34/34 vectors; run 1: 16 resolved, 8 resolved differently as intended, 1 still open; 19 new: 0 high, 3 medium, 16 low)
- **"Resolved differently" (8):** in every case the fixed text pinned the opposite of run 1's guess; run 2 found no fix ambiguous. Run 1's crate is replaced by run 2's in `rust-impl/` (run 1's report kept in `rust-impl/run1/`).
- **Still open (A-022, harness only):** harness session-state shapes now in a WIRE_FORMAT appendix, not only the vector `format` block.
- **Contradictions fixed:** "rejected" in §7/§4.6 now means the content is discarded while the message still counts as received (B-002); group texts need a seen state at their epoch listing both sender and receiver, replacing the self-contradicting pair of rules (B-005, **ref changed**: `receiveGroupText` takes the receiver); the vector randomness rule for offers corrected (B-007).
- **Pinned:** `spkId` = prekey number n, starting at 1, previous = n − 1 (B-003); current bundle = highest `created`, ties highest `spkId`, >24 h future ignored (B-004); KEM due-policy counting, no offer while holding `SS` (B-006); relay output has no covenant binding, epoch start E × 25,920,000, lock_time range (B-008); invalid UTF-8 shown with U+FFFD, message still received (B-009); v1 bundles carry no devices, receivers ignore 0–20 (B-010); publications with a wrong tag or marker ignored (B-011); settings `epoch` is now the Unix time in seconds of the change, so a restored client needs no counter (B-012; previously "goes up by one"); dummy first-contact format (B-013, **ref added**: `coverFirstContact`); SPEC_CHANGELOG ships with the spec, relay signature script opaque to clients (B-014); rusty-kaspa commit pinned, ⌈transient × 0.5⌉, Kaspa's ID/size layouts out of scope for clients (B-015); default-name `n` is one byte (B-016, **ref added**: `defaultName`, cross-checked against the contract's rule); English wordlist, exactly 24 words (B-017, **ref changed**: `identityFromMnemonic` rejects others and no longer takes a passphrase); tag chain and `pqEpoch` checked independently (B-018).
- **Open for Kaspaguy:** B-001 (two first contacts crossing: which session a pair keeps) and B-019 (skipped keys are never evicted, against the delete-keys aim).
- **Vectors:** every existing vector byte-identical; 6 added: `ratchet-receiver-edge-cases` (non-zero padding rejected; reserved header bytes, kind 0x07 and kind 0x02 received), `ratchet-reject-low-order-ratchet-key`, `first-contact-reject-low-order`, `group-state-duplicate-identity-key`, `cover-first-contact`, `registry-default-names` (40 in all).
- **Existing implementations must:** apply the rules above and reproduce the 6 new vectors.

## 2026-09-29 — KEM mix point: full sequence (A-017, Kaspaguy)
- **Changed:** `WIRE_FORMAT.md` §4.5 gains Kaspaguy's one-line rule (verbatim) and a 7-step sequence, including the answer-on-a-new-ratchet-key case (3b). The draft sequence Kaspaguy supplied was corrected in three places to match the code and the vectors: `pqEpoch` changes only at the moment a side mixes (not when offering or encapsulating); Alice's messages between the answer and her mix carry E − 1; at his mix Bob re-keys his *outgoing* tag chain (he has watched Alice's re-keyed chain since encapsulating).
- **Summary sentence (Kaspaguy)** added above the sequence; its last clause corrected so watching the peer's re-keyed chain starts when `SS` is known, not at a party's own mix (otherwise the answerer could never see the message that triggers its mix).
- **Vectors:** unchanged.
- **Existing implementations must:** nothing, if they already reproduce `kem-step-full`.

## 2026-09-29 — Second-implementation findings resolved (independent Rust implementation: 31/31 vectors, 25 ambiguities)
Every ambiguity is now pinned in the text to the reference implementation's behaviour, except where the reference itself was wrong (marked **ref fixed**). Numbers are the report's (`rust-impl/AMBIGUITIES.md`).
- **Vector vs spec (spec was right):** the transaction vector's fee formula wrongly included storage mass; Kaspa's rule is 100 × max(compute, normalized transient) (A-023). Vector description and `tools/lanecheck` fixed; the value (527,000) is unchanged.
- **High:** ML-KEM seeds are `d ‖ z` for KeyGen_internal (A-003, §1–§2); the first contact is message N = 0 and uses no tag index, tag counters restart only at a KEM step (A-011, §4.1–§4.2); the offerer mixes `SS` into the sending chain of its **next** DH step after the one carrying the answer, with a sequence (A-017, §4.5).
- **Medium:** empty BIP-39 passphrase, always (A-005); header `flags` and trailing bytes reserved, senders 0, receivers ignore; "signed" flag marked TODO (A-008); eager ratchet steps and Bob's initial ratchet spelled out (A-010); name field layout and receiver bounds (A-012, **ref fixed**: receivers now reject a length of 0 or over 20); body padding must be zero, every kind is accepted as received and unknown kinds are ignored, 0x02 now "ignored" instead of "rejected" (A-013); `pqEpoch` receive rule (A-018); KEM state table incl. re-offers (A-019); settings `epoch` = per-member counter, highest wins, default before any preference, timer 108,000 s (A-021); Kaspa consensus files cited normatively for ID/size/mass and fee, 100 g per compute-budget unit (A-023).
- **Low:** owner-key label and validity (A-001); KDF defaults (A-002); unclamped X25519 secrets (A-004); bundle limits, `created` unit, device entries (A-006, **ref fixed**: `nDevices` > 20 rejected); BIP-340 message and aux (A-007, **ref fixed**: bundles now use fresh aux instead of zeros; vectors keep explicit zeros); rk/ck split and the message key used directly (A-009); prekey order and `spkId` check (A-014); tag window, replays (A-015); skipped-key limit per chain per message (A-016); group duplicates by owner key, no own-membership check (A-020); harness shapes and new vectors with a skipped key and a pending offer (A-022); PROTOCOL_SPEC §5 bundle-marker exception (A-024); all-zero X25519 results and FIPS 203 key checks are errors (A-025, **ref fixed**: two paths threw instead of rejecting, a crash a hostile peer could trigger in `openFirstContact` and when answering a malformed KEM offer).
- **Vectors:** every existing vector byte-identical; added `ratchet-skipped-key-state`, `kem-step-offer-pending`, `kem-step-malformed-offer`; the transaction vector's description corrected.
- **Existing implementations must:** follow the pinned rules above. The Rust implementation diverges from them in four places the vectors don't reach: it rejects non-zero trailing header bytes (spec: ignore), doesn't check body padding (spec: reject non-zero), rejects unknown body kinds (spec: accept and ignore), accepts all-zero X25519 results (spec: reject), caps skipped keys at 1,000 per session (spec: per chain, per message) and treats a duplicate identity key or name in a group state as invalid (spec: owner keys only). To be aligned on the next run.

## 2026-09-29 — Vector file made self-describing (before the second implementation)
- **Changed:** `protocol/vectors/v1.json` restructured: a `format` block (encoding, ordering, named random inputs, session-state layout, result shapes) and 31 vectors, each `{id, kind, description, input, expected}` and runnable in isolation. Kinds: keys, bundle, buckets, first-contact, ratchet, kem-step, groups, conversation-settings, transaction. New coverage: prekey keys, bundle digest/signature and rejects, bucket cases, first-contact intermediates (DH1–3, ML-KEM secret, SK) and rejects, out-of-order + replay + late previous-chain delivery, tampering, crossing KEM offers, group receive rules, settings encode/reject/effective cases, and a relay-paid transaction (ID and masses from rusty-kaspa 2.1.0).
- **Randomness:** every random value is now a named input (`ephemeral_x25519_sk`, `mlkem_encaps_m`, `ratchet_x25519_sk`, `random_field`, `mlkem_keygen_seed`, `schnorr_aux`); the reference code's test-only generator is no longer needed to reproduce anything.
- **Vectors:** every byte string of the previous file (23) is present unchanged in the new one (checked). The layout changed, which the pre-publication rule allows since no existing entry's bytes changed.
- **Existing implementations must:** read the new layout; no protocol behaviour changed.

## 2026-09-29 — Protocol renamed Kasveil → Kaspaveil (names only)
- **Changed:** the protocol's name in every document and tool. `WIRE_FORMAT.md` §1 records that all labels keep their `kasveil/v1/` prefix permanently.
- **Vectors:** every entry byte-identical; only the file's `description` text now says Kaspaveil. No byte on the wire changes (labels, lane ID `KVL` 0x01 and vector seed labels are untouched).
- **Existing implementations must:** nothing.

## 2026-09-29 — Spec bug: 16-byte hashes are BLAKE2b-128, not truncated BLAKE2b-256
- **Changed:** `WIRE_FORMAT.md` §1 defines `BLAKE2b-128` (output-length parameter 16) and §4.1, §4.2, §4.3, §4.5 now use it for the message tag, first-contact tag, bundle tag and KEM `offerId`. `PROTOCOL_SPEC.md` §6.1 had the same error and also omitted the `kasveil/v1/fc-tag` label; fixed. §6.1 also described ongoing tags as `HKDF(root, "tag" ‖ n)` from the ratchet root; corrected to the per-direction tag keys of `WIRE_FORMAT.md` §4.1/§4.5. The text previously said `BLAKE2b(…)[0..16]` (truncation), which gives different bytes. The reference code and vectors always used BLAKE2b-128; the text was wrong.
- **Vectors:** unchanged (they were always right).
- **Existing implementations must:** use BLAKE2b with a 16-byte output length for these four values. An implementation that followed the old text fails every tag in the vectors.
- **Found by:** a pre-implementation check of the spec against the reference code (the kind of ambiguity the second implementation is meant to surface).

## 2026-09-29 — Test-vector policy clarified
- **Changed:** `WIRE_FORMAT.md` §1: vectors are frozen from first publication; before that, a draft may add sections while every existing entry stays byte-identical; changing an existing entry is a new protocol version. (The KEM and group sections below were added under this rule.)
- **Existing implementations must:** nothing.

## 2026-09-29 — Groups (body kinds 0x03, 0x04)
- **Changed:** new `WIRE_FORMAT.md` §4.6; §7 kinds 0x03 and 0x04 defined; §4.2 first contacts may now carry kinds 0x03 and 0x04 as well as 0x01 (`openFirstContact` also returns the kind). `PROTOCOL_SPEC.md` §4: groups use pairwise fan-out (replaces the draft's "encrypt once, wrap the key per member").
- **Vectors:** new `group` section in `v1.json` (a group state and a group text over the vector session). Every earlier entry is byte-identical.
- **Existing implementations must:** implement §4.6, accept kinds 0x03/0x04 in a first contact, and reproduce `group`.
- **Status:** v1 is still a draft; nothing has been published.

## 2026-09-29 — KEM ratchet step (body kind 0x05)
- **Changed:** `WIRE_FORMAT.md` §4.1 header plaintext: bytes 41–44 (previously zero padding) now carry `pqEpoch u32`; 3 zero bytes remain. New §4.5 (KEM step); §7 kind 0x05 defined.
- **Vectors:** new `kem_step` section in `v1.json`. Every earlier entry is byte-identical (with no KEM step, `pqEpoch` is 0, the same bytes as the old padding).
- **Existing implementations must:** write `pqEpoch` into the header, implement §4.5, and reproduce `kem_step`. Implementations that never run a KEM step stay interoperable only until the peer runs one.
- **Status:** v1 is still a draft; nothing has been published.

## 2026-09-29 — Wire format v1 draft
- First version: keys from the phrase, bundle, first contact, ongoing messages, bundle publication, cover traffic, buckets, body kinds 0x01 and 0x06, test vectors.
