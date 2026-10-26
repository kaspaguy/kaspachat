# Root-key ceremony runbook (2-of-3 FROST)

The treasury and registry contracts check one ordinary Schnorr key, the **root key**. Nobody ever holds it whole. Three holders each keep one share on their own device, and any **two** of them together can sign. The root key's only jobs:
- replace the treasury's relay key when it is lost or stolen;
- rotate the registrar, price and auction keys.

**In normal operation the root is never used.** There is no monthly signing: since SC-0012 (2026-09-30) the treasury's throttle bounds what the relay key can spend, so the relay key no longer needs a monthly certificate. The throttle changes how often the root is needed, not whether it's needed: the holders keep their shares safe and are called only for a replacement, a repair or a refresh.

Tool: `kaspaveil-ceremony` (`tools/ceremony/`, FROST from the Zcash Foundation's `frost-secp256k1-tr` 3.0.0, BIP-340 signatures). Before mainnet this whole runbook is rehearsed once on testnet with the real people and devices (spec §10 item 6).

## Before you start
- **Three people, three physically separate devices.** Ideally offline laptops that never touch the internet after the tool is installed.
- **The same tool on every device.** Build it from the same source commit, and all three read out and compare the binary's SHA-256 hash before using it.
- **Folders on every device:**
  - `priv/`: stays on that device, never copied;
  - `xfer/`: the files that travel between devices, on a USB stick or by QR.
- Holder numbers are 1, 2 and 3. They're fixed for life, so write them down.

## A. Key generation (once)
1. **Each holder:** `kaspaveil-ceremony dkg1 <n> priv xfer`, then give `xfer/dkg1-from-<n>.json` to **both** other holders. Everyone must receive the *same* file from each holder, so compare hashes aloud.
2. **Each holder:** `kaspaveil-ceremony dkg2 <n> priv xfer`. This writes `dkg2-from-<n>-to-<j>.json` for each other holder *j*. **These two files are secret.** Hand each one only to holder *j*, in person, then delete it from the stick.
3. **Each holder:** `kaspaveil-ceremony dkg3 <n> priv xfer`. The command:
   - prints `ROOT KEY: …`;
   - saves your share in `priv/key.json`;
   - deletes the round-2 secrets.
4. **All three read their ROOT KEY aloud. They must be identical.** If they aren't, stop, delete everything and start again.
5. Record the root key in the ceremony log. The contracts are compiled with it (`kaspaveil_hot bytecode treasury_hot.sil <rootKey>`, and the registry's `rootKey`).
6. **Backups:** each holder backs up **only their own** `priv/key.json` (for example on an encrypted stick in a separate place). Never keep two shares in one place.

## B. Replacing the relay key (only when it is lost or stolen)
The relay operator supplies three things: the treasury spending pot's **covenant ID** (32-byte hex, published with the deployment), the **new relay public key** (32-byte hex) and the pot's current **replacement number** (its key nonce, readable from the chain; 0 for the first replacement). Any two holders sign, with one of them (or the operator) acting as coordinator. None of the files in this section is secret, so they can travel by message or email.
1. **Each of the two signers:** `kaspaveil-ceremony commit <n> priv xfer`, then give `commit-from-<n>.json` to the coordinator.
2. **Coordinator:** `kaspaveil-ceremony package xfer <potCov> <newRelayPub> <nonce> <i> <j>`, then give `package.json` to both signers.
3. **Each signer:** `kaspaveil-ceremony sign <n> priv xfer`. **Before you sign, read the screen:** check the pot, the replacement number and the new relay key against what the operator told you by a separate route (a phone call, for example). Give `share-from-<n>.json` to the coordinator. Your one-time nonce is deleted automatically, because a nonce must never be used twice.
4. **Coordinator:** `kaspaveil-ceremony aggregate xfer`. This checks the signature against the root key with libsecp256k1 and writes `replace-<nonce>.hex`. Send it to the relay operator, who submits the replacement (`kaspaveil-lanecheck pot-replace - <newrelaykey> <pot.state>` with the signature in `KASPAVEIL_REPLACE_SIG`). From the next block on, only the new relay key can pay message fees. The signature works once only (the pot's replacement number moves on).

## C. Share repair (RTS: Repairable Threshold Scheme)
Use this when a holder's share is **gone for good**: the device is destroyed, the file is deleted, or the backup is unreadable. The two remaining holders rebuild the missing share for the same seat (same holder number). The root key is never assembled anywhere, and neither helper learns the rebuilt share. It uses FROST's RTS (eprint 2017/1155) and needs both remaining holders (2 of 3).

**Repair makes the same share again. It does not cancel the old one.** If the old device might still exist somewhere (lost or stolen rather than destroyed), use a share refresh instead (section D), which makes every old share useless.

Roles: holder *L* lost their share; holders *A* and *B* help. *L* may be a new person taking over the seat.
1. **A:** `kaspaveil-ceremony repair1 A priv xfer L B`, and **B:** `kaspaveil-ceremony repair1 B priv xfer L A`. Each writes a secret file for the *other helper*: `repair1-from-A-to-B.json` goes to B only, and `repair1-from-B-to-A.json` goes to A only, in person, then deleted from the stick.
2. **A:** `kaspaveil-ceremony repair2 A priv xfer L B`, and **B:** `kaspaveil-ceremony repair2 B priv xfer L A`. Each writes a secret file for *L*: `repair2-from-A-to-L.json` and `repair2-from-B-to-L.json`. Hand both to L only, in person. The helpers' temporary values are deleted automatically.
3. **L:** gets a copy of the public `group-from-*.json` from a helper, then runs `kaspaveil-ceremony repair3 L priv xfer A B`.
   - The tool rebuilds the share, **checks it against the group's public record** and only then saves `priv/key.json`. A wrong or dishonest value from a helper stops it with `REPAIR FAILED`, and no key is written.
   - It prints the root key: **all three read it aloud and compare.**
4. **Prove it works:** L and one of the helpers sign a test replacement (section B, steps 1–4) for a **dummy pot ID of 64 zeros**, never the real pot's ID: a signature for the real pot stays valid until it is used, so it must never be made for a test. `aggregate` verifies the test signature against the root key; then delete it.
5. L makes a fresh backup of `priv/key.json` (section A.6).

## D. Share refresh (proactive rotation)
**When to use:** a holder's device is lost or stolen, and you don't know whether the share has been compromised. Refresh rotates every share to a fresh one, so any old share, including a thief's, becomes worthless.

**What it does:** all three holders run three rounds together. The root public key doesn't change, so the contracts stay compiled against the same key. Every old share is replaced.

**Critical:** refresh can't add a device that never held a share. Bringing a replacement device online is a keystore restore (the holder's own backup, A.6), or an RTS repair (§C) if there is no backup, **followed by** a refresh.

**Procedure:**
1. **All three holders:** `kaspaveil-ceremony refresh1 <n> priv xfer`, then exchange `refresh1-from-<n>.json` (public).
2. **All three holders:** `kaspaveil-ceremony refresh2 <n> priv xfer`. The round-2 secret files (`refresh2-from-<n>-to-<j>.json`) go **in person** to the right holder, with the same handling rules as DKG round 2: delete each one from the stick immediately after handing it over.
3. **All three holders:** `kaspaveil-ceremony refresh3 <n> priv xfer`. This writes the new share to `priv/key.new.json`; the old `priv/key.json` is left untouched for now.
4. **All three read the ROOT KEY aloud. It must match what it was before the refresh.** If it doesn't, stop, delete `priv/key.new.json` and carry on with the old shares. The tool also stops by itself if the root key or the threshold changed.
5. **Only after all three confirm:** each holder runs `kaspaveil-ceremony refresh-commit <n> priv xfer`. It checks that all three ended with the same group record, makes the new share `priv/key.json` and deletes the old one. Then securely destroy every old backup and make a fresh one (A.6).

**Safety checks in the tool:**
- the threshold must stay 2-of-3, and all three seats must be refreshed (CVE-2025-58359 affected the refresh functions in frost versions before 2.2.0; this tool pins 3.0.0);
- the root key must be unchanged;
- each share must actually change;
- no commit happens unless the three group records match.

## E. What can go wrong
- **One share destroyed or one holder gone:** the other two can still sign everything. Repair it promptly (section C), because a second loss would be fatal.
- **Two shares lost:** the root key is gone. Relay-paid sending carries on for as long as the relay key itself is safe, but a lost or stolen relay key could never be replaced, and the registrar, price and auction keys could never be rotated. The funds stay locked in the treasury, still only able to pay message fees. The contracts can't recover from this, which is why the shares live in three separate places with three separate people.
- **One share stolen or possibly copied:** harmless on its own, since it takes two. Retire it with a refresh (section D). Repair (section C) is not enough, because it recreates the same share.
- **A replacement signed for the wrong relay key:** whoever holds that key can burn fees at the throttled rate (spec §8.3) until a second replacement. The on-screen check in B.3 is there to stop this.
- **A stolen relay key before anyone notices:** it can burn at most the throttle's allowance per 1-hour interval (at least 20 KAS an hour), raised only slowly (about 1.76× a day). Replace it (section B) as soon as the indexer's treasury alert fires.

## Simulated runs
**Relay-key replacement (2026-09-30, since SC-0012):**
- `rehearse-sim.sh` now signs replacements throughout: key generation, a replacement by holders 1 and 2, holder 2's share lost and repaired, a replacement by the repaired holder, a corrupted repair refused, the stolen-share refresh, and the thief's old share refused. It passes.
- **On testnet-10:** the rehearsal's 2-of-3 key (`c7ad88c6…492d`) is the root of a testnet spending pot (covenant ID `f95d664d…fc7e`). Holders 1 and 3 signed replacement no. 0 with this runbook's section B, and the pot accepted it (`e29a4814…7432`). Replaying the same signature, and a replacement signed by a single non-root key, were both rejected by the node.

**Earlier: monthly certificates (2026-09-29, retired in SC-0012).** The records below concern the retired certificate design. The ceremony steps themselves (A, C, D) are unchanged.

### One machine, three folders (2026-09-29)
- DKG: all three holders computed the same root key.
- Holders 1 and 3 signed an epoch-22 certificate, which verified with libsecp256k1.
- The spent nonce was refused on reuse.
- A hot wallet compiled with the threshold root key accepted a spend with this certificate on the local rusty-kaspa 2.1.0 engine. The five attack spends failed there, as they should.

**On testnet-10 (2026-09-29):**
- The simulated ceremony's certificate paid two real 2 KB lane messages from a hot wallet whose root is the 2-of-3 group key:
  - funding `6be1cae5…850a`;
  - messages `4b43aa2d…36b7` and `c307e68d…c677`, payloads read back byte-identical.
- The node rejected withdrawal, wrong lane, old-epoch, future-epoch and uncertified spends.
- The fee was the same 0.00527 KAS as with a single root key: a threshold signature is an ordinary 64-byte Schnorr signature.

**Share repair tested (2026-09-29):**
- `rehearse-sim.sh`:
  - key generation, then holder 2's share is lost and repaired by holders 1 and 3;
  - the rebuilt share is byte-identical to the lost one;
  - no repair secrets are left anywhere;
  - the repaired holder co-signs a valid certificate;
  - a corrupted repair value is refused, with no key written.
- **On testnet-10:** holder 1's share in the ceremony above was deleted and repaired by holders 2 and 3. The repaired share co-signed a new epoch-22 certificate, which paid a real message (`f93400f9…174e`, payload identical on read-back).

**Refresh tested (2026-09-29):**
- `rehearse-sim.sh` stolen-share drill: the root key is unchanged, all shares are replaced, and no refresh secrets are left; the refreshed shares sign; the thief's old share plus a refreshed share is refused (`InvalidSignatureShare`).
- **On testnet-10:** holder 2's share was copied to a "thief" folder and all three holders refreshed. The root key stayed `a933230e…`. The thief's share with refreshed holder 3 produced no certificate. Refreshed holders 2 and 3 signed one that paid a real message (`cf7e2cad…d8aa`, payload identical on read-back).

## F. The real rehearsal (three people, three devices, testnet, before mainnet)
Run everything once for real, using a throwaway testnet root:
1. **Key generation** (A).
2. **Create a testnet spending pot** with the root key and a throwaway relay key (`kaspaveil-lanecheck pot-genesis`), fund its reservoir, top it up, and have the operator pay one testnet message with the relay key.
3. **Relay-key replacement** (B), signed by two holders; the operator submits it. The old relay key is refused, and the new one pays a second testnet message.
4. **Share repair** (C): one holder deletes their share (on the throwaway root only), and the other two repair it.
5. **Replacement signed by the repaired holder** plus one other (replacement no. 1); the operator submits it and pays a third testnet message with the newest relay key.
6. **D.2 refresh drill (stolen device):** treat H3's share as compromised: H3 hands a copy to a "thief" folder, then carries on with their own copy (the restore). All three run a refresh (D). Confirm:
   - the root public key is unchanged;
   - the refreshed shares sign a replacement (no. 2), and the operator pays a fourth testnet message after submitting it;
   - **H3's old share can't combine with the refreshed set to sign** (the coordinator's `aggregate` refuses it).
7. Write down in the ceremony log:
   - who held which seat;
   - the hash of the tool binary;
   - the root key and the pot's covenant ID;
   - all transaction IDs;
   - anything in this runbook that was unclear.
