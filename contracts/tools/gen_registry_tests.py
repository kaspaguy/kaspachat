#!/usr/bin/env python3
"""Build debugger test scenarios for registry_shard.sil v2 (prototype). Real BIP-340 signatures."""
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bip340 import pubkey, sign  # noqa: E402

DEPTH = 20
ZERO = bytes(32)
MONTH_DAA = 25_920_000
NOW = 480_000_000
KAS = 100_000_000
REGISTRY_ID = bytes([7] * 32)
DEV_SK, REG_SK, PRICE_SK, ROOT_SK, OWNER_SK, NEW_OWNER_SK, EVE_SK, AUC_SK = (bytes([i] * 32) for i in (1, 2, 3, 4, 5, 6, 9, 11))
DEV, REG, PRICEK, ROOTK, OWNER, NEW_OWNER, EVE, AUC = (pubkey(k) for k in (DEV_SK, REG_SK, PRICE_SK, ROOT_SK, OWNER_SK, NEW_OWNER_SK, EVE_SK, AUC_SK))
GRACE_DAA = MONTH_DAA
HELD = 1
RESERVOIR_SCRIPT = bytes.fromhex("aa20" + "33" * 32 + "87")       # one-month payments (sweeps after 30 days)
RESERVOIR_LONG_SCRIPT = bytes.fromhex("aa20" + "44" * 32 + "87")  # 2-12 month prepayments (sweeps after 360 days)
PRICE = 100 * KAS


def h(b):
    return hashlib.blake2b(b, digest_size=32).digest()


def i8(v):
    return v.to_bytes(8, "little")


def leaf(key, nkey, nidx, owner, expiry, nonce):
    return h(i8(key) + i8(nkey) + i8(nidx) + owner + i8(expiry) + i8(nonce))


def name_key(name):
    return int.from_bytes(h(name)[:7], "little")


def shard(name):
    return name_key(name) >> 52


def domain(label, shard_id):
    return b"kasveil/v1/" + label + REGISTRY_ID + i8(shard_id)


ZEROS = [ZERO]
for _ in range(DEPTH):
    ZEROS.append(h(ZEROS[-1] + ZEROS[-1]))


class Tree:
    def __init__(self):
        self.leaves = {0: (0, 0, 0, ZERO, 0, 0)}

    def node(self, level, idx, cache):
        if (level, idx) in cache:
            return cache[(level, idx)]
        if level == 0:
            v = leaf(*self.leaves[idx]) if idx in self.leaves else ZERO
        elif not any(idx << level <= i < (idx + 1) << level for i in self.leaves):
            v = ZEROS[level]
        else:
            v = h(self.node(level - 1, 2 * idx, cache) + self.node(level - 1, 2 * idx + 1, cache))
        cache[(level, idx)] = v
        return v

    def root(self):
        return self.node(DEPTH, 0, {})

    def path(self, idx):
        c = {}
        return ["0x" + self.node(l, (idx >> l) ^ 1, c).hex() for l in range(DEPTH)]

    def insert(self, name, owner, expiry):
        key = name_key(name)
        low = next(i for i, (k, nk, *_r) in self.leaves.items() if k < key and (nk == 0 or key < nk))
        lk, lnk, lni, lo, le, ln = self.leaves[low]
        size = len(self.leaves)
        low_path = self.path(low)
        self.leaves[low] = (lk, key, size, lo, le, ln)
        new_path = self.path(size)
        self.leaves[size] = (key, lnk, lni, owner, expiry, 0)
        return [lk, lnk, lni, "0x" + lo.hex(), le, ln, low, low_path, new_path]

    def find(self, name):
        key = name_key(name)
        return next(i for i, l in self.leaves.items() if l[0] == key)


def default_name(owner, n):
    v = int.from_bytes(h(owner + bytes([n]))[:5], "big")
    return b"kv" + "".join("abcdefghijklmnopqrstuvwxyz234567"[(v >> (5 * (7 - i))) & 31] for i in range(8)).encode()


def state(t, **kw):
    s = {"root": "0x" + t.root().hex(), "size": len(t.leaves), "registrar": "0x" + REG.hex(), "priceKey": "0x" + PRICEK.hex(),
         "auctionKey": "0x" + AUC.hex(), "price": PRICE, "priceNonce": 0, "keyNonce": 0, "prepaidRegs": 0, "prepaidMonths": 0, "transfersOpen": 1}
    s.update(kw)
    return s


def ctor(shard_id):
    return ["0x" + ZERO.hex(), "0x" + REGISTRY_ID.hex(), shard_id, "0x" + DEV.hex(), "0x" + (bytes(2) + RESERVOIR_SCRIPT).hex(), "0x" + (bytes(2) + RESERVOIR_LONG_SCRIPT).hex(),
            "0x" + ROOTK.hex(), "0x" + REG.hex(), "0x" + PRICEK.hex(), "0x" + AUC.hex(), PRICE]


# utxo_daa is when the shard's UTXO was created (OpTxInputDaaScore); by default shortly before the transaction.
# Every shard UTXO carries its covenant ID (SC-0016); cov_out picks the continuation's binding:
# "keep" (output 0 bound), "drop" (output 0 unbound) or "fork" (a second output also bound).
COV = "0x" + "c0" * 32


def case(title, expect, fn, args, shard_id, before, after, extra_outputs=(), out_value=KAS, lock_time=NOW, utxo_daa=None, cov_out="keep"):
    utxo_daa = lock_time - 1_000 if utxo_daa is None else utxo_daa
    out0 = {"value": out_value, "state": after}
    if cov_out != "drop":
        out0.update(covenant_id=COV, authorizing_input=0)
    outs = [out0, *extra_outputs]
    if cov_out == "fork":
        outs.append({"value": KAS, "state": after, "covenant_id": COV, "authorizing_input": 0})
    return {"name": title, "function": fn, "args": args, "expect": expect, "constructor_args": ctor(shard_id),
            "tx": {"lock_time": lock_time, "inputs": [{"utxo_value": KAS, "utxo_daa_score": utxo_daa, "state": before, "covenant_id": COV}],
                   "outputs": outs}}


def pay(months, dev_short=0, res_short=0, price=PRICE, reservoir=None):
    total = months * price
    res = reservoir or (RESERVOIR_SCRIPT if months == 1 else RESERVOIR_LONG_SCRIPT)
    return ({"value": total * 25 // 100 - dev_short, "script_hex": "20" + DEV.hex() + "ac"},
            {"value": total * 75 // 100 - res_short, "script_hex": res.hex()})


def hx(b):
    return "0x" + b.hex()


def main(out_dir):
    tests = []

    # --- registerDirect ---
    t = Tree()
    name = b"catch22"
    sid = shard(name)
    before = state(t)
    low = t.insert(name, OWNER, NOW + 3 * MONTH_DAA)
    after = state(t)
    rdd = h(domain(b"reg-direct", sid) + name + OWNER + i8(3) + i8(NOW))
    args = [hx(name), hx(OWNER), 3, NOW, hx(sign(rdd, REG_SK)), *low]
    tests.append(case("registerDirect catch22, 3 months at the state price", "pass", "registerDirect", args, sid, before, after, pay(3)))
    nobouncer = list(args); nobouncer[4] = hx(sign(rdd, EVE_SK))
    tests.append(case("registerDirect without the bouncer's signature (reserved list bypass)", "fail", "registerDirect", nobouncer, sid, before, after, pay(3)))
    tests.append(case("registerDirect dev share 1 sompi short", "fail", "registerDirect", args, sid, before, after, pay(3, dev_short=1)))
    tests.append(case("registerDirect treasury share 1 sompi short", "fail", "registerDirect", args, sid, before, after, pay(3, res_short=1)))
    tests.append(case("registerDirect on the wrong shard", "fail", "registerDirect", args, (sid + 1) % 16, before, after, pay(3)))
    tests.append(case("registerDirect 3 months paid to the one-month reservoir (would be swept too early)", "fail", "registerDirect", args, sid, before, after, pay(3, reservoir=RESERVOIR_SCRIPT)))
    tests.append(case("registerDirect draining the registry's own value", "fail", "registerDirect", args, sid, before, after, pay(3), out_value=KAS - 1))
    tests.append(case("registerDirect with the shard's continuation unbound from its covenant (lineage would end)", "fail", "registerDirect", args, sid, before, after, pay(3), cov_out="drop"))
    tests.append(case("registerDirect forking the shard into two bound continuations", "fail", "registerDirect", args, sid, before, after, pay(3), cov_out="fork"))

    # --- registerDefault (free names) ---
    for n in (0, 2):
        t = Tree()
        name = default_name(OWNER, n)
        sid = shard(name)
        before = state(t)
        low = t.insert(name, OWNER, 0)
        dd = h(domain(b"reg-default", sid) + name + OWNER)
        args = [hx(name), hx(OWNER), n, hx(sign(dd, REG_SK)), *low]
        tests.append(case(f"registerDefault @{name.decode()} (re-roll {n}), free, never expires", "pass", "registerDefault", args, sid, before, state(t)))
        if n == 0:
            tests.append(case("registerDefault without the bouncer's signature", "fail", "registerDefault",
                              args[:3] + [hx(sign(dd, EVE_SK))] + args[4:], sid, before, state(t)))
            eve_name = default_name(EVE, 0)
            t2 = Tree(); b2s = state(t2); low2 = t2.insert(eve_name, OWNER, 0)
            dd2 = h(domain(b"reg-default", shard(eve_name)) + eve_name + OWNER)
            tests.append(case("registerDefault squatting someone else's derived name", "fail", "registerDefault",
                              [hx(eve_name), hx(OWNER), 0, hx(sign(dd2, REG_SK)), *low2], shard(eve_name), b2s, state(t2)))
            chosen = b"kvabcdefgh"
            t3 = Tree(); b3s = state(t3); low3 = t3.insert(chosen, OWNER, 0)
            dd3 = h(domain(b"reg-default", shard(chosen)) + chosen + OWNER)
            tests.append(case("registerDefault with a hand-picked kv name", "fail", "registerDefault",
                              [hx(chosen), hx(OWNER), 0, hx(sign(dd3, REG_SK)), *low3], shard(chosen), b3s, state(t3)))
    t = Tree()
    tests.append(case("registerDefault with a third re-roll (n = 3)", "fail", "registerDefault",
                      [hx(default_name(OWNER, 0)), hx(OWNER), 3, hx(bytes(64)), 0, 0, 0, hx(ZERO), 0, 0, 0, t.path(0), t.path(1)],
                      shard(default_name(OWNER, 0)), state(t), state(t)))

    # --- registerPrepaid ---
    t = Tree()
    name = b"dog-cat-21"
    sid = shard(name)
    before = state(t)
    low = t.insert(name, OWNER, NOW + 2 * MONTH_DAA)
    after = state(t, prepaidRegs=1, prepaidMonths=2)
    d = h(domain(b"reg-prepaid", sid) + name + OWNER + i8(2) + i8(NOW))
    good = [hx(name), hx(OWNER), 2, NOW, hx(sign(d, REG_SK)), *low]
    tests.append(case("registerPrepaid with the registrar's signature, counters go up", "pass", "registerPrepaid", good, sid, before, after))
    bad = list(good); bad[4] = hx(sign(d, EVE_SK))
    tests.append(case("registerPrepaid signed by a non-registrar", "fail", "registerPrepaid", bad, sid, before, after))
    tests.append(case("registerPrepaid hiding it from the public counters", "fail", "registerPrepaid", good, sid, before, state(t)))
    bad = list(good); bad[2] = 12
    tests.append(case("registerPrepaid stretching a 2-month voucher to 12", "fail", "registerPrepaid", bad, sid, before, state(t, prepaidRegs=1, prepaidMonths=12)))

    # --- renewals and transfer on an existing name ---
    t = Tree()
    name = b"fat-32"
    sid = shard(name)
    exp = NOW + MONTH_DAA
    t.insert(name, OWNER, exp)
    idx = t.find(name)
    k, nk, ni, ow, ex, no = t.leaves[idx]
    path = t.path(idx)
    base = [k, nk, ni, hx(ow), ex, no, idx, path]
    before = state(t)

    r = copy.deepcopy(t); r.leaves[idx] = (k, nk, ni, ow, ex + 6 * MONTH_DAA, no)
    tests.append(case("renewDirect 6 months extends from the current expiry", "pass", "renewDirect", base + [6], sid, before, state(r), pay(6)))
    tests.append(case("renewDirect underpaid", "fail", "renewDirect", base + [6], sid, before, state(r), pay(6, res_short=1)))
    r1 = copy.deepcopy(t); r1.leaves[idx] = (k, nk, ni, ow, ex + MONTH_DAA, no)
    tests.append(case("renewDirect 1 month to the one-month reservoir", "pass", "renewDirect", base + [1], sid, before, state(r1), pay(1)))
    tests.append(case("renewDirect 1 month paid to the prepayment reservoir", "fail", "renewDirect", base + [1], sid, before, state(r1), pay(1, reservoir=RESERVOIR_LONG_SCRIPT)))

    rd = h(domain(b"renew-prepaid", sid) + i8(k) + i8(ex) + i8(1))
    r1 = copy.deepcopy(t); r1.leaves[idx] = (k, nk, ni, ow, ex + MONTH_DAA, no)
    tests.append(case("renewPrepaid with the registrar's signature", "pass", "renewPrepaid", base + [1, hx(sign(rd, REG_SK))], sid, before, state(r1, prepaidMonths=1)))
    tests.append(case("renewPrepaid signed by a non-registrar", "fail", "renewPrepaid", base + [1, hx(sign(rd, EVE_SK))], sid, before, state(r1, prepaidMonths=1)))

    # Renewal cut-off: the shard's UTXO must have been created by the end of grace (expiry + 30 days).
    # This is a lower bound on "now", so the cut-off is soft: it bites once anyone touches the shard after grace.
    rr = copy.deepcopy(t); rr.leaves[idx] = (k, nk, ni, ow, ex + MONTH_DAA, no)
    g = ex + GRACE_DAA
    tests.append(case("renewDirect on the last block of grace (shard touched at grace end)", "pass", "renewDirect", base + [1], sid, before, state(rr), pay(1),
                      lock_time=g + 1_000, utxo_daa=g))
    tests.append(case("renewDirect after grace (shard touched one block after grace)", "fail", "renewDirect", base + [1], sid, before, state(rr), pay(1),
                      lock_time=g + 1_000, utxo_daa=g + 1))
    tests.append(case("renewPrepaid after grace (shard touched one block after grace)", "fail", "renewPrepaid", base + [1, hx(sign(rd, REG_SK))], sid, before,
                      state(r1, prepaidMonths=1), lock_time=g + 1_000, utxo_daa=g + 1))
    tests.append(case("renewDirect after grace on a shard untouched since before grace ended (soft cut-off)", "pass", "renewDirect", base + [1], sid, before,
                      state(rr), pay(1), lock_time=g + MONTH_DAA, utxo_daa=g - 1_000))

    td = h(domain(b"transfer", sid) + i8(k) + NEW_OWNER + i8(no))
    tr = copy.deepcopy(t); tr.leaves[idx] = (k, nk, ni, NEW_OWNER, ex, no + 1)
    tests.append(case("transfer signed by the owner", "pass", "transfer", base + [hx(NEW_OWNER), hx(sign(td, OWNER_SK))], sid, before, state(tr)))
    tests.append(case("transfer signed by someone else", "fail", "transfer", base + [hx(NEW_OWNER), hx(sign(td, EVE_SK))], sid, before, state(tr)))
    # Replay: after A->B and B->A the nonce is 2, so A's original signature (nonce 0) is dead.
    back = copy.deepcopy(t); back.leaves[idx] = (k, nk, ni, OWNER, ex, 2)
    rbase = [k, nk, ni, hx(OWNER), ex, 2, idx, back.path(idx)]
    rt = copy.deepcopy(back); rt.leaves[idx] = (k, nk, ni, NEW_OWNER, ex, 3)
    tests.append(case("transfer replaying an old signature", "fail", "transfer", rbase + [hx(NEW_OWNER), hx(sign(td, OWNER_SK))], sid, state(back), state(rt)))
    # SC-0017: transfers closed until the root opens them (once).
    tests.append(case("transfer while transfers are closed (owner-signed)", "fail", "transfer", base + [hx(NEW_OWNER), hx(sign(td, OWNER_SK))], sid,
                      state(t, transfersOpen=0), state(tr, transfersOpen=0)))

    # --- resale: 7.5% from each side to Kaspaguy ---
    payout = bytes.fromhex("20" + "55" * 32 + "ac")
    sale = 1000 * KAS
    sd = h(domain(b"sell", sid) + i8(k) + NEW_OWNER + i8(sale) + bytes(2) + payout + i8(no))
    sold = copy.deepcopy(t); sold.leaves[idx] = (k, nk, ni, NEW_OWNER, ex, no + 1)
    def sale_outs(fee_short=0, seller_short=0, payout_hex=payout.hex()):
        return ({"value": sale * 15 // 100 - fee_short, "script_hex": "20" + DEV.hex() + "ac"},
                {"value": sale * 925 // 1000 - seller_short, "script_hex": payout_hex})
    sargs = base + [hx(NEW_OWNER), sale, hx(bytes(2) + payout), hx(sign(sd, OWNER_SK))]
    tests.append(case("sell: seller paid 92.5%, Kaspaguy 15%, name moves", "pass", "sell", sargs, sid, before, state(sold), sale_outs()))
    tests.append(case("sell while transfers are closed", "fail", "sell", sargs, sid, state(t, transfersOpen=0), state(sold, transfersOpen=0), sale_outs()))
    tests.append(case("sell: Kaspaguy's 15% one sompi short", "fail", "sell", sargs, sid, before, state(sold), sale_outs(fee_short=1)))
    tests.append(case("sell: seller's 92.5% one sompi short", "fail", "sell", sargs, sid, before, state(sold), sale_outs(seller_short=1)))
    tests.append(case("sell: payout redirected to another address", "fail", "sell", sargs, sid, before, state(sold), sale_outs(payout_hex="20" + "66" * 32 + "ac")))
    lowball = list(sargs); lowball[9] = sale // 10
    tests.append(case("sell: buyer claims a lower price than the seller signed", "fail", "sell", lowball, sid, before, state(sold), sale_outs()))
    forged = list(sargs); forged[11] = hx(sign(sd, EVE_SK))
    tests.append(case("sell: not signed by the owner", "fail", "sell", forged, sid, before, state(sold), sale_outs()))
    # Sale cut-off: the shard's UTXO must have been created by the name's expiry (same soft bound as renewals).
    tests.append(case("sell on the name's last block (shard touched at expiry)", "pass", "sell", sargs, sid, before, state(sold), sale_outs(),
                      lock_time=ex + 1_000, utxo_daa=ex))
    tests.append(case("sell after expiry (shard touched one block after expiry)", "fail", "sell", sargs, sid, before, state(sold), sale_outs(),
                      lock_time=ex + 1_000, utxo_daa=ex + 1))

    # --- lapse, reclaim, auction, release: no special rules for auctioned names ---
    HOLD_DAA = 6 * MONTH_DAA
    held_since = ex + GRACE_DAA
    held = copy.deepcopy(t); held.leaves[idx] = (k, nk, ni, ZERO, held_since, no + 1)
    tests.append(case("reclaim after expiry + 30-day grace (anyone may call)", "pass", "reclaim", base, sid, before, state(held), lock_time=held_since))
    tests.append(case("reclaim one block before the grace period ends", "fail", "reclaim", base, sid, before, state(held), lock_time=held_since - 1))
    tests.append(case("reclaim (permissionless) with the continuation unbound from the covenant", "fail", "reclaim", base, sid, before, state(held), lock_time=held_since, cov_out="drop"))
    tests.append(case("reclaim (permissionless) forking the shard into two bound continuations", "fail", "reclaim", base, sid, before, state(held), lock_time=held_since, cov_out="fork"))
    ft = Tree(); fname = default_name(OWNER, 0); ft.insert(fname, OWNER, 0); fidx = ft.find(fname)
    fk, fnk, fni, fow, fex, fno = ft.leaves[fidx]
    fheld = copy.deepcopy(ft); fheld.leaves[fidx] = (fk, fnk, fni, ZERO, fex + GRACE_DAA, fno + 1)
    tests.append(case("reclaim a free name (free names never lapse)", "fail", "reclaim", [fk, fnk, fni, hx(fow), fex, fno, fidx, ft.path(fidx)],
                      shard(fname), state(ft), state(fheld), lock_time=10**11))
    hk, hnk, hni, how, hex_, hno = held.leaves[idx]
    hbase = [hk, hnk, hni, hx(how), hex_, hno, idx, held.path(idx)]
    held2 = copy.deepcopy(held); held2.leaves[idx] = (hk, hnk, hni, ZERO, hex_ + GRACE_DAA, hno + 1)
    tests.append(case("reclaim a name already held for auction", "fail", "reclaim", hbase, sid, state(held), state(held2), lock_time=10**11))
    hren = copy.deepcopy(held); hren.leaves[idx] = (hk, hnk, hni, ZERO, hex_ + MONTH_DAA, hno)
    tests.append(case("renew a held name (would stall its auction)", "fail", "renewDirect", hbase + [1], sid, state(held), state(hren), pay(1)))

    bid = 500 * KAS
    now2 = held_since + 1000
    won = copy.deepcopy(held); won.leaves[idx] = (hk, hnk, hni, NEW_OWNER, now2 + MONTH_DAA, hno + 1)
    def auc_sig(sk, key_nonce_bid=None, b=bid, n=hno, kk=hk):
        return hx(sign(h(domain(b"auction", sid) + i8(kk) + NEW_OWNER + i8(b) + i8(now2) + i8(n)), sk))
    def auc_outs(res_short=0, b=bid):
        return ({"value": b - PRICE * 75 // 100, "script_hex": "20" + DEV.hex() + "ac"},
                {"value": PRICE * 75 // 100 - res_short, "script_hex": RESERVOIR_SCRIPT.hex()})
    tests.append(case("settleAuction: winner gets 30 days; month's 75% to treasury, rest of bid to Kaspaguy", "pass", "settleAuction",
                      hbase + [hx(NEW_OWNER), bid, now2, auc_sig(AUC_SK)], sid, state(held), state(won), auc_outs(), lock_time=now2))
    tests.append(case("settleAuction: treasury's 75% of the month one sompi short", "fail", "settleAuction",
                      hbase + [hx(NEW_OWNER), bid, now2, auc_sig(AUC_SK)], sid, state(held), state(won), auc_outs(res_short=1), lock_time=now2))
    tests.append(case("settleAuction: not signed by the auction key", "fail", "settleAuction",
                      hbase + [hx(NEW_OWNER), bid, now2, auc_sig(REG_SK)], sid, state(held), state(won), auc_outs(), lock_time=now2))
    tests.append(case("settleAuction: bid below the reserve (one month's price)", "fail", "settleAuction",
                      hbase + [hx(NEW_OWNER), PRICE - 1, now2, auc_sig(AUC_SK, b=PRICE - 1)], sid, state(held), state(won), auc_outs(b=PRICE - 1), lock_time=now2))
    tests.append(case("settleAuction on a name nobody reclaimed", "fail", "settleAuction",
                      base + [hx(NEW_OWNER), bid, now2, auc_sig(AUC_SK, n=no, kk=k)], sid, before, state(won), auc_outs(), lock_time=now2))
    new_auc_sk = bytes([12] * 32); new_auc = pubkey(new_auc_sk)
    tests.append(case("settleAuction by a rotated-in auction key on a name held before the rotation", "pass", "settleAuction",
                      hbase + [hx(NEW_OWNER), bid, now2, auc_sig(new_auc_sk)], sid, state(held, auctionKey=hx(new_auc), keyNonce=1),
                      state(won, auctionKey=hx(new_auc), keyNonce=1), auc_outs(), lock_time=now2))
    pd_ = h(domain(b"auction-prepaid", sid) + i8(hk) + NEW_OWNER + i8(now2) + i8(hno))
    tests.append(case("settleAuctionPrepaid: paid with credits, public counter goes up", "pass", "settleAuctionPrepaid",
                      hbase + [hx(NEW_OWNER), now2, hx(sign(pd_, AUC_SK))], sid, state(held), state(won, prepaidMonths=1), lock_time=now2))
    htd = h(domain(b"transfer", sid) + i8(hk) + NEW_OWNER + i8(hno))
    tmoved = copy.deepcopy(held); tmoved.leaves[idx] = (hk, hnk, hni, NEW_OWNER, hex_, hno + 1)
    tests.append(case("transferring a held name without settlement", "fail", "transfer", hbase + [hx(NEW_OWNER), hx(sign(htd, AUC_SK))],
                      sid, state(held), state(tmoved)))

    # Holding is bounded: 6 months after the hold began, anyone may release an unsold name.
    rel = copy.deepcopy(held); rel.leaves[idx] = (hk, hnk, hni, ZERO, 1, hno + 1)
    tests.append(case("release an unsold name 6 months after the hold began", "pass", "release", hbase, sid, state(held), state(rel), lock_time=held_since + HOLD_DAA))
    tests.append(case("release one block before 6 months", "fail", "release", hbase, sid, state(held), state(rel), lock_time=held_since + HOLD_DAA - 1))
    tests.append(case("release a name that isn't held", "fail", "release", base, sid, before, state(rel), lock_time=10**11))
    rk_, rnk, rni, row, rex, rno = rel.leaves[idx]
    rbase = [rk_, rnk, rni, hx(row), rex, rno, idx, rel.path(idx)]
    now3 = held_since + HOLD_DAA + 100
    claimed = copy.deepcopy(rel); claimed.leaves[idx] = (rk_, rnk, rni, NEW_OWNER, now3 + 2 * MONTH_DAA, rno + 1)
    cd = h(domain(b"claim-direct", sid) + name + NEW_OWNER + i8(2) + i8(now3) + i8(rno))
    cargs = [hx(name), hx(NEW_OWNER), 2, now3, hx(sign(cd, REG_SK))] + rbase
    tests.append(case("claimReleasedDirect: a released name registers like a new one", "pass", "claimReleasedDirect", cargs, sid, state(rel), state(claimed), pay(2), lock_time=now3))
    tests.append(case("claimReleasedDirect without the doorman", "fail", "claimReleasedDirect", cargs[:4] + [hx(sign(cd, EVE_SK))] + rbase,
                      sid, state(rel), state(claimed), pay(2), lock_time=now3))
    tests.append(case("claimReleasedDirect on a name still held for auction", "fail", "claimReleasedDirect", cargs[:5] + hbase,
                      sid, state(held), state(claimed), pay(2), lock_time=now3))
    cpd = h(domain(b"claim-prepaid", sid) + name + NEW_OWNER + i8(2) + i8(now3) + i8(rno))
    tests.append(case("claimReleasedPrepaid: with credits, public counters go up", "pass", "claimReleasedPrepaid",
                      [hx(name), hx(NEW_OWNER), 2, now3, hx(sign(cpd, REG_SK))] + rbase, sid, state(rel), state(claimed, prepaidRegs=1, prepaidMonths=2), lock_time=now3))
    # Replays: the name's original registration signatures are public on-chain. Once it is released they must not claim
    # it (they would hand it back to the old owner, free on the prepaid path and already lapsed, ready to re-hold).
    replayed = copy.deepcopy(rel); replayed.leaves[idx] = (rk_, rnk, rni, OWNER, NOW + MONTH_DAA, rno + 1)
    orig_p = h(domain(b"reg-prepaid", sid) + name + OWNER + i8(1) + i8(NOW))
    tests.append(case("claimReleasedPrepaid replaying the name's original registerPrepaid signature", "fail", "claimReleasedPrepaid",
                      [hx(name), hx(OWNER), 1, NOW, hx(sign(orig_p, REG_SK))] + rbase, sid, state(rel), state(replayed, prepaidRegs=1, prepaidMonths=1), lock_time=now3))
    orig_d = h(domain(b"reg-direct", sid) + name + OWNER + i8(1) + i8(NOW))
    tests.append(case("claimReleasedDirect replaying the name's original registerDirect signature", "fail", "claimReleasedDirect",
                      [hx(name), hx(OWNER), 1, NOW, hx(sign(orig_d, REG_SK))] + rbase, sid, state(rel), state(replayed), pay(1), lock_time=now3))

    # After winning, the name is an ordinary Plus name: renews normally, and lapses and re-auctions the same way.
    wk, wnk, wni, wow, wex, wno = won.leaves[idx]
    wbase = [wk, wnk, wni, hx(wow), wex, wno, idx, won.path(idx)]
    wren = copy.deepcopy(won); wren.leaves[idx] = (wk, wnk, wni, wow, wex + MONTH_DAA, wno)
    tests.append(case("auction winner renews from day 31 like any Plus name", "pass", "renewDirect", wbase + [1], sid, state(won), state(wren), pay(1)))
    wheld = copy.deepcopy(won); wheld.leaves[idx] = (wk, wnk, wni, ZERO, wex + GRACE_DAA, wno + 1)
    tests.append(case("unrenewed auction win lapses back to auction after the same grace", "pass", "reclaim", wbase, sid, state(won), state(wheld),
                      lock_time=wex + GRACE_DAA))

    # --- price key ---
    t = Tree()
    sid = 0
    def price_case(title, expect, new_price, sk=PRICE_SK, nonce=0, cur=PRICE):
        pd = h(domain(b"price", sid) + i8(new_price) + i8(nonce))
        return case(title, expect, "setPrice", [new_price, hx(sign(pd, sk))], sid, state(t, price=cur, priceNonce=0),
                    state(t, price=new_price, priceNonce=1))
    tests.append(price_case("setPrice +50% (the limit)", "pass", 150 * KAS))
    tests.append(price_case("setPrice -50% (the limit)", "pass", 50 * KAS))
    tests.append(price_case("setPrice +51%", "fail", 151 * KAS))
    tests.append(price_case("setPrice -51%", "fail", 49 * KAS))
    tests.append(price_case("setPrice below 10 KAS", "fail", 9 * KAS, cur=12 * KAS))
    tests.append(price_case("setPrice above 1,000 KAS", "fail", 1001 * KAS, cur=800 * KAS))
    tests.append(price_case("setPrice signed by another key", "fail", 120 * KAS, sk=EVE_SK))
    tests.append(price_case("setPrice replaying a used signature", "fail", 120 * KAS, nonce=1))

    # --- root rotation ---
    new_reg, new_price_key, new_auc = pubkey(bytes([7] * 32)), pubkey(bytes([8] * 32)), pubkey(bytes([12] * 32))
    rot = h(domain(b"rotate", sid) + new_reg + new_price_key + new_auc + i8(0))
    after = state(t, registrar=hx(new_reg), priceKey=hx(new_price_key), auctionKey=hx(new_auc), keyNonce=1)
    rargs = [hx(new_reg), hx(new_price_key), hx(new_auc)]
    od = h(domain(b"open-transfers", sid) + i8(0))
    tests.append(case("openTransfers signed by the root (one way)", "pass", "openTransfers", [hx(sign(od, ROOT_SK))], sid,
                      state(t, transfersOpen=0), state(t, transfersOpen=1, keyNonce=1)))
    tests.append(case("openTransfers signed by the registrar", "fail", "openTransfers", [hx(sign(od, REG_SK))], sid,
                      state(t, transfersOpen=0), state(t, transfersOpen=1, keyNonce=1)))
    tests.append(case("openTransfers again once open (nothing can close or re-open)", "fail", "openTransfers", [hx(sign(h(domain(b"open-transfers", sid) + i8(1)), ROOT_SK))], sid,
                      state(t, transfersOpen=1, keyNonce=1), state(t, transfersOpen=1, keyNonce=2)))
    tests.append(case("openTransfers sneaking in a key change", "fail", "openTransfers", [hx(sign(od, ROOT_SK))], sid,
                      state(t, transfersOpen=0), state(t, transfersOpen=1, keyNonce=1, registrar=hx(EVE))))
    tests.append(case("rotateKeys signed by the root (registrar, price and auction keys)", "pass", "rotateKeys", rargs + [hx(sign(rot, ROOT_SK))], sid, state(t), after))
    tests.append(case("rotateKeys signed by the registrar", "fail", "rotateKeys", rargs + [hx(sign(rot, REG_SK))], sid, state(t), after))
    tests.append(case("rotateKeys also changing the price", "fail", "rotateKeys", rargs + [hx(sign(rot, ROOT_SK))], sid, state(t),
                      state(t, registrar=hx(new_reg), priceKey=hx(new_price_key), auctionKey=hx(new_auc), keyNonce=1, price=PRICE * 2)))

    json.dump({"tests": tests}, open(f"{out_dir}/registry_shard.test.json", "w"), indent=1)
    json.dump([{"kind": "bytes", "value": list(ZERO)}, {"kind": "bytes", "value": list(REGISTRY_ID)}, {"kind": "int", "value": 0},
               {"kind": "bytes", "value": list(DEV)}, {"kind": "bytes", "value": list(bytes(2) + RESERVOIR_SCRIPT)}, {"kind": "bytes", "value": list(bytes(2) + RESERVOIR_LONG_SCRIPT)},
               {"kind": "bytes", "value": list(ROOTK)}, {"kind": "bytes", "value": list(REG)}, {"kind": "bytes", "value": list(PRICEK)},
               {"kind": "bytes", "value": list(AUC)}, {"kind": "int", "value": PRICE}], open(f"{out_dir}/registry_shard.args.json", "w"))
    print(f"tests {len(tests)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
