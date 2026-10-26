#!/usr/bin/env python3
"""Debugger scenarios for payment.sil (SC-0018)."""
import json, sys
KAS = 100_000_000
DEV = bytes.fromhex("20" + "11" * 32 + "ac")
RES = bytes.fromhex("aa20" + "33" * 32 + "87")
OTHER = bytes.fromhex("aa20" + "44" * 32 + "87")
ORDER = bytes([5] * 32)
MIN = 100 * KAS
LATE = 2_592_000
hx = lambda b: "0x" + b.hex()
ctor = [hx(ORDER), hx(bytes(2) + DEV), hx(bytes(2) + RES), MIN]

# inputs: (value, script or None, sequence = the relative lock settleLate needs; default 0)
def case(title, expect, inputs, outs, idx=0, fn="settle"):
    return {"name": title, "function": fn, "args": [], "expect": expect, "constructor_args": ctor,
            "tx": {"active_input_index": idx, "inputs": [{"utxo_value": i[0], "sequence": i[2] if len(i) > 2 else 0,
                   **({"utxo_script_hex": i[1].hex()} if i[1] else {})} for i in inputs],
                   "outputs": [{"value": v, "script_hex": s.hex()} for v, s in outs]}}

def split(total, fee=500_000, res_short=0, dev_short=0, res=RES, dev=DEV):
    t = total * 75 // 100
    return [(t - res_short, res), (total - t - fee - dev_short, dev)]

T = []
T.append(case("settle exactly the order amount: 75% treasury, 25% Kaspaguy less the fee", "pass", [(MIN, None)], split(MIN)))
T.append(case("settle two payments to the same order address (underpayment topped up)", "pass", [(60 * KAS, None), (40 * KAS, None)], split(MIN)))
T.append(case("settle the same two payments, checked from the second input", "pass", [(60 * KAS, None), (40 * KAS, None)], split(MIN), idx=1))
T.append(case("settle an overpayment (all of it split)", "pass", [(130 * KAS, None)], split(130 * KAS)))
T.append(case("settle below the order amount", "fail", [(MIN - 1, None)], split(MIN - 1)))
T.append(case("treasury share 1 sompi short", "fail", [(MIN, None)], split(MIN, res_short=1)))
T.append(case("Kaspaguy's share short by more than the fee allowance", "fail", [(MIN, None)], split(MIN, fee=1_000_001)))
T.append(case("treasury share sent elsewhere", "fail", [(MIN, None)], split(MIN, res=OTHER)))
T.append(case("everything to Kaspaguy", "fail", [(MIN, None)], [(MIN - 500_000, DEV), (0, RES)]))
T.append(case("a third output (skimming)", "fail", [(MIN, None)], split(MIN) + [(1, OTHER)]))
T.append(case("mixing in an input from another script", "fail", [(MIN, None), (KAS, OTHER)], split(MIN + KAS)))
T.append(case("more than 8 inputs", "fail", [(MIN // 9 + 1, None)] * 9, split((MIN // 9 + 1) * 9)))
# SC-0024: nothing is stranded. A short or late payment settles on its own with settleLate, whose relative lock time
# (input sequence >= LATE) the network enforces: the spend is refused until the payment is 3 days old.
L = "settleLate"
T.append(case("a short payment settles on its own after 3 days", "pass", [(50 * KAS, None, LATE)], split(50 * KAS), fn=L))
T.append(case("a short payment with a lock one block short of 3 days", "fail", [(50 * KAS, None, LATE - 1)], split(50 * KAS), fn=L))
T.append(case("a second full payment after the order was settled", "pass", [(MIN, None, LATE)], split(MIN), fn=L))
T.append(case("a fresh short payment through settle (no lock)", "fail", [(30 * KAS, None, LATE), (20 * KAS, None)], split(50 * KAS), idx=1))
T.append(case("a fresh short payment through settleLate without the lock", "fail", [(30 * KAS, None, LATE), (20 * KAS, None)], split(50 * KAS), idx=1, fn=L))
T.append(case("settleLate still splits 75/25: treasury share 1 sompi short", "fail", [(50 * KAS, None, LATE)], split(50 * KAS, res_short=1), fn=L))
T.append(case("settleLate sending the treasury share elsewhere", "fail", [(50 * KAS, None, LATE)], split(50 * KAS, res=OTHER), fn=L))
T.append(case("settleLate mixing in an input from another script", "fail", [(50 * KAS, None, LATE), (KAS, OTHER, LATE)], split(51 * KAS), fn=L))
json.dump({"tests": T}, open(f"{sys.argv[1]}/payment.test.json", "w"), indent=1)
json.dump([{"kind": "bytes", "value": list(ORDER)}, {"kind": "bytes", "value": list(bytes(2) + DEV)}, {"kind": "bytes", "value": list(bytes(2) + RES)}, {"kind": "int", "value": MIN}], open(f"{sys.argv[1]}/payment.args.json", "w"))
print(f"tests {len(T)}")
