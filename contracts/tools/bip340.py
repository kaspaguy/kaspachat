"""BIP-340 Schnorr signing (reference algorithm) — test tooling only, never for real keys."""
import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def _mul(p, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = _add(r, p)
        p = _add(p, p)
    return r


def pubkey(seckey: bytes) -> bytes:
    return _mul(G, int.from_bytes(seckey, "big"))[0].to_bytes(32, "big")


def sign(msg32: bytes, seckey: bytes, aux: bytes = bytes(32)) -> bytes:
    d0 = int.from_bytes(seckey, "big")
    pt = _mul(G, d0)
    d = d0 if pt[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + pt[0].to_bytes(32, "big") + msg32), "big") % N
    r = _mul(G, k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(_tagged("BIP0340/challenge", r[0].to_bytes(32, "big") + pt[0].to_bytes(32, "big") + msg32), "big") % N
    return r[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")
