# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent cross-check of qv-dev-lan-pairing.txt (spec 0013; plans 0037, 0038, 0042).

Python 3 standard library only (hashlib, hmac). Run by hand, not in CI:

    python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py

From the vector inputs (P, nonces, VK, IDs, X-Wing ek/ct/ss), this script
recomputes every new-device and sync-mode handshake value and the sync-mode
proofs with its own canonical CBOR and HKDF, then
compares it with the file. It cannot check the *_record values (XChaCha20-
Poly1305 is not in the stdlib) or X-Wing itself (draft-11 KATs cover it).
It exits non-zero on any mismatch.
"""

import hashlib
import hmac
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def u(n):
    return head(0, n)


def b(x):
    return head(2, len(x)) + x


def t(s):
    s = s.encode()
    return head(3, len(s)) + s


def arr(*items):
    return head(4, len(items)) + b"".join(items)


def sha256(x):
    return hashlib.sha256(x).digest()


def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha512).digest()
        out += block
        i += 1
    return out[:length]


def mac1(key, msg):
    return hmac.new(key, msg, hashlib.sha512).digest()[:32]


def load():
    v = {}
    with open(os.path.join(HERE, "qv-dev-lan-pairing.txt")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                k, _, val = line.partition(" = ")
                v[k] = bytes.fromhex(val)
    return v


def main():
    v = load()
    p, nb, na = v["p"], v["nonce_b"], v["nonce_a"]
    vk, vault = v["vk"], v["vault_id"]
    gen = int.from_bytes(v["key_generation"], "big")
    ek, ct, ss = v["ek_b"], v["ct"], v["ss"]
    want = {}

    pid = hkdf(p, b"", arr(t("qv/lan-pair-id/v1")), 16)
    k_hello = hkdf(p, pid, arr(t("qv/lan-pair-mac/v1"), t("hello")))
    k_accept = hkdf(p, pid, arr(t("qv/lan-pair-mac/v1"), t("accept")))
    commit = sha256(arr(t("qv/lan-pair-commit/v1"), b(nb)))
    fields = [t("qv/lan-pair-hello/v1"), u(1), b(pid), u(0), b(commit), b(ek)]
    body = arr(*fields)
    hello = arr(*fields, b(mac1(k_hello, body)))
    hh = sha256(hello)
    transcript = arr(t("qv/lan-pair-accept/v1"), b(hh), b(na), b(ct))
    accept = arr(t("qv/lan-pair-accept/v1"), b(na), b(ct), b(mac1(k_accept, transcript)))
    ah = sha256(accept)
    th = sha256(arr(t("qv/lan-pair-th/v1"), b(hh), b(ah)))
    k_b2a = hkdf(ss + p, th, arr(t("qv/lan-pair-key/v1"), t("b2a")))
    k_a2b = hkdf(ss + p, th, arr(t("qv/lan-pair-key/v1"), t("a2b")))
    h = sha256(arr(t("qv/lan-pair-sas/v1"), b(th), b(nb)))
    sas = ("%06d" % (int.from_bytes(h[:4], "big") % 1_000_000)).encode()

    want.update(
        pairing_id=pid,
        k_hello=k_hello,
        k_accept=k_accept,
        commit_b=commit,
        hello_body=body,
        hello=hello,
        hello_hash=hh,
        accept_transcript=transcript,
        accept=accept,
        accept_hash=ah,
        th=th,
        k_b2a=k_b2a,
        k_a2b=k_a2b,
        sas=sas,
        reveal=arr(t("qv/lan-pair-reveal/v1"), b(nb)),
        grant=arr(t("qv/lan-pair-grant/v1"), b(vault), u(gen), b(vk)),
        error_integrity=arr(t("qv/lan-error/v1"), u(4)),
    )

    # The sync-mode handshake (0013 §4.8): mode 1, same inputs.
    sfields = [t("qv/lan-pair-hello/v1"), u(1), b(pid), u(1), b(commit), b(ek)]
    sbody = arr(*sfields)
    shello = arr(*sfields, b(mac1(k_hello, sbody)))
    shh = sha256(shello)
    stranscript = arr(t("qv/lan-pair-accept/v1"), b(shh), b(na), b(ct))
    saccept = arr(t("qv/lan-pair-accept/v1"), b(na), b(ct), b(mac1(k_accept, stranscript)))
    sah = sha256(saccept)
    sth = sha256(arr(t("qv/lan-pair-th/v1"), b(shh), b(sah)))
    k_proof = hkdf(vk, vault, arr(t("qv/purpose/v1"), t("lan-proof"), u(gen), u(1)))

    def proof(role):
        return mac1(k_proof, arr(t("qv/lan-pair-prove/v1"), b(sth), t(role), b(vault), u(gen)))

    want.update(
        sync_hello_body=sbody,
        sync_hello=shello,
        sync_hello_hash=shh,
        sync_accept_transcript=stranscript,
        sync_accept=saccept,
        sync_accept_hash=sah,
        sync_th=sth,
        k_proof=k_proof,
        proof_a=proof("a"),
        proof_b=proof("b"),
        prove=arr(t("qv/lan-pair-prove/v1"), b(vault), u(gen), b(proof("b"))),
        proved=arr(t("qv/lan-pair-proved/v1"), b(proof("a"))),
    )
    bad = [k for k, x in want.items() if v.get(k) != x]
    # Record lengths: plaintext + 16-byte tag (0013 §6).
    for rec, msg in (
        ("reveal_record", "reveal"),
        ("grant_record", "grant"),
        ("error_record", "error_integrity"),
        ("prove_record", "prove"),
        ("proved_record", "proved"),
    ):
        if len(v[rec]) != len(want[msg]) + 16:
            bad.append(rec)
    if bad:
        print("MISMATCH:", ", ".join(bad))
        return 1
    print("OK: %d values recomputed independently" % len(want))
    return 0


if __name__ == "__main__":
    sys.exit(main())
