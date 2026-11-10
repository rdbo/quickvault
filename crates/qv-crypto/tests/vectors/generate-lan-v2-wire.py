#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent canonical wire/transcript fixtures, not successful PAKE sessions.

Uses cryptography50.0.0 and cbor2 6.2.1. The X-Wing public inputs come from
our pinned draft11 fixture; opaque messages and slot ciphertext are synthetic
shape inputs. Production authentication/slot verification must still reject
invalid credentials; these vectors check wire bytes, MACs and transcripts.
"""
import hashlib
import hmac
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def enc(value):
    return cbor2.dumps(value, canonical=True)


def digest(value):
    return hashlib.sha256(enc(value)).digest()


def kdf(key, salt, info, size=32):
    return HKDF(algorithm=hashes.SHA512(), length=size, salt=salt, info=enc(info)).derive(key)


def mac(key, value):
    return hmac.digest(key, enc(value), "sha512")[:32]


kem = {}
for line in Path(__file__).with_name("xwing-draft-11.txt").read_text().splitlines():
    if " = " not in line or line.startswith("#"):
        continue
    name, value = line.split(" = ", 1)
    if name in kem:
        break
    kem[name] = bytes.fromhex(value)
pairing, nonce_b, nonce_a = bytes(range(16)), bytes(range(16, 48)), bytes(range(48, 80))
vault = bytes.fromhex("00112233445546778899aabbccddeeff")
slot = bytes.fromhex("112233445566478899aabbccddeeff00")
head = bytes.fromhex("2233445566774899aabbccddeeff0011")
obj = bytes.fromhex("33445566778849aabbccddeeff001122")
record = bytes.fromhex("4455667788994abbccddeeff00112233")
descriptor = enc({0: slot, 1: 1, 2: bytes([1])*32, 3: 1, 4: bytes([2])*32, 5: bytes([3])*24, 6: bytes([4])*48})
assert len(descriptor) == 171
print("# SPDX-License-Identifier: AGPL-3.0-or-later")
print("# source: development-only wire shapes, generate-lan-v2-wire.py, cbor2/cryptography")
for method, intent in [(0, 0), (1, 0), (1, 1)]:
    j = [2, 1 if method == 0 else 0, method, intent]
    pid = kdf(pairing, b"", ["qv/lan-pair-id/v2"], 16)
    hello_key = kdf(pairing, pid, ["qv/lan-pair-mac/v2", "hello"])
    accept_key = kdf(pairing, pid, ["qv/lan-pair-mac/v2", "accept"])
    hello_body = ["qv/lan-pair-hello/v2", 2, pid, method, intent, digest(["qv/lan-pair-commit/v2", nonce_b]), kem["pk"]]
    hello = hello_body + [mac(hello_key, hello_body)]
    accept_body = ["qv/lan-pair-accept/v2", 2, method, intent, nonce_a, kem["ct"]]
    accept_input = ["qv/lan-pair-accept-mac/v2", digest(hello), accept_body]
    accept = accept_body + [mac(accept_key, accept_input)]
    outer_input = ["qv/lan-pair-th/v2", j, digest(hello), digest(accept)]
    t0 = digest(outer_input)
    values = dict(method=bytes([method]), intent=bytes([intent]), pairing=pairing, j=enc(j),
                  hello=enc(hello), hello_body=enc(hello_body), hello_hash=digest(hello),
                  accept=enc(accept), accept_body=enc(accept_body), accept_input=enc(accept_input),
                  accept_hash=digest(accept), outer_input=enc(outer_input), t0=t0,
                  qr=enc(["qv/lan-pair-qr/v2", 2, pairing, [[bytes([10,0,0,2]),1271]], "qv-0123456789abcdef"]))
    if method == 0:
        r = ["qv/lan-pake-start/v2", nonce_b, bytes([65])*96]
        s = ["qv/lan-pake-response/v2", bytes([66])*320]
        f = ["qv/lan-pake-finish/v2", bytes([67])*64]
        auth = ["qv/lan-auth-th/v2", j, t0, r, s, f]
        values.update(r=enc(r), s=enc(s), f=enc(f),
                      finished=enc(["qv/lan-finished/v2", bytes([68])*32]),
                      grant=enc(["qv/lan-pair-grant/v2", vault, 1, bytes([69])*32, descriptor, record, head, obj, bytes([70])*32]))
    else:
        pb = ["qv/lan-key-prove/v2", bytes([71])*32]
        pa = ["qv/lan-key-proved/v2", vault, 1, bytes([72])*32]
        auth = ["qv/lan-auth-th/v2", j, t0, pb, pa]
        values.update(r=enc(pb), s=enc(pa))
    values.update(auth_input=enc(auth), ta=digest(auth), error=enc(["qv/lan-error/v2", 9]))
    print()
    for name, value in values.items():
        print(f"{name} = {value.hex()}")
