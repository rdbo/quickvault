#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic 0013 §15 KATs using independent libraries, never product keys.

PYTHONPATH=/tmp/qv-0047-vector-tools python3 generate-lan-v2.py > qv-dev-lan-v2.txt
Tools used: cryptography50.0.0, cbor2 6.2.1, PyNaCl1.6.2 (libsodium).
This checks bytes/primitive interoperability, not protocol security.
"""
import hashlib
import hmac

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt


def enc(value):
    return cbor2.dumps(value, canonical=True)


def digest(value):
    return hashlib.sha256(enc(value)).digest()


def kdf(key, salt, info, size=32):
    return HKDF(algorithm=hashes.SHA512(), length=size, salt=salt, info=enc(info)).derive(key)


def mac(key, value):
    return hmac.digest(key, enc(value), "sha512")[:32]


ss, pairing = bytes(range(32)), bytes(range(32, 48))
nonce, t0 = bytes(range(48, 80)), bytes(range(128, 160))
vk = bytes(range(176, 208))
vid = bytearray(range(208, 224))
vid[6] = (vid[6] & 15) | 64
vid[8] = (vid[8] & 63) | 128
vid = bytes(vid)
print("# SPDX-License-Identifier: AGPL-3.0-or-later")
print("# source: QuickVault development-only profile2 fixtures, independently generated")
print("# generator: generate-lan-v2.py; cryptography50.0.0/cbor2 6.2.1/PyNaCl1.6.2")
for method in range(3):
    j = ([2, 1, 0, 0], [2, 0, 1, 0], [2, 0, 1, 1])[method]
    pid = kdf(pairing, b"", ["qv/lan-pair-id/v2"], 16)
    hello = kdf(pairing, pid, ["qv/lan-pair-mac/v2", "hello"])
    accept = kdf(pairing, pid, ["qv/lan-pair-mac/v2", "accept"])
    tag = kdf(pairing, pid, ["qv/lan-pair-tag/v2"], 4)
    values = dict(mode=bytes([method]), ss=ss, pairing=pairing, t0=t0, nonce=nonce,
                  vault_id=vid, vk=vk, j=enc(j), pairing_id=pid, hello_key=hello,
                  accept_key=accept, discovery_tag=tag,
                  commitment=digest(["qv/lan-pair-commit/v2", nonce]))
    sas = int.from_bytes(digest(["qv/lan-pair-sas/v2", j, t0, nonce])[:4], "big") % 1000000
    values["sas"] = f"{sas:06}".encode()
    if method == 0:
        z = bytes(range(64, 128))
        first = ["qv/lan-pake-start/v2", nonce, bytes([65]) * 96]
        second = ["qv/lan-pake-response/v2", bytes([66]) * 320]
        final = ["qv/lan-pake-finish/v2", bytes([67]) * 64]
    else:
        z = kdf(vk, t0, ["qv/lan-key-auth/v2", j, "schedule", t0], 64)
        proof_key = kdf(vk, t0, ["qv/lan-key-auth/v2", j, "mac", t0])
        pb = mac(proof_key, ["qv/lan-key-proof/v2", j, "b", t0])
        pa = mac(proof_key, ["qv/lan-key-proof/v2", j, "a", t0, digest([vid, 1])])
        values.update(key_mac=proof_key, proof_b=pb, proof_a=pa)
        first = ["qv/lan-key-prove/v2", pb]
        second = ["qv/lan-key-proved/v2", vid, 1, pa]
    transcript = ["qv/lan-auth-th/v2", j, t0, first, second]
    if method == 0:
        transcript.append(final)
        values["flight_f"] = enc(final)
    ta = digest(transcript)
    values.update(z=z, ta=ta, flight_r=enc(first), flight_s=enc(second))
    for epoch, th, material in [(0, t0, ss + pairing), (1, ta, ss + pairing + z)]:
        for direction in ["a2b", "b2a"]:
            key = kdf(material, th, ["qv/lan-key/v2", j, epoch, direction, th])
            aad = enc(["qv/lan-record/v2", j, epoch, direction, th, 0])
            plain = b"qv-v2 synthetic frame"
            ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plain, aad, bytes(24), key)
            values[f"key_{epoch}_{direction}"] = key
            values[f"aad_{epoch}_{direction}"] = aad
            values[f"frame_{epoch}_{direction}"] = ciphertext
    if method == 0:
        finished_key = kdf(ss + pairing + z, ta, ["qv/lan-finished-key/v2", j, "b", ta])
        values["finished_key"] = finished_key
        values["finished_tag"] = mac(finished_key, ["qv/lan-finished-mac/v2", j, "b", ta])
    print()
    for name, value in values.items():
        print(f"{name} = {value.hex()}")
