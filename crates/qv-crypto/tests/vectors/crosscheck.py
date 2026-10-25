# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent cross-check of QuickVault's development vectors.

Python 3 standard library only (hmac, hashlib, unicodedata; optional
`openssl` binary). Run by hand, not in CI:

    python3 -I crates/qv-crypto/tests/vectors/crosscheck.py          # verify
    python3 -I crates/qv-crypto/tests/vectors/crosscheck.py --write  # regenerate

What it checks, independently of the Rust code:
  * qv-dev-keys.txt: every HKDF-SHA-512 derivation, MAC/1 value and canonical
    CBOR info/message/AAD byte string (computed here; the Rust tests must match).
  * qv-dev-padme.txt: Padmé values (computed here).
  * qv-dev-stored-data.txt: ciphertext length = padme(4 + L) + 16. It cannot
    check XChaCha20-Poly1305 itself (not in the stdlib); the primitive is
    covered by the upstream draft-irtf-cfrg-xchacha-03 vector.
  * qv-dev-password-kdf.txt: the NFC form (unicodedata), and the Argon2id
    output via `openssl kdf ... ARGON2ID` when OpenSSL >= 3.2 is available
    (skipped with a notice otherwise). Argon2 is not in the stdlib.

Integers in the vector files are big-endian hex (key generation: 4 bytes;
Padmé values: 8 bytes).
"""

import hashlib
import hmac
import os
import subprocess
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS = "# status: development-only; regenerated freely until roadmap phase 1.16\n"


# --- canonical CBOR for the flat arrays used in info/AAD (RFC 8949 §4.2) ---

def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | ai]) + n.to_bytes(width, "big")
    raise ValueError(n)


def cbor(item):
    if isinstance(item, int):
        return head(0, item)
    if isinstance(item, bytes):
        return head(2, len(item)) + item
    if isinstance(item, str):
        b = item.encode()
        return head(3, len(b)) + b
    raise TypeError(item)


def array(*items):
    return head(4, len(items)) + b"".join(cbor(i) for i in items)


# --- primitives from the standard library ---

def hkdf_sha512(ikm, salt, info, length=32):
    prk = hmac.new(salt if salt is not None else b"\0" * 64, ikm, hashlib.sha512).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        out += block
        counter += 1
    return out[:length]


def mac1(key, msg):
    return hmac.new(key, msg, hashlib.sha512).digest()[:32]


def padme(n):
    if n < 2:
        return n
    e = n.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (n + mask) & ~mask


# --- vector files ---

def parse(path):
    records, cur = [], {}
    for line in open(path):
        line = line.strip()
        if line.startswith("#"):
            continue
        if not line:
            if cur:
                records.append(cur)
                cur = {}
            continue
        name, value = (x.strip() for x in line.split("=", 1))
        cur[name] = bytes.fromhex(value)
    if cur:
        records.append(cur)
    return records


LABELS = ["record", "attachment", "header-mac", "manifest", "state-commit",
          "local-state", "device-storage", "recovery-ed25519", "recovery-mldsa65"]


def dev_keys():
    vk = bytes(range(32))
    mk = bytes([0x33] * 32)
    vault = bytes([0x11] * 16)
    slot = bytes([0x22] * 16)
    record = bytes([0x01] * 16)
    attachment = bytes([0x02] * 16)
    kdf_salt = bytes([0x44] * 32)
    gen = 1
    kdf_profile = wrap_profile = derivation_profile = 1

    out = [("vk", vk), ("mk", mk), ("vault_id", vault), ("slot_id", slot),
           ("record_id", record), ("attachment_id", attachment),
           ("kdf_salt", kdf_salt), ("generation", gen.to_bytes(4, "big"))]
    kek_info = array("qv/kek/v1", kdf_profile)
    kek = hkdf_sha512(mk, vault, kek_info)
    commit_msg = array("qv/kek-commit/v1", vault, gen, slot)
    wrap_info = array("qv/kek-wrap/v1")
    out += [("kek_info", kek_info), ("kek", kek),
            ("kek_commit_msg", commit_msg), ("kek_commit", mac1(kek, commit_msg)),
            ("wrap_info", wrap_info), ("wrap_key", hkdf_sha512(kek, None, wrap_info)),
            ("slot_aad", array("qv/password-slot/v1", vault, gen, slot, kdf_profile,
                               kdf_salt, wrap_profile))]
    purpose = {}
    for label in LABELS:
        info = array("qv/purpose/v1", label, gen, derivation_profile)
        purpose[label] = hkdf_sha512(vk, vault, info)
        key = label.replace("-", "_")
        out += [(f"purpose_info_{key}", info), (f"purpose_{key}", purpose[label])]
    rk_info = array("qv/record-key/v1", record)
    ak_info = array("qv/attachment-key/v1", attachment)
    mac_msg = b"QuickVault MAC/1 development vector"
    out += [("record_key_info", rk_info),
            ("record_key", hkdf_sha512(purpose["record"], vault, rk_info)),
            ("attachment_key_info", ak_info),
            ("attachment_key", hkdf_sha512(purpose["attachment"], vault, ak_info)),
            ("mac_msg", mac_msg),
            ("mac_header", mac1(purpose["header-mac"], mac_msg))]
    return [out]


def dev_padme():
    ns = [4, 5, 8, 9, 20, 100, 1000, 1025, 4096, 65_540, 1_000_000,
          (1 << 20) - (16 << 10), (1 << 20) - (16 << 10) + 1, (1 << 32) + 3]
    return [[("n", n.to_bytes(8, "big")), ("padded", padme(n).to_bytes(8, "big"))] for n in ns]


def render(header, records):
    text = STATUS + header
    for rec in records:
        text += "\n" + "".join(f"{k} = {v.hex()}\n" for k, v in rec)
    return text


FILES = {
    "qv-dev-keys.txt": ("# Key hierarchy (spec 0002 §3.1–3.3, §3.6), computed by crosscheck.py\n"
                        "# with the Python standard library. `generation` is a 4-byte big-endian integer.\n",
                        dev_keys),
    "qv-dev-padme.txt": ("# Padmé (0004 §3.2), computed by crosscheck.py. Integers are 8-byte big-endian.\n",
                         dev_padme),
}


def main():
    write = "--write" in sys.argv[1:]
    failures = 0
    for name, (header, build) in FILES.items():
        path = os.path.join(HERE, name)
        expected = render(header, build())
        if write:
            open(path, "w").write(expected)
            print(f"wrote {name}")
        elif open(path).read() != expected:
            print(f"MISMATCH {name}")
            failures += 1
        else:
            print(f"ok {name} ({len(build())} records)")

    # Stored data: lengths and framing arithmetic only.
    for rec in parse(os.path.join(HERE, "qv-dev-stored-data.txt")):
        if len(rec["ciphertext"]) != padme(4 + len(rec["plaintext"])) + 16:
            print(f"MISMATCH qv-dev-stored-data.txt length for L={len(rec['plaintext'])}")
            failures += 1
    print("ok qv-dev-stored-data.txt (lengths only; XChaCha not checked here)")

    # Password KDF: NFC, and Argon2id through OpenSSL if available.
    rec = parse(os.path.join(HERE, "qv-dev-password-kdf.txt"))[0]
    if unicodedata.normalize("NFC", rec["password"].decode()).encode() != rec["nfc"]:
        print("MISMATCH qv-dev-password-kdf.txt nfc")
        failures += 1
    try:
        res = subprocess.run(
            ["openssl", "kdf", "-keylen", "32", "-kdfopt", "hexpass:" + rec["nfc"].hex(),
             "-kdfopt", "hexsalt:" + rec["salt"].hex(), "-kdfopt", "memcost:262144",
             "-kdfopt", "iter:3", "-kdfopt", "lanes:4", "ARGON2ID"],
            capture_output=True, text=True, check=True)
        mk = bytes.fromhex(res.stdout.strip().replace(":", ""))
        if mk != rec["mk"]:
            print("MISMATCH qv-dev-password-kdf.txt mk (OpenSSL)")
            failures += 1
        else:
            print("ok qv-dev-password-kdf.txt (NFC and OpenSSL Argon2id)")
    except (OSError, subprocess.CalledProcessError):
        print("skip qv-dev-password-kdf.txt Argon2id: no OpenSSL with ARGON2ID (NFC checked)")

    if failures:
        print(f"{failures} mismatch(es)")
        sys.exit(1)


if __name__ == "__main__":
    main()
