#!/usr/bin/env python3
"""Independent reference implementation of Sanctum's sealed-file format
(`SANCTUMS`, version 1), written from the format description in
`crates/sanctum-crypto/src/sealed.rs` (not from the Rust code paths).

XChaCha20-Poly1305 is built here from HChaCha20 (implemented below) and the
ChaCha20-Poly1305 of the `cryptography` package, and checked against the
draft-irtf-cfrg-xchacha-03 test vectors before anything is generated.
Argon2id and HKDF come from `cryptography` (>= 44).

Generates sealed_vectors.json, which the Rust known-answer tests must
reproduce byte for byte.

    python3 crates/sanctum-crypto/tests/kat/generate_sealed_vectors.py
"""
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SANCTUMS"
VERSION = 1
KIND_INFO = {
    1: b"SANCTUM-STORE-host-state-v1",
    2: b"SANCTUM-STORE-backlog-v1",
    3: b"SANCTUM-STORE-client-state-v1",
}


# -- XChaCha20-Poly1305 ------------------------------------------------------

def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha_encrypt(key: bytes, nonce24: bytes, pt: bytes, aad: bytes) -> bytes:
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\x00" * 4 + nonce24[16:], pt, aad)


def _self_test():
    # draft-irtf-cfrg-xchacha-03, section 2.2.1 (HChaCha20).
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    assert hchacha20(key, nonce).hex() == (
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    ), "HChaCha20 self-test"
    # Appendix A.3.1 (AEAD_XChaCha20_Poly1305).
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one"
        b" tip for the future, sunscreen would be it."
    )
    ct = xchacha_encrypt(
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        pt,
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    )
    assert ct[:16].hex() == "bd6d179d3e83d43b9576579493c0e939", "XChaCha self-test"
    assert ct[-16:].hex() == "c0875924c1c7987947deafd8780acf49", "XChaCha tag self-test"


# -- Sealed file ---------------------------------------------------------------

def det(label: str, n: int) -> bytes:
    return hashlib.sha256(b"sanctum-kat:" + label.encode()).digest()[:n]


def build(kind, memory_kib, iterations, lanes, passphrase, master, salt, wrap_nonce,
          body_nonce, plaintext):
    prefix = (
        MAGIC
        + struct.pack(">H", VERSION)
        + bytes([kind])
        + struct.pack(">III", memory_kib, iterations, lanes)
        + salt
    )
    kek = Argon2id(
        salt=salt, length=32, iterations=iterations, lanes=lanes, memory_cost=memory_kib
    ).derive(passphrase)
    wrapped = xchacha_encrypt(kek, wrap_nonce, master, prefix)
    header = prefix + wrap_nonce + wrapped
    body_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=KIND_INFO[kind]).derive(master)
    body = body_nonce + xchacha_encrypt(body_key, body_nonce, plaintext, header)
    return {
        "kind": kind,
        "memory_kib": memory_kib,
        "iterations": iterations,
        "lanes": lanes,
        "passphrase": passphrase.hex(),
        "master_key": master.hex(),
        "salt": salt.hex(),
        "wrap_nonce": wrap_nonce.hex(),
        "body_nonce": body_nonce.hex(),
        "plaintext": plaintext.hex(),
        "kek": kek.hex(),
        "body_key": body_key.hex(),
        "header": header.hex(),
        "file": (header + body).hex(),
    }


def main():
    _self_test()
    vectors = {
        "description": "Sanctum sealed files (SANCTUMS v1) known-answer vectors",
        "generator": "crates/sanctum-crypto/tests/kat/generate_sealed_vectors.py (Python cryptography)",
        "vectors": [
            build(1, 8 * 1024, 1, 1, b"correct horse battery staple",
                  det("sealed-master-1", 32), det("sealed-salt-1", 16),
                  det("sealed-wrap-nonce-1", 24), det("sealed-body-nonce-1", 24),
                  b"sanctum sealed-file KAT: host state v1"),
            build(3, 8 * 1024, 2, 2, "phrase de passe été".encode(),
                  det("sealed-master-3", 32), det("sealed-salt-3", 16),
                  det("sealed-wrap-nonce-3", 24), det("sealed-body-nonce-3", 24),
                  b""),
        ],
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sealed_vectors.json")
    with open(out, "w") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
