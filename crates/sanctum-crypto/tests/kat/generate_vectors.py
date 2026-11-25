#!/usr/bin/env python3
"""Independent reference implementation of Sanctum's X3DH + Double Ratchet
profile (protocol v2), written from the Signal specifications and the
constants documented in sanctum-crypto (not from the Rust code).

Generates vectors.json, which the Rust known-answer tests must reproduce
byte for byte. Requires the `cryptography` package.

    python3 crates/sanctum-crypto/tests/kat/generate_vectors.py
"""
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

X3DH_INFO = b"SANCTUM-X3DH-v2"
RK_INFO = b"SANCTUM-DR-RK-v2"
MSG_INFO = b"SANCTUM-DR-MSG-v2"
AD_DOMAIN = b"SANCTUM-DR-v2"


def det_key(label: str) -> bytes:
    """Deterministic 32-byte private key from a label."""
    return hashlib.sha256(b"sanctum-kat:" + label.encode()).digest()


def pub(priv: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(priv)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def dh(priv: bytes, peer_pub: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    return X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(peer_pub)
    )


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


# X3DH (spec section 3.3): SK = KDF(F || DH1 || DH2 || DH3 [|| DH4])
def x3dh_sk(dhs) -> bytes:
    return hkdf(b"\xff" * 32 + b"".join(dhs), b"\x00" * 32, X3DH_INFO, 32)


# Double Ratchet (spec section 5.2)
def kdf_rk(rk: bytes, dh_out: bytes):
    out = hkdf(dh_out, rk, RK_INFO, 64)
    return out[:32], out[32:]


def kdf_ck(ck: bytes):
    mk = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    next_ck = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return next_ck, mk


def message_keys(mk: bytes):
    out = hkdf(mk, b"\x00" * 32, MSG_INFO, 44)
    return out[:32], out[32:]


def encode_header(dh_pub: bytes, pn: int, n: int) -> bytes:
    return dh_pub + pn.to_bytes(4, "big") + n.to_bytes(4, "big")


class Party:
    def __init__(self, ad: bytes):
        self.ad = ad
        self.dhs = None
        self.dhr = None
        self.rk = None
        self.cks = None
        self.ckr = None
        self.ns = self.nr = self.pn = 0
        self.skipped = {}

    @classmethod
    def alice(cls, sk, bob_pub, ratchet_priv, ad):
        p = cls(ad)
        p.dhs = ratchet_priv
        p.dhr = bob_pub
        p.rk, p.cks = kdf_rk(sk, dh(ratchet_priv, bob_pub))
        return p

    @classmethod
    def bob(cls, sk, spk_priv, ad):
        p = cls(ad)
        p.dhs = spk_priv
        p.rk = sk
        return p

    def encrypt(self, pt: bytes):
        self.cks, mk = kdf_ck(self.cks)
        header = (pub(self.dhs), self.pn, self.ns)
        self.ns += 1
        key, nonce = message_keys(mk)
        ct = ChaCha20Poly1305(key).encrypt(nonce, pt, self.ad + encode_header(*header))
        return header, ct

    def decrypt(self, header, ct, next_ratchet_priv=None):
        dh_pub, pn, n = header
        ad = self.ad + encode_header(*header)
        if (dh_pub, n) in self.skipped:  # TrySkippedMessageKeys
            key, nonce = message_keys(self.skipped.pop((dh_pub, n)))
            return ChaCha20Poly1305(key).decrypt(nonce, ct, ad)
        if dh_pub != self.dhr:
            self._skip(pn)
            self.pn = self.ns
            self.ns = self.nr = 0
            self.dhr = dh_pub
            self.rk, self.ckr = kdf_rk(self.rk, dh(self.dhs, self.dhr))
            self.dhs = next_ratchet_priv
            self.rk, self.cks = kdf_rk(self.rk, dh(self.dhs, self.dhr))
        self._skip(n)
        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1
        key, nonce = message_keys(mk)
        return ChaCha20Poly1305(key).decrypt(nonce, ct, self.ad + encode_header(*header))

    def _skip(self, until):
        while self.ckr is not None and self.nr < until:
            self.ckr, mk = kdf_ck(self.ckr)
            self.skipped[(self.dhr, self.nr)] = mk
            self.nr += 1


def h(b: bytes) -> str:
    return b.hex()


def main():
    keys = {
        name: det_key(name)
        for name in [
            "alice_ik", "alice_ek", "bob_ik", "bob_spk", "bob_opk",
            "alice_ratchet_1", "bob_ratchet_1", "alice_ratchet_2", "bob_ratchet_2",
        ]
    }
    a_ik, b_ik = pub(keys["alice_ik"]), pub(keys["bob_ik"])
    b_spk, b_opk = pub(keys["bob_spk"]), pub(keys["bob_opk"])
    a_ek = pub(keys["alice_ek"])

    dh1 = dh(keys["alice_ik"], b_spk)
    dh2 = dh(keys["alice_ek"], b_ik)
    dh3 = dh(keys["alice_ek"], b_spk)
    dh4 = dh(keys["alice_ek"], b_opk)
    sk = x3dh_sk([dh1, dh2, dh3, dh4])
    sk_no_opk = x3dh_sk([dh1, dh2, dh3])

    ad = AD_DOMAIN + a_ik + b_ik
    alice = Party.alice(sk, b_spk, keys["alice_ratchet_1"], ad)
    bob = Party.bob(sk, keys["bob_spk"], ad)

    steps = []

    def record(sender, header, ct, pt):
        steps.append({
            "sender": sender,
            "plaintext": h(pt),
            "dh_public": h(header[0]),
            "pn": header[1],
            "n": header[2],
            "ciphertext": h(ct),
        })

    m1 = alice.encrypt(b"first message")
    m2 = alice.encrypt(b"second message")
    record("alice", *m1, b"first message")
    record("alice", *m2, b"second message")
    # Bob receives out of order: m2 then m1.
    assert bob.decrypt(*m2, next_ratchet_priv=keys["bob_ratchet_1"]) == b"second message"
    assert bob.decrypt(*m1) == b"first message"
    r1 = bob.encrypt(b"bob replies")
    record("bob", *r1, b"bob replies")
    assert alice.decrypt(*r1, next_ratchet_priv=keys["alice_ratchet_2"]) == b"bob replies"
    m3 = alice.encrypt(b"third message")
    record("alice", *m3, b"third message")
    assert bob.decrypt(*m3, next_ratchet_priv=keys["bob_ratchet_2"]) == b"third message"

    vectors = {
        "description": "Sanctum protocol v2: X3DH + Double Ratchet known-answer vectors",
        "generator": "crates/sanctum-crypto/tests/kat/generate_vectors.py (Python cryptography)",
        "private_keys": {k: h(v) for k, v in keys.items()},
        "x3dh": {
            "alice_identity_public": h(a_ik),
            "alice_ephemeral_public": h(a_ek),
            "bob_identity_public": h(b_ik),
            "bob_signed_prekey_public": h(b_spk),
            "bob_one_time_prekey_public": h(b_opk),
            "shared_secret": h(sk),
            "shared_secret_without_opk": h(sk_no_opk),
        },
        "ratchet": {"associated_data_prefix": h(ad), "steps": steps},
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    with open(out, "w") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
