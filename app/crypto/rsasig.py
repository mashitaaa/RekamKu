from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass

from . import der

DIGESTS = {
    "2.16.840.1.101.3.4.2.1": ("sha256", 32),
    "2.16.840.1.101.3.4.2.2": ("sha384", 48),
    "2.16.840.1.101.3.4.2.3": ("sha512", 64),
}
DIGEST_OIDS = {name: o for o, (name, _) in DIGESTS.items()}
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
RSA_WITH = {"1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512"}
SHA256_WITH_RSA = "1.2.840.113549.1.1.11"


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def spki(self) -> bytes:
        body = der.seq(der.integer(self.n), der.integer(self.e))
        return der.seq(der.algorithm(RSA_ENCRYPTION, der.null()), der.bit_string(body))

    def key_id(self) -> bytes:
        return hashlib.sha1(der.seq(der.integer(self.n), der.integer(self.e))).digest()


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @classmethod
    def from_library(cls, key) -> "PrivateKey":
        nums = key.private_numbers()
        pub = nums.public_numbers
        return cls(pub.n, pub.e, nums.d, nums.p, nums.q, nums.dmp1, nums.dmq1, nums.iqmp)

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)


def public_from_spki(spki: bytes | der.Node) -> PublicKey:
    node = spki if isinstance(spki, der.Node) else der.parse_exact(spki)
    node.expect(der.SEQUENCE)
    if node[0][0].oid() != RSA_ENCRYPTION:
        raise SignatureError("only RSA keys are supported")
    key = der.parse_exact(node[1].bits()).expect(der.SEQUENCE)
    n, e = key[0].int(), key[1].int()
    if n <= 0 or e < 3 or e % 2 == 0:
        raise SignatureError("invalid RSA public key")
    return PublicKey(n, e)


def digest_info(hash_name: str, digest: bytes) -> bytes:
    return der.seq(der.algorithm(DIGEST_OIDS[hash_name], der.null()), der.octet_string(digest))


def emsa_pkcs1_v15(hash_name: str, digest: bytes, k: int) -> bytes:
    t = digest_info(hash_name, digest)
    if k < len(t) + 11:
        raise SignatureError("key too short for this hash")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def _private_op(key: PrivateKey, m: int) -> int:
    while True:
        r = secrets.randbelow(key.n - 2) + 2
        if math.gcd(r, key.n) == 1:
            break
    c = (m * pow(r, key.e, key.n)) % key.n
    s1 = pow(c, key.dp, key.p)
    s2 = pow(c, key.dq, key.q)
    h = (key.qinv * (s1 - s2)) % key.p
    s = (s2 + h * key.q) * pow(r, -1, key.n) % key.n
    if pow(s, key.e, key.n) != m:
        raise SignatureError("RSA computation fault")
    return s


def sign_digest(key: PrivateKey, digest: bytes, hash_name: str = "sha256") -> bytes:
    k = key.public.size
    em = emsa_pkcs1_v15(hash_name, digest, k)
    return _private_op(key, int.from_bytes(em, "big")).to_bytes(k, "big")


def verify_digest(key: PublicKey, digest: bytes, signature: bytes, hash_name: str = "sha256") -> bool:
    k = key.size
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= key.n:
        return False
    em = pow(s, key.e, key.n).to_bytes(k, "big")
    try:
        expected = emsa_pkcs1_v15(hash_name, digest, k)
    except SignatureError:
        return False
    return hmac.compare_digest(em, expected)


def hash_bytes(hash_name: str, *parts: bytes) -> bytes:
    h = hashlib.new(hash_name)
    for p in parts:
        h.update(p)
    return h.digest()
