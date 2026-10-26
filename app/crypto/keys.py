from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .cascade import seal, unseal

KEY_LEN = 32


def _hkdf(ikm: bytes, info: bytes, salt: bytes | None = None, length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


@dataclass(frozen=True)
class KdfParams:
    n: int = 2 ** 17
    r: int = 8
    p: int = 1

    def encode(self) -> str:
        return f"scrypt$n={self.n}$r={self.r}$p={self.p}"

    @classmethod
    def decode(cls, s: str) -> "KdfParams":
        parts = dict(x.split("=") for x in s.split("$")[1:])
        return cls(n=int(parts["n"]), r=int(parts["r"]), p=int(parts["p"]))


class ServerKeys:
    def __init__(self, master: bytes):
        if len(master) != KEY_LEN:
            raise ValueError("server key must be 32 bytes")
        self.pepper = _hkdf(master, b"rekamku/pepper/v1")
        self.username_mac = _hkdf(master, b"rekamku/username-index/v1")
        self.flask_secret = _hkdf(master, b"rekamku/flask-session/v1")

    @classmethod
    def load_or_create(cls, path: str, env_hex: str | None = None) -> "ServerKeys":
        if env_hex:
            return cls(bytes.fromhex(env_hex))
        if os.path.exists(path):
            with open(path, "rb") as fh:
                return cls(fh.read())
        os.makedirs(os.path.dirname(path), exist_ok=True)
        master = secrets.token_bytes(KEY_LEN)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(master)
        return cls(master)

    def username_index(self, username: str) -> bytes:
        return hmac.new(self.username_mac, username.strip().lower().encode(), hashlib.sha256).digest()

    def derive_kek(self, secret: str, salt: bytes, params: KdfParams, label: bytes) -> bytes:
        stretched = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=params.n, r=params.r, p=params.p,
                                   maxmem=256 * 1024 * 1024, dklen=KEY_LEN)
        return _hkdf(stretched, b"rekamku/kek/" + label, salt=self.pepper)


def new_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def wrap(kek: bytes, key: bytes, context: bytes) -> bytes:
    return seal(kek, key, b"wrap|" + context)


def unwrap(kek: bytes, blob: bytes, context: bytes) -> bytes:
    key = unseal(kek, blob, b"wrap|" + context)
    if len(key) != KEY_LEN:
        raise ValueError("invalid wrapped key length")
    return key


_B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(_B32) for _ in range(20))
    return "-".join(raw[i:i + 4] for i in range(0, 20, 4))


def normalize_recovery_code(code: str) -> str:
    s = "".join(ch for ch in code.upper() if ch.isalnum())
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def new_log_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    return priv_raw, priv.public_key().public_bytes(**_RAW)


def seal_to(public_raw: bytes, data: bytes, context: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(**_RAW)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_raw))
    key = _hkdf(shared, b"rekamku/activity/v1", salt=eph_pub + public_raw)
    return eph_pub + seal(key, data, context)


def open_from(private_raw: bytes, blob: bytes, context: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(private_raw)
    eph_pub = blob[:32]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = _hkdf(shared, b"rekamku/activity/v1", salt=eph_pub + priv.public_key().public_bytes(**_RAW))
    return unseal(key, blob[32:], context)
