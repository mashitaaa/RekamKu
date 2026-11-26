from __future__ import annotations

import base64
import hashlib
import re
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_BITS = 3072
TOKEN_PREFIX = "RKS1"
OAEP_LABEL = b"rekamku/share-key/v1"
SHARE_KEY_LEN = 32


class TokenError(ValueError):
    pass


def new_rsa_keypair(bits: int = RSA_BITS) -> tuple[bytes, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    return priv_der, public_der(priv.public_key())


def public_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private(der: bytes):
    return serialization.load_der_private_key(der, password=None)


def load_public(der: bytes):
    return serialization.load_der_public_key(der)


def fingerprint(public_key_der: bytes, groups: int = 8) -> str:
    h = hashlib.sha256(public_key_der).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, groups * 4, 4))


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=OAEP_LABEL)


def new_share_key() -> bytes:
    return secrets.token_bytes(SHARE_KEY_LEN)


def encrypt_share_key(requester_pub_der: bytes, share_id: str, share_key: bytes) -> str:
    if len(share_key) != SHARE_KEY_LEN:
        raise ValueError("share key must be 32 bytes")
    sid = bytes.fromhex(share_id)
    ct = load_public(requester_pub_der).encrypt(TOKEN_PREFIX.encode() + sid + share_key, _oaep())
    body = base64.urlsafe_b64encode(ct).decode().rstrip("=")
    return f"{TOKEN_PREFIX}.{share_id}.{body}"


def parse_token(token: str) -> tuple[str, bytes]:
    t = re.sub(r"\s+", "", token or "")
    parts = t.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not re.fullmatch(r"[0-9a-f]{32}", parts[1]):
        raise TokenError("This does not look like a RekamKu share key.")
    try:
        ct = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except (ValueError, TypeError):
        raise TokenError("The share key is damaged. Copy it again in full.")
    return parts[1], ct


def decrypt_share_key(private_der: bytes, share_id: str, ciphertext: bytes) -> bytes:
    try:
        plain = load_private(private_der).decrypt(ciphertext, _oaep())
    except ValueError:
        raise TokenError("This key was not encrypted for your account, or it was changed on the way.")
    prefix = TOKEN_PREFIX.encode()
    if len(plain) != len(prefix) + 16 + SHARE_KEY_LEN or not plain.startswith(prefix):
        raise TokenError("The share key has an unexpected format.")
    if plain[len(prefix):len(prefix) + 16] != bytes.fromhex(share_id):
        raise TokenError("This key belongs to a different request.")
    return plain[-SHARE_KEY_LEN:]
