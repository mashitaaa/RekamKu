from __future__ import annotations

import hashlib
import hmac
import warnings

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4, TripleDES

DES_BLOCK = 8
DES_KEY_LEN = 8
RC4_KEY_LEN = 16
RC4_DROP = 3072
AES_KEY_LEN = 32
GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16

_ZERO_DROP = bytes(RC4_DROP)


class IntegrityError(Exception):
    pass


def _des(key: bytes) -> TripleDES:
    if len(key) != DES_KEY_LEN:
        raise ValueError("DES key must be 8 bytes")
    return TripleDES(key * 3)


def des_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(64).padder()
    data = padder.update(plaintext) + padder.finalize()
    enc = Cipher(_des(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def des_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % DES_BLOCK:
        raise IntegrityError("invalid DES ciphertext length")
    dec = Cipher(_des(key), modes.CBC(iv)).decryptor()
    data = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    try:
        return unpadder.update(data) + unpadder.finalize()
    except ValueError as e:
        raise IntegrityError("invalid DES padding") from e


def rc4_xor(key: bytes, data: bytes) -> bytes:
    if len(key) != RC4_KEY_LEN:
        raise ValueError("RC4 key must be 16 bytes")
    c = Cipher(ARC4(key), mode=None).encryptor()
    c.update(_ZERO_DROP)
    return c.update(data)


def rc4_subkey(master: bytes, label: bytes, index: int) -> bytes:
    msg = label + index.to_bytes(8, "big")
    return hmac.new(master, msg, hashlib.sha256).digest()[:RC4_KEY_LEN]


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return gcm_decrypt_obj(AESGCM(key), nonce, ciphertext, aad)


def gcm_decrypt_obj(aead: AESGCM, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except InvalidTag as e:
        raise IntegrityError("AES-GCM tag mismatch (data modified or wrong key)") from e
