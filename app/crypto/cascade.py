from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import primitives as P
from .primitives import IntegrityError

MAGIC = b"RKU1"
VERSION = 1
HEADER_LEN = 32
SALT_LEN = 24
CHUNK_OVERHEAD = P.DES_BLOCK + P.DES_BLOCK + P.GCM_TAG_LEN
DEFAULT_CHUNK_LOG2 = 20
_INFO = b"rekamku/cascade/v1"

__all__ = ["IntegrityError", "Encryptor", "Decryptor", "seal", "unseal",
           "encrypt_stream", "BlobReader", "ciphertext_size"]


@dataclass(frozen=True)
class _Keys:
    aes: AESGCM
    des: bytes
    rc4: bytes


def _derive(key: bytes, salt: bytes) -> _Keys:
    if len(key) != 32:
        raise ValueError("object key must be 32 bytes")
    okm = HKDF(algorithm=hashes.SHA256(), length=32 + 8 + 32, salt=salt, info=_INFO).derive(key)
    return _Keys(aes=AESGCM(okm[:32]), des=okm[32:40], rc4=okm[40:72])


def _aad(ctx_hash: bytes, index: int, last: bool) -> bytes:
    return ctx_hash + struct.pack(">QB", index, 1 if last else 0)


def _nonce(index: int) -> bytes:
    return index.to_bytes(P.GCM_NONCE_LEN, "big")


def ciphertext_size(plain_len: int, chunk_log2: int = DEFAULT_CHUNK_LOG2) -> int:
    cs = 1 << chunk_log2
    n = max(1, -(-plain_len // cs))
    last = plain_len - (n - 1) * cs
    last_pad = P.DES_BLOCK - (last % P.DES_BLOCK)
    return HEADER_LEN + (n - 1) * (cs + CHUNK_OVERHEAD) + last + last_pad + P.DES_BLOCK + P.GCM_TAG_LEN


class Encryptor:
    def __init__(self, key: bytes, context: bytes, chunk_log2: int = DEFAULT_CHUNK_LOG2):
        if not 10 <= chunk_log2 <= 24:
            raise ValueError("chunk size must be 1 KiB .. 16 MiB")
        salt = os.urandom(SALT_LEN)
        self.chunk_size = 1 << chunk_log2
        self.header = MAGIC + bytes([VERSION, chunk_log2, 0, 0]) + salt
        self._k = _derive(key, salt)
        self._ctx = hashlib.sha256(self.header + context).digest()
        self._next = 0
        self._closed = False

    def encrypt_chunk(self, plaintext: bytes, last: bool) -> bytes:
        if self._closed:
            raise RuntimeError("encryptor already closed")
        if len(plaintext) > self.chunk_size or (not last and len(plaintext) != self.chunk_size):
            raise ValueError("a non-final chunk must be exactly chunk_size")
        i = self._next
        iv = os.urandom(P.DES_BLOCK)
        c1 = iv + P.des_cbc_encrypt(self._k.des, iv, plaintext)
        c2 = P.rc4_xor(P.rc4_subkey(self._k.rc4, b"rc4", i), c1)
        out = self._k.aes.encrypt(_nonce(i), c2, _aad(self._ctx, i, last))
        self._next += 1
        self._closed = last
        return out


def encrypt_stream(key: bytes, context: bytes, read: Callable[[int], bytes], write: Callable[[bytes], object],
                   chunk_log2: int = DEFAULT_CHUNK_LOG2, on_plain: Callable[[bytes], None] | None = None) -> int:
    enc = Encryptor(key, context, chunk_log2)
    cs = enc.chunk_size
    write(enc.header)

    def read_full() -> bytes:
        buf = bytearray()
        while len(buf) < cs:
            part = read(cs - len(buf))
            if not part:
                break
            buf += part
        return bytes(buf)

    total = 0
    cur = read_full()
    while True:
        nxt = read_full() if len(cur) == cs else b""
        last = not nxt
        if on_plain:
            on_plain(cur)
        write(enc.encrypt_chunk(cur, last))
        total += len(cur)
        if last:
            return total
        cur = nxt


class Decryptor:
    def __init__(self, key: bytes, context: bytes, header: bytes):
        if len(header) != HEADER_LEN or header[:4] != MAGIC or header[4] != VERSION:
            raise IntegrityError("unrecognised header")
        chunk_log2 = header[5]
        if not 10 <= chunk_log2 <= 24:
            raise IntegrityError("invalid chunk size in header")
        self.chunk_size = 1 << chunk_log2
        self.enc_chunk_size = self.chunk_size + CHUNK_OVERHEAD
        self._k = _derive(key, header[8:8 + SALT_LEN])
        self._ctx = hashlib.sha256(header + context).digest()

    def decrypt_chunk(self, index: int, ciphertext: bytes, last: bool) -> bytes:
        c2 = P.gcm_decrypt_obj(self._k.aes, _nonce(index), ciphertext, _aad(self._ctx, index, last))
        c1 = P.rc4_xor(P.rc4_subkey(self._k.rc4, b"rc4", index), c2)
        plain = P.des_cbc_decrypt(self._k.des, c1[:P.DES_BLOCK], c1[P.DES_BLOCK:])
        if not last and len(plain) != self.chunk_size:
            raise IntegrityError("unexpected chunk length")
        return plain


class BlobReader:
    def __init__(self, path: str, key: bytes, context: bytes):
        self.path = path
        self._fh: BinaryIO = open(path, "rb")
        try:
            header = self._fh.read(HEADER_LEN)
            self._dec = Decryptor(key, context, header)
            body = os.fstat(self._fh.fileno()).st_size - HEADER_LEN
            ecs = self._dec.enc_chunk_size
            self.n_chunks = max(1, -(-body // ecs))
            last_len = body - (self.n_chunks - 1) * ecs
            if body <= 0 or last_len < CHUNK_OVERHEAD:
                raise IntegrityError("file truncated")
        except Exception:
            self._fh.close()
            raise
        self.chunk_size = self._dec.chunk_size
        self._cache: tuple[int, bytes] | None = None

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def chunk(self, i: int) -> bytes:
        if not 0 <= i < self.n_chunks:
            raise IndexError(i)
        if self._cache and self._cache[0] == i:
            return self._cache[1]
        ecs = self._dec.enc_chunk_size
        self._fh.seek(HEADER_LEN + i * ecs)
        ct = self._fh.read(ecs)
        plain = self._dec.decrypt_chunk(i, ct, last=(i == self.n_chunks - 1))
        self._cache = (i, plain)
        return plain

    def iter_range(self, start: int = 0, end: int | None = None) -> Iterator[bytes]:
        cs = self.chunk_size
        first = start // cs
        i = first
        while i < self.n_chunks:
            data = self.chunk(i)
            lo = start - i * cs if i == first else 0
            if end is not None and (i + 1) * cs >= end:
                yield data[lo:end - i * cs]
                return
            yield data[lo:]
            i += 1

    def read_all(self) -> bytes:
        return b"".join(self.iter_range())


def seal(key: bytes, plaintext: bytes, context: bytes) -> bytes:
    out: list[bytes] = []
    view = memoryview(plaintext)
    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        chunk = bytes(view[pos:pos + n])
        pos += len(chunk)
        return chunk

    encrypt_stream(key, context, read, out.append)
    return b"".join(out)


def unseal(key: bytes, blob: bytes, context: bytes) -> bytes:
    if len(blob) < HEADER_LEN + CHUNK_OVERHEAD:
        raise IntegrityError("object too short")
    dec = Decryptor(key, context, blob[:HEADER_LEN])
    body = blob[HEADER_LEN:]
    ecs = dec.enc_chunk_size
    n = max(1, -(-len(body) // ecs))
    return b"".join(dec.decrypt_chunk(i, body[i * ecs:(i + 1) * ecs], last=(i == n - 1)) for i in range(n))
