from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import current_app

from .crypto import seal, unseal
from .crypto.asym import fingerprint, load_private, new_rsa_keypair, public_der
from .crypto.rsasig import PrivateKey
from .crypto.x509 import build_self_signed
from .db import get_db, log_activity


def ctx_enc(uid: str) -> bytes:
    return f"enckey|{uid}".encode()


def username_of(uid: str, umk: bytes) -> str:
    row = get_db().execute("SELECT account FROM users WHERE id=?", (uid,)).fetchone()
    return json.loads(unseal(umk, row["account"], b"account|" + uid.encode()))["username"]


def ensure_encryption_keys(uid: str, umk: bytes) -> bool:
    db = get_db()
    row = db.execute("SELECT enc_pub FROM users WHERE id=?", (uid,)).fetchone()
    if row is None or row["enc_pub"] is not None:
        return False
    priv, pub = new_rsa_keypair(current_app.config.get("RSA_BITS", 3072))
    db.execute("UPDATE users SET enc_pub=?, enc_priv=? WHERE id=? AND enc_pub IS NULL",
               (pub, seal(umk, priv, ctx_enc(uid)), uid))
    db.commit()
    log_activity(uid, "encryption_key_created")
    return True


def encryption_private(uid: str, umk: bytes) -> bytes:
    row = get_db().execute("SELECT enc_priv FROM users WHERE id=?", (uid,)).fetchone()
    return unseal(umk, row["enc_priv"], ctx_enc(uid))


def own_key_status(uid: str, umk: bytes) -> tuple[str | None, bool]:
    row = get_db().execute("SELECT enc_pub, enc_priv FROM users WHERE id=?", (uid,)).fetchone()
    if row is None or row["enc_priv"] is None:
        return None, True
    pub = public_der(load_private(unseal(umk, row["enc_priv"], ctx_enc(uid))).public_key())
    return fingerprint(pub), pub == row["enc_pub"]


def ctx_sig(uid: str) -> bytes:
    return f"sigkey|{uid}".encode()


def ctx_cert(uid: str) -> bytes:
    return f"sigcert|{uid}".encode()


def signing_identity(uid: str, umk: bytes) -> tuple[PrivateKey, bytes] | None:
    row = get_db().execute("SELECT sig_priv, sig_cert FROM users WHERE id=?", (uid,)).fetchone()
    if row is None or row["sig_priv"] is None:
        return None
    key = serialization.load_der_private_key(unseal(umk, row["sig_priv"], ctx_sig(uid)), password=None)
    return PrivateKey.from_library(key), unseal(umk, row["sig_cert"], ctx_cert(uid))


def create_signing_identity(uid: str, umk: bytes) -> tuple[PrivateKey, bytes]:
    lib_key = rsa.generate_private_key(public_exponent=65537,
                                       key_size=current_app.config.get("SIGN_RSA_BITS", 3072))
    key = PrivateKey.from_library(lib_key)
    cert = build_self_signed(key, username_of(uid, umk))
    der = lib_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    db = get_db()
    db.execute("UPDATE users SET sig_priv=?, sig_cert=?, sig_fpr=? WHERE id=?",
               (seal(umk, der, ctx_sig(uid)), seal(umk, cert, ctx_cert(uid)), hashlib.sha256(cert).digest(), uid))
    db.commit()
    log_activity(uid, "signing_key_created")
    return key, cert


def signing_fingerprint(uid: str) -> str | None:
    row = get_db().execute("SELECT sig_fpr FROM users WHERE id=?", (uid,)).fetchone()
    return row["sig_fpr"].hex().upper() if row and row["sig_fpr"] else None
