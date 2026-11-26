from __future__ import annotations

import json

from flask import current_app

from .crypto import seal, unseal
from .crypto.asym import fingerprint, load_private, new_rsa_keypair, public_der
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
