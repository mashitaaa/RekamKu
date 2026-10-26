from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

from .crypto.keys import open_from, seal_to, unwrap

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users(
    id            TEXT PRIMARY KEY,          -- random UUID
    username_idx  BLOB NOT NULL UNIQUE,      -- HMAC-SHA256(server key, username), for sign-in lookup
    kdf           TEXT NOT NULL,             -- scrypt parameters, e.g. scrypt$n=131072$r=8$p=1
    pw_salt       BLOB NOT NULL,
    umk_by_pw     BLOB NOT NULL,             -- UMK wrapped by the password KEK
    rc_salt       BLOB NOT NULL,
    umk_by_rc     BLOB NOT NULL,             -- UMK wrapped by the recovery-code KEK
    account       BLOB NOT NULL,             -- encrypted {username, created} (UMK)
    log_pub       BLOB NOT NULL,             -- X25519 public key: lets the server append log entries
    log_priv      BLOB NOT NULL,             -- matching private key, wrapped by the UMK
    profile       BLOB                       -- encrypted profile JSON (UMK)
);
CREATE TABLE IF NOT EXISTS files(
    id            TEXT PRIMARY KEY,          -- random UUID
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fek           BLOB NOT NULL,             -- file key wrapped by the UMK
    meta          BLOB NOT NULL,             -- encrypted {name, note, category, size, SHA-256, uploaded}
    blob_name     TEXT NOT NULL UNIQUE       -- random name of the ciphertext file in storage/
);
CREATE INDEX IF NOT EXISTS files_by_owner ON files(user_id);
CREATE TABLE IF NOT EXISTS activity(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entry    BLOB NOT NULL                   -- {event, time} sealed to the user's log_pub
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path: str):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.close()


def _log_ctx(user_id: str) -> bytes:
    return f"activity|{user_id}".encode()


def log_activity(user_id: str, event: str):
    db = get_db()
    row = db.execute("SELECT log_pub FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        return
    entry = seal_to(row["log_pub"], json.dumps({"event": event, "at": now()}).encode(), _log_ctx(user_id))
    db.execute("INSERT INTO activity(user_id, entry) VALUES(?,?)", (user_id, entry))
    db.execute("DELETE FROM activity WHERE user_id=? AND id NOT IN "
               "(SELECT id FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 200)", (user_id, user_id))
    db.commit()


def read_activity(user_id: str, umk: bytes, limit: int = 40) -> list[dict]:
    db = get_db()
    row = db.execute("SELECT log_priv FROM users WHERE id=?", (user_id,)).fetchone()
    priv = unwrap(umk, row["log_priv"], f"logkey|{user_id}".encode())
    out = []
    for r in db.execute("SELECT entry FROM activity WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit)):
        try:
            out.append(json.loads(open_from(priv, r["entry"], _log_ctx(user_id))))
        except Exception:
            out.append({"event": "log_damaged", "at": now()})
    return out
