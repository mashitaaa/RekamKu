from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

from .crypto.keys import open_from, seal_to, unwrap

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users(
    id            TEXT PRIMARY KEY,
    username_idx  BLOB NOT NULL UNIQUE,
    kdf           TEXT NOT NULL,
    pw_salt       BLOB NOT NULL,
    umk_by_pw     BLOB NOT NULL,
    rc_salt       BLOB NOT NULL,
    umk_by_rc     BLOB NOT NULL,
    account       BLOB NOT NULL,
    log_pub       BLOB NOT NULL,
    log_priv      BLOB NOT NULL,
    profile       BLOB,
    enc_pub       BLOB,
    enc_priv      BLOB,
    sig_priv      BLOB,
    sig_cert      BLOB,
    sig_fpr       BLOB
);
CREATE TABLE IF NOT EXISTS files(
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fek           BLOB NOT NULL,
    meta          BLOB NOT NULL,
    blob_name     TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS files_by_owner ON files(user_id);
CREATE TABLE IF NOT EXISTS shares(
    id            TEXT PRIMARY KEY,
    owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requester_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status        TEXT NOT NULL,
    request       BLOB NOT NULL,
    outbox        BLOB NOT NULL,
    grant_info    BLOB,
    key_owner     BLOB,
    key_requester BLOB
);
CREATE INDEX IF NOT EXISTS shares_by_owner ON shares(owner_id);
CREATE INDEX IF NOT EXISTS shares_by_requester ON shares(requester_id);
CREATE TABLE IF NOT EXISTS shared_files(
    share_id      TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    file_id       TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    fek           BLOB NOT NULL,
    meta          BLOB NOT NULL,
    PRIMARY KEY (share_id, file_id)
);
CREATE TABLE IF NOT EXISTS activity(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entry    BLOB NOT NULL
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


USER_COLUMNS = ("enc_pub", "enc_priv", "sig_priv", "sig_cert", "sig_fpr")


def init_db(path: str):
    con = sqlite3.connect(path)
    have = {r[1] for r in con.execute("PRAGMA table_info(users)")}
    if have:
        for col in USER_COLUMNS:
            if col not in have:
                con.execute(f"ALTER TABLE users ADD COLUMN {col} BLOB")
        con.commit()
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
