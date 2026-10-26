from __future__ import annotations

import json
import os
import re
import secrets
import uuid

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

from ..crypto import IntegrityError, seal
from ..crypto.keys import KdfParams, new_key, new_log_keypair, new_recovery_code, normalize_recovery_code, unwrap, wrap
from ..db import get_db, log_activity, now
from ..security import safe_next

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,32}")


def password_problems(pw: str, username: str = "") -> list[str]:
    errs = []
    if not 12 <= len(pw) <= 128:
        errs.append("Password must be 12 to 128 characters long.")
    if username and username.lower() in pw.lower():
        errs.append("Password must not contain your username.")
    if len(set(pw)) < 6:
        errs.append("Password is too easy to guess. Use a wider mix of characters.")
    return errs


def _sk():
    return current_app.extensions["server_keys"]


def start_session(uid: str, umk: bytes):
    session.clear()
    session.permanent = True
    session["csrf"] = secrets.token_urlsafe(32)
    session["uid"] = uid
    session["sid"] = current_app.extensions["keys"].put(uid, umk)


def create_user(username: str, password: str) -> tuple[str, str, bytes]:
    sk, params = _sk(), current_app.config["KDF"]
    uid = uuid.uuid4().hex
    umk = new_key()
    code = new_recovery_code()
    pw_salt, rc_salt = os.urandom(16), os.urandom(16)
    kek_pw = sk.derive_kek(password, pw_salt, params, b"pw")
    kek_rc = sk.derive_kek(code, rc_salt, params, b"rc")
    log_priv, log_pub = new_log_keypair()
    account = json.dumps({"username": username, "created": now()}).encode()
    db = get_db()
    db.execute(
        "INSERT INTO users(id, username_idx, kdf, pw_salt, umk_by_pw, rc_salt, umk_by_rc, account, log_pub, "
        "log_priv, profile) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (uid, sk.username_index(username), params.encode(), pw_salt, wrap(kek_pw, umk, b"umk|pw|" + uid.encode()),
         rc_salt, wrap(kek_rc, umk, b"umk|rc|" + uid.encode()), seal(umk, account, b"account|" + uid.encode()),
         log_pub, wrap(umk, log_priv, f"logkey|{uid}".encode()), None))
    db.commit()
    return uid, code, umk


def verify_password(row, password: str) -> bytes | None:
    kek = _sk().derive_kek(password, row["pw_salt"], KdfParams.decode(row["kdf"]), b"pw")
    try:
        return unwrap(kek, row["umk_by_pw"], b"umk|pw|" + row["id"].encode())
    except IntegrityError:
        return None


def rewrap_password(uid: str, umk: bytes, new_password: str):
    params = current_app.config["KDF"]
    salt = os.urandom(16)
    kek = _sk().derive_kek(new_password, salt, params, b"pw")
    get_db().execute("UPDATE users SET kdf=?, pw_salt=?, umk_by_pw=? WHERE id=?",
                     (params.encode(), salt, wrap(kek, umk, b"umk|pw|" + uid.encode()), uid))


def rewrap_recovery(uid: str, umk: bytes) -> str:
    code = new_recovery_code()
    salt = os.urandom(16)
    kek = _sk().derive_kek(code, salt, current_app.config["KDF"], b"rc")
    get_db().execute("UPDATE users SET rc_salt=?, umk_by_rc=? WHERE id=?",
                     (salt, wrap(kek, umk, b"umk|rc|" + uid.encode()), uid))
    return code


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.uid:
        return redirect(url_for("vault.dashboard"))
    form = {"username": ""}
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        form["username"] = u
        errs = []
        if not USERNAME_RE.fullmatch(u):
            errs.append("Username must be 3 to 32 characters: letters, digits, or underscores.")
        errs += password_problems(pw, u)
        if pw != request.form.get("password2", ""):
            errs.append("The two passwords do not match.")
        if not request.form.get("consent"):
            errs.append("Tick the consent box to allow us to process your health data.")
        if not errs and get_db().execute("SELECT 1 FROM users WHERE username_idx=?",
                                         (_sk().username_index(u),)).fetchone():
            errs.append("That username is taken. Choose another one.")
        if errs:
            for e in errs:
                flash(e, "error")
            return render_template("auth/register.html", form=form), 400
        uid, code, umk = create_user(u, pw)
        start_session(uid, umk)
        log_activity(uid, "account_created")
        return render_template("auth/recovery_code.html", code=code, first=True)
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.uid:
        return redirect(url_for("vault.dashboard"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()[:64]
        pw = request.form.get("password", "")[:128]
        idx = _sk().username_index(u)
        keys = ("u:" + idx.hex(), "ip:" + (request.remote_addr or "?"))
        th = current_app.extensions["throttle"]
        if th.blocked(*keys):
            flash("Too many failed attempts. Wait 15 minutes, or recover your account with your recovery code.",
                  "error")
            return render_template("auth/login.html", username=u), 429
        row = get_db().execute("SELECT * FROM users WHERE username_idx=?", (idx,)).fetchone()
        umk = None
        if row:
            umk = verify_password(row, pw)
        else:
            _sk().derive_kek(pw, os.urandom(16), current_app.config["KDF"], b"pw")
        if umk is None:
            th.fail(*keys)
            if row:
                log_activity(row["id"], "login_failed")
            flash("Incorrect username or password.", "error")
            return render_template("auth/login.html", username=u), 401
        th.reset(keys[0])
        start_session(row["id"], umk)
        log_activity(row["id"], "login")
        return redirect(safe_next(request.args.get("next")) or url_for("vault.dashboard"))
    return render_template("auth/login.html", username="")


@bp.post("/logout")
def logout():
    current_app.extensions["keys"].drop(session.get("sid"))
    session.clear()
    flash("You are signed out. Your session key has been erased from server memory.", "ok")
    return redirect(url_for("auth.login"))


@bp.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        u = request.form.get("username", "").strip()[:64]
        code = normalize_recovery_code(request.form.get("code", ""))
        pw = request.form.get("password", "")
        errs = password_problems(pw, u)
        if pw != request.form.get("password2", ""):
            errs.append("The two new passwords do not match.")
        idx = _sk().username_index(u)
        keys = ("rc:" + idx.hex(), "ip:" + (request.remote_addr or "?"))
        th = current_app.extensions["throttle"]
        if th.blocked(*keys):
            flash("Too many failed attempts. Wait 15 minutes.", "error")
            return render_template("auth/recover.html", username=u), 429
        if errs:
            for e in errs:
                flash(e, "error")
            return render_template("auth/recover.html", username=u), 400
        row = get_db().execute("SELECT * FROM users WHERE username_idx=?", (idx,)).fetchone()
        umk = None
        if row:
            kek = _sk().derive_kek(code, row["rc_salt"], KdfParams.decode(row["kdf"]), b"rc")
            try:
                umk = unwrap(kek, row["umk_by_rc"], b"umk|rc|" + row["id"].encode())
            except IntegrityError:
                umk = None
        else:
            _sk().derive_kek(code, os.urandom(16), current_app.config["KDF"], b"rc")
        if umk is None:
            th.fail(*keys)
            flash("Incorrect username or recovery code.", "error")
            return render_template("auth/recover.html", username=u), 401
        rewrap_password(row["id"], umk, pw)
        new_code = rewrap_recovery(row["id"], umk)
        get_db().commit()
        current_app.extensions["keys"].drop_user(row["id"])
        start_session(row["id"], umk)
        log_activity(row["id"], "recovered")
        return render_template("auth/recovery_code.html", code=new_code, first=False)
    return render_template("auth/recover.html", username="")
