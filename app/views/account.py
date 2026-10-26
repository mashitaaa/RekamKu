from __future__ import annotations

import json
import os

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

from ..crypto import unseal
from ..db import get_db, log_activity, read_activity
from ..security import login_required
from .auth import password_problems, rewrap_password, rewrap_recovery, verify_password
from .vault import list_files

bp = Blueprint("account", __name__)

EVENTS = {
    "account_created": ("Account created", "ok"),
    "login": ("Signed in", "ok"),
    "login_failed": ("Failed sign-in attempt", "warn"),
    "recovered": ("Account recovered with recovery code", "info"),
    "password_changed": ("Password changed", "info"),
    "recovery_regenerated": ("New recovery code created", "info"),
    "profile_updated": ("Profile updated", "info"),
    "file_uploaded": ("File uploaded", "ok"),
    "file_viewed": ("File opened", "info"),
    "file_downloaded": ("File downloaded", "info"),
    "file_deleted": ("File deleted", "info"),
    "integrity_checked": ("Integrity checked", "ok"),
    "integrity_failed": ("File failed verification", "warn"),
    "log_damaged": ("Log entry could not be verified", "warn"),
}


def _row():
    return get_db().execute("SELECT * FROM users WHERE id=?", (g.uid,)).fetchone()


@bp.get("/account")
@login_required
def settings():
    row = _row()
    account = json.loads(unseal(g.umk, row["account"], b"account|" + g.uid.encode()))
    acts = read_activity(g.uid, g.umk, limit=15)
    files = [f for fs in list_files(g.uid, g.umk).values() for f in fs]
    stats = {"n": len(files), "bytes": sum(f["stored_size"] for f in files)}
    return render_template("account/settings.html", username=account["username"], acts=acts, events=EVENTS,
                           stats=stats, created=account["created"])


@bp.post("/account/password")
@login_required
def change_password():
    row = _row()
    if verify_password(row, request.form.get("current", "")) is None:
        flash("Your current password is incorrect. The password was not changed.", "error")
        return redirect(url_for("account.settings") + "#password")
    new = request.form.get("password", "")
    errs = password_problems(new)
    if new != request.form.get("password2", ""):
        errs.append("The two new passwords do not match.")
    if errs:
        for e in errs:
            flash(e, "error")
        return redirect(url_for("account.settings") + "#password")
    rewrap_password(g.uid, g.umk, new)
    get_db().commit()
    current_app.extensions["keys"].drop_user(g.uid, keep=session.get("sid"))
    log_activity(g.uid, "password_changed")
    flash("Password changed. Other sessions were signed out. Your files did not need re-encryption.", "ok")
    return redirect(url_for("account.settings"))


@bp.post("/account/recovery-code")
@login_required
def new_recovery():
    if verify_password(_row(), request.form.get("current", "")) is None:
        flash("Incorrect password. Your recovery code was not changed.", "error")
        return redirect(url_for("account.settings") + "#recovery")
    code = rewrap_recovery(g.uid, g.umk)
    get_db().commit()
    log_activity(g.uid, "recovery_regenerated")
    return render_template("auth/recovery_code.html", code=code, first=False)


@bp.post("/account/delete")
@login_required
def delete_account():
    if verify_password(_row(), request.form.get("current", "")) is None:
        flash("Incorrect password. Your account was not deleted.", "error")
        return redirect(url_for("account.settings") + "#delete")
    if request.form.get("confirm", "").strip().upper() != "DELETE":
        flash("Type DELETE to confirm.", "error")
        return redirect(url_for("account.settings") + "#delete")
    db = get_db()
    blobs = [r["blob_name"] for r in db.execute("SELECT blob_name FROM files WHERE user_id=?", (g.uid,))]
    db.execute("DELETE FROM users WHERE id=?", (g.uid,))
    db.commit()
    for b in blobs:
        try:
            os.remove(os.path.join(current_app.config["STORAGE_DIR"], b))
        except FileNotFoundError:
            pass
    current_app.extensions["keys"].drop_user(g.uid)
    session.clear()
    flash("Your account and all your records were permanently deleted.", "ok")
    return redirect(url_for("pages.index"))
