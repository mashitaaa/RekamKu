from __future__ import annotations

import json
import re
from datetime import date

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ..catalog import BLOOD_TYPES, PROFILE_FIELDS, PROFILE_GROUPS, SEXES
from ..crypto import seal, unseal
from ..db import get_db, log_activity
from ..security import login_required

bp = Blueprint("profile", __name__)


def ctx_profile(uid: str) -> bytes:
    return f"profile|{uid}".encode()


def load_profile(uid: str, umk: bytes) -> dict:
    row = get_db().execute("SELECT profile FROM users WHERE id=?", (uid,)).fetchone()
    if not row or row["profile"] is None:
        return {}
    return json.loads(unseal(umk, row["profile"], ctx_profile(uid)))


def validate(form) -> tuple[dict, list[str]]:
    data, errs = {}, []
    for key, label, _grp, _cls, _basis, _hint, kind in PROFILE_FIELDS:
        v = form.get(key, "").strip()
        v = v[:600 if kind == "textarea" else 120]
        if not v:
            data[key] = ""
            continue
        if kind == "nik" and not re.fullmatch(r"\d{16}", v):
            errs.append("NIK must be exactly 16 digits.")
        elif kind == "digits" and not re.fullmatch(r"\d{13}", v):
            errs.append(f"{label} must be exactly 13 digits.")
        elif kind == "tel" and not re.fullmatch(r"\+?[0-9 \-]{8,20}", v):
            errs.append(f"{label} may only contain digits, spaces, + or - (8 to 20 characters).")
        elif kind == "date":
            try:
                if not date(1900, 1, 1) <= date.fromisoformat(v) <= date.today():
                    raise ValueError
            except ValueError:
                errs.append("Date of birth is not valid.")
        elif kind == "blood" and v not in BLOOD_TYPES:
            errs.append("Choose a blood type from the list.")
        elif kind == "sex" and v not in SEXES:
            errs.append("Choose a sex from the list.")
        data[key] = v
    return data, errs


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def edit():
    profile = load_profile(g.uid, g.umk)
    if request.method == "POST":
        data, errs = validate(request.form)
        if errs:
            for e in errs:
                flash(e, "error")
            profile = data
        else:
            get_db().execute("UPDATE users SET profile=? WHERE id=?",
                             (seal(g.umk, json.dumps(data).encode(), ctx_profile(g.uid)), g.uid))
            get_db().commit()
            log_activity(g.uid, "profile_updated")
            flash("Profile saved and encrypted.", "ok")
            return redirect(url_for("profile.edit"))
    filled = sum(1 for f in PROFILE_FIELDS if profile.get(f[0]))
    return render_template("vault/profile.html", profile=profile, fields=PROFILE_FIELDS, groups=PROFILE_GROUPS,
                           blood_types=BLOOD_TYPES, sexes=SEXES, filled=filled, total=len(PROFILE_FIELDS))
