from flask import Blueprint, g, redirect, render_template, url_for

from ..catalog import CATEGORIES, NOT_ENCRYPTED, PROFILE_FIELDS

bp = Blueprint("pages", __name__)


@bp.get("/")
def index():
    if g.uid:
        return redirect(url_for("vault.dashboard"))
    return render_template("pages/index.html", categories=CATEGORIES)


@bp.get("/privacy")
def privacy():
    return render_template("pages/privacy.html", fields=PROFILE_FIELDS, categories=CATEGORIES,
                           not_encrypted=NOT_ENCRYPTED)
