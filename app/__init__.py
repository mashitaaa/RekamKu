from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, request

from . import db, security
from .crypto.keys import KdfParams, ServerKeys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, instance_path=os.path.join(BASE, "instance"))
    instance = (overrides or {}).get("INSTANCE_DIR", app.instance_path)
    cfg = {
        "INSTANCE_DIR": instance,
        "DB_PATH": os.path.join(instance, "rekamku.db"),
        "STORAGE_DIR": os.path.join(instance, "storage"),
        "SERVER_KEY_PATH": os.path.join(instance, "server.key"),
        "KDF": KdfParams(),
        "CHUNK_LOG2": 20,
        "IDLE_TIMEOUT": 15 * 60,
        "ABSOLUTE_TIMEOUT": 8 * 3600,
        "LOGIN_LIMIT": 5, "LOGIN_WINDOW": 15 * 60,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "SESSION_COOKIE_SECURE": os.environ.get("REKAMKU_HTTPS") == "1",
        "SESSION_COOKIE_NAME": "rk_session",
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
        "MAX_CONTENT_LENGTH": 210 * 1024 * 1024,
    }
    cfg.update(overrides or {})
    app.config.update(cfg)

    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    keys = ServerKeys.load_or_create(app.config["SERVER_KEY_PATH"], os.environ.get("REKAMKU_SERVER_KEY"))
    app.secret_key = keys.flask_secret
    app.extensions["server_keys"] = keys
    app.extensions["keys"] = security.KeyCache(app.config["IDLE_TIMEOUT"], app.config["ABSOLUTE_TIMEOUT"])
    app.extensions["throttle"] = security.Throttle(app.config["LOGIN_LIMIT"], app.config["LOGIN_WINDOW"])
    db.init_db(app.config["DB_PATH"])

    app.before_request(security.before_request)
    app.after_request(security.after_request)
    app.teardown_appcontext(db.close_db)

    from .views import account, auth, pages, profile, vault
    for bp in (auth.bp, vault.bp, profile.bp, account.bp, pages.bp):
        app.register_blueprint(bp)

    @app.template_filter("size")
    def _size(n):
        n = int(n or 0)
        if n >= 1 << 20:
            return f"{n / (1 << 20):.1f} MB"
        return f"{max(1, round(n / 1024))} KB"

    @app.template_filter("date")
    def _date(iso, with_time=False):
        d = datetime.fromisoformat(iso).astimezone()
        s = f"{d.day} {MONTHS[d.month - 1]} {d.year}"
        return s + d.strftime(", %H:%M") if with_time else s

    @app.template_filter("ago")
    def _ago(iso):
        secs = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
        for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
            if secs >= n:
                k = int(secs // n)
                return f"{k} {unit}{'s' if k > 1 else ''} ago"
        return "just now"

    @app.context_processor
    def _ctx():
        from flask import g, session
        ctx = {"csrf_token": session.get("csrf", ""), "signed_in": bool(g.get("uid")), "nav_counts": {}, "me": {}}
        if g.get("uid"):
            from .views.vault import list_files
            ctx["nav_counts"] = {k: len(v) for k, v in list_files(g.uid, g.umk).items()}
            from .views.profile import load_profile
            name = load_profile(g.uid, g.umk).get("name", "")
            initials = "".join(w[0] for w in name.split()[:2]).upper() or "Me"
            ctx["me"] = {"name": name, "first": name.split()[0] if name else "", "initials": initials}
        return ctx

    from werkzeug.exceptions import HTTPException

    @app.errorhandler(HTTPException)
    def _err(e):
        code = e.code or 500
        if request.headers.get("X-CSRF-Token"):
            return {"ok": False, "error": e.description}, code
        return render_template("pages/error.html", code=code, error=e), code

    return app
