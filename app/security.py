from __future__ import annotations

import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, flash, g, redirect, request, session, url_for


class KeyCache:
    def __init__(self, idle: int, absolute: int):
        self.idle, self.absolute = idle, absolute
        self._d: dict[str, dict] = {}
        self._lock = threading.Lock()

    def put(self, uid: str, umk: bytes) -> str:
        sid = secrets.token_urlsafe(32)
        t = time.monotonic()
        with self._lock:
            self._d[sid] = {"uid": uid, "umk": umk, "created": t, "seen": t}
        return sid

    def get(self, sid: str | None):
        if not sid:
            return None
        t = time.monotonic()
        with self._lock:
            e = self._d.get(sid)
            if not e:
                return None
            if t - e["seen"] > self.idle or t - e["created"] > self.absolute:
                del self._d[sid]
                return None
            e["seen"] = t
            return e

    def drop(self, sid: str | None):
        with self._lock:
            self._d.pop(sid, None)

    def drop_user(self, uid: str, keep: str | None = None):
        with self._lock:
            for sid in [s for s, e in self._d.items() if e["uid"] == uid and s != keep]:
                del self._d[sid]


class Throttle:
    def __init__(self, limit: int, window: int):
        self.limit, self.window = limit, window
        self._d: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, key):
        q, t = self._d[key], time.monotonic()
        while q and t - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, *keys) -> bool:
        with self._lock:
            return any(len(self._trim(k)) >= self.limit for k in keys)

    def fail(self, *keys):
        with self._lock:
            for k in keys:
                self._trim(k).append(time.monotonic())

    def reset(self, *keys):
        with self._lock:
            for k in keys:
                self._d.pop(k, None)


def before_request():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        sent = request.headers.get("X-CSRF-Token")
        if sent is None and request.mimetype in ("application/x-www-form-urlencoded", "multipart/form-data"):
            sent = request.form.get("csrf")
        if not sent or not secrets.compare_digest(sent, session["csrf"]):
            abort(400, "Invalid CSRF token. Reload the page and try again.")
    g.uid = g.umk = None
    e = current_app.extensions["keys"].get(session.get("sid"))
    if e and e["uid"] == session.get("uid"):
        g.uid, g.umk = e["uid"], e["umk"]
    elif session.get("uid"):
        session.pop("uid", None)
        session.pop("sid", None)
        g.session_expired = True


def after_request(resp):
    h = resp.headers
    h.setdefault("Content-Security-Policy",
                 "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; "
                 "media-src 'self' blob:; font-src 'self'; connect-src 'self'; form-action 'self'; "
                 "frame-ancestors 'none'; base-uri 'none'")
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if not request.path.startswith("/static/"):
        h["Cache-Control"] = "no-store"
    if current_app.config.get("SESSION_COOKIE_SECURE"):
        h["Strict-Transport-Security"] = "max-age=31536000"
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if not g.get("uid"):
            if request.accept_mimetypes.best == "application/json" or request.headers.get("X-CSRF-Token"):
                abort(401)
            flash("Your session has ended. Sign in again to open your vault."
                  if g.get("session_expired") else "Sign in to open your vault.", "info")
            return redirect(url_for("auth.login", next=request.path))
        return view(*a, **kw)
    return wrapper


def safe_next(target: str | None) -> str | None:
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None
