from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request,
                   stream_with_context, url_for)

from ..catalog import CATEGORIES, INLINE, MIME, PROFILE_FIELDS
from ..crypto import BlobReader, IntegrityError, seal, unseal
from ..crypto.asym import TokenError, decrypt_share_key, encrypt_share_key, fingerprint, new_share_key, parse_token
from ..crypto.keys import open_from, seal_to, unwrap, wrap
from ..db import get_db, log_activity, now
from ..keyring import encryption_private, own_key_status, username_of
from ..security import login_required
from .profile import load_profile
from .vault import blob_path, ctx_blob, ctx_fek, ctx_meta, list_files

bp = Blueprint("sharing", __name__)

WANTS = {"profile": "Health profile", "identity": "Identity documents", "documents": "Medical documents",
         "videos": "Medical videos"}
OPEN = ("pending", "approved", "active")
SHARED_META = ("name", "desc", "ext", "category", "size", "sha256", "uploaded", "signatures")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def c_request(sid):
    return f"sharereq|{sid}".encode()


def c_outbox(sid, uid):
    return f"shareout|{sid}|{uid}".encode()


def c_key(sid, side):
    return f"sharekey|{side}|{sid}".encode()


def c_grant(sid):
    return f"sharegrant|{sid}".encode()


def c_fek(sid, fid):
    return f"sharefek|{sid}|{fid}".encode()


def c_meta(sid, fid):
    return f"sharemeta|{sid}|{fid}".encode()


def shared_meta(meta: dict) -> dict:
    return {k: meta[k] for k in SHARED_META if k in meta}


def _close(sid: str, status: str):
    db = get_db()
    db.execute("DELETE FROM shared_files WHERE share_id=?", (sid,))
    db.execute("UPDATE shares SET status=?, grant_info=NULL, key_owner=NULL, key_requester=NULL WHERE id=?",
               (status, sid))
    db.commit()


def _expired(grant: dict) -> bool:
    exp = grant.get("expires")
    return bool(exp) and datetime.fromisoformat(exp) <= utcnow()


def _user_by_name(username: str):
    idx = current_app.extensions["server_keys"].username_index(username)
    return get_db().execute("SELECT * FROM users WHERE username_idx=?", (idx,)).fetchone()


def _wants(form) -> list[str]:
    return [w for w in WANTS if w in form.getlist("wants")]



def _requester_item(row) -> dict:
    out = json.loads(unseal(g.umk, row["outbox"], c_outbox(row["id"], g.uid)))
    item = {"id": row["id"], "status": row["status"], **out, "grant": None, "n_files": 0}
    if row["status"] == "active":
        k = unwrap(g.umk, row["key_requester"], c_key(row["id"], "requester"))
        grant = json.loads(unseal(k, row["grant_info"], c_grant(row["id"])))
        if _expired(grant):
            _close(row["id"], "expired")
            item["status"] = "expired"
        else:
            item["grant"] = grant
            item["n_files"] = get_db().execute("SELECT COUNT(*) FROM shared_files WHERE share_id=?",
                                               (row["id"],)).fetchone()[0]
    return item


@bp.get("/shared")
@login_required
def mine():
    rows = get_db().execute("SELECT * FROM shares WHERE requester_id=? ORDER BY rowid DESC", (g.uid,)).fetchall()
    items = [_requester_item(r) for r in rows]
    my_fpr, intact = own_key_status(g.uid, g.umk)
    return render_template("share/mine.html", items=items, wants=WANTS, my_fpr=my_fpr, key_intact=intact,
                           form=request.args)


@bp.post("/shared/request")
@login_required
def create_request():
    username = request.form.get("username", "").strip()[:64]
    reason = request.form.get("reason", "").strip()[:300]
    wants = _wants(request.form)
    errs = []
    owner = _user_by_name(username) if username else None
    if not username:
        errs.append("Enter the username of the patient whose records you want to see.")
    elif owner is not None and owner["id"] == g.uid:
        errs.append("You cannot request access to your own records.")
    if len(reason) < 5:
        errs.append("Tell the patient why you need access (at least a few words).")
    if not wants:
        errs.append("Choose at least one kind of data you need.")
    if not errs and get_db().execute(
            "SELECT COUNT(*) FROM shares WHERE requester_id=? AND status='pending'",
            (g.uid,)).fetchone()[0] >= current_app.config.get("MAX_OPEN_REQUESTS", 10):
        errs.append("You have too many requests waiting for an answer. Wait for a reply or withdraw one first.")
    if errs:
        for e in errs:
            flash(e, "error")
        return redirect(url_for("sharing.mine", username=username, reason=reason))

    # The answer is the same whether or not the account exists (or already has an open request from
    # this user), so the form cannot be used to find out who has a RekamKu account.
    sent = (f"If an account named {username} exists, your request was sent. When the patient approves it, they will "
            f"send you an encrypted key by WhatsApp or e-mail. Paste it here to open the records.")
    if owner is None or get_db().execute(
            f"SELECT 1 FROM shares WHERE owner_id=? AND requester_id=? AND status IN ({','.join('?' * len(OPEN))})",
            (owner["id"], g.uid, *OPEN)).fetchone():
        flash(sent, "ok")
        return redirect(url_for("sharing.mine"))

    sid = uuid.uuid4().hex
    me = username_of(g.uid, g.umk)
    at = now()
    req = {"from": me, "reason": reason, "wants": wants, "at": at}
    out = {"to": username.lower(), "reason": reason, "wants": wants, "at": at}
    db = get_db()
    db.execute("INSERT INTO shares(id, owner_id, requester_id, status, request, outbox) VALUES(?,?,?,?,?,?)",
               (sid, owner["id"], g.uid, "pending", seal_to(owner["log_pub"], json.dumps(req).encode(), c_request(sid)),
                seal(g.umk, json.dumps(out).encode(), c_outbox(sid, g.uid))))
    db.commit()
    log_activity(g.uid, "share_requested")
    log_activity(owner["id"], "share_request_received")
    flash(sent, "ok")
    return redirect(url_for("sharing.mine"))


@bp.post("/shared/redeem")
@login_required
def redeem():
    token = request.form.get("token", "")
    try:
        sid, ct = parse_token(token)
    except TokenError as e:
        flash(str(e), "error")
        return redirect(url_for("sharing.mine"))
    row = get_db().execute("SELECT * FROM shares WHERE id=? AND requester_id=?", (sid, g.uid)).fetchone()
    if row is None:
        flash("This key does not belong to any of your requests.", "error")
        return redirect(url_for("sharing.mine"))
    if row["status"] == "active":
        flash("You already added this key. The shared records are below.", "info")
        return redirect(url_for("sharing.view", sid=sid))
    if row["status"] != "approved":
        flash("This request is no longer open, so the key cannot be used.", "error")
        return redirect(url_for("sharing.mine"))
    try:
        k = decrypt_share_key(encryption_private(g.uid, g.umk), sid, ct)
        grant = json.loads(unseal(k, row["grant_info"], c_grant(sid)))
    except TokenError as e:
        flash(str(e), "error")
        return redirect(url_for("sharing.mine"))
    except IntegrityError:
        flash("The key decrypted, but it does not open this share. Ask the patient to send it again.", "error")
        return redirect(url_for("sharing.mine"))
    if _expired(grant):
        _close(sid, "expired")
        flash("This share has already expired.", "error")
        return redirect(url_for("sharing.mine"))
    db = get_db()
    db.execute("UPDATE shares SET status='active', key_requester=? WHERE id=?",
               (wrap(g.umk, k, c_key(sid, "requester")), sid))
    db.commit()
    log_activity(g.uid, "share_key_redeemed")
    log_activity(row["owner_id"], "share_key_used")
    flash("Key accepted. It was decrypted with your private key and is now stored encrypted in your account.", "ok")
    return redirect(url_for("sharing.view", sid=sid))


@bp.post("/shared/<sid>/withdraw")
@login_required
def withdraw(sid):
    row = get_db().execute("SELECT * FROM shares WHERE id=? AND requester_id=?", (sid, g.uid)).fetchone()
    if row is None or row["status"] not in OPEN:
        abort(404, "Request not found.")
    _close(sid, "withdrawn")
    log_activity(g.uid, "share_withdrawn")
    log_activity(row["owner_id"], "share_withdrawn_by_requester")
    flash("Done. Your copy of the share key was deleted.", "ok")
    return redirect(url_for("sharing.mine"))


def open_share(sid: str):
    row = get_db().execute("SELECT * FROM shares WHERE id=? AND requester_id=?", (sid, g.uid)).fetchone()
    if row is None or row["status"] != "active":
        abort(404, "This share is not available. It may have been revoked or never approved.")
    k = unwrap(g.umk, row["key_requester"], c_key(sid, "requester"))
    grant = json.loads(unseal(k, row["grant_info"], c_grant(sid)))
    if _expired(grant):
        _close(sid, "expired")
        abort(410, "This share has expired.")
    return row, k, grant


def _shared_files(sid: str, k: bytes) -> list[dict]:
    out = []
    for r in get_db().execute("SELECT file_id, meta FROM shared_files WHERE share_id=?", (sid,)).fetchall():
        m = json.loads(unseal(k, r["meta"], c_meta(sid, r["file_id"])))
        m["id"] = r["file_id"]
        out.append(m)
    out.sort(key=lambda m: m.get("uploaded", ""), reverse=True)
    return out


@bp.get("/shared/<sid>")
@login_required
def view(sid):
    row, k, grant = open_share(sid)
    files = _shared_files(sid, k)
    groups = {c: [f for f in files if f["category"] == c] for c in CATEGORIES}
    return render_template("share/view.html", sid=sid, grant=grant, groups=groups, categories=CATEGORIES,
                           fields=PROFILE_FIELDS, n_files=len(files))


def _shared_file(sid: str, fid: str, k: bytes):
    r = get_db().execute("SELECT sf.fek, sf.meta, f.user_id, f.blob_name FROM shared_files sf "
                         "JOIN files f ON f.id = sf.file_id WHERE sf.share_id=? AND sf.file_id=?",
                         (sid, fid)).fetchone()
    if r is None:
        abort(404, "File not found in this share.")
    meta = json.loads(unseal(k, r["meta"], c_meta(sid, fid)))
    meta["id"] = fid
    return r, meta, unwrap(k, r["fek"], c_fek(sid, fid))


@bp.get("/shared/<sid>/files/<fid>")
@login_required
def shared_file(sid, fid):
    row, k, grant = open_share(sid)
    r, m, _ = _shared_file(sid, fid, k)
    log_activity(g.uid, "shared_file_opened")
    log_activity(row["owner_id"], "shared_file_opened_by_requester")
    return render_template("share/file.html", sid=sid, f=m, grant=grant, cat=CATEGORIES[m["category"]],
                           inline=m["ext"] in INLINE)


@bp.get("/shared/<sid>/files/<fid>/content")
@login_required
def shared_content(sid, fid):
    row, k, grant = open_share(sid)
    r, m, fek = _shared_file(sid, fid, k)
    size = m["size"]
    download = request.args.get("download") == "1" or m["ext"] not in INLINE
    start, stop, status = 0, size, 200
    headers = {"Accept-Ranges": "bytes"}
    if request.range and not download:
        rng = request.range.range_for_length(size)
        if rng is None:
            return Response(status=416, headers={"Content-Range": f"bytes */{size}"})
        start, stop = rng
        status = 206
        headers["Content-Range"] = f"bytes {start}-{stop - 1}/{size}"
    headers["Content-Length"] = str(stop - start)
    if download:
        ascii_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in m["name"])
        headers["Content-Disposition"] = (f'attachment; filename="{ascii_name}"; '
                                          f"filename*=UTF-8''{quote(m['name'])}")
        log_activity(row["owner_id"], "shared_file_downloaded_by_requester")
    try:
        rd = BlobReader(blob_path(r["blob_name"]), fek, ctx_blob(r["user_id"], fid, r["blob_name"]))
        try:
            rd.chunk(start // rd.chunk_size)
        except IntegrityError:
            rd.close()
            raise
    except (IntegrityError, FileNotFoundError):
        abort(409, "This file is not intact (it was modified or damaged in storage), so it was not sent.")

    def generate():
        try:
            yield from rd.iter_range(start, stop)
        finally:
            rd.close()

    mime = "application/octet-stream" if download else MIME.get(m["ext"], "application/octet-stream")
    resp = Response(stream_with_context(generate()), status=status, mimetype=mime, headers=headers,
                    direct_passthrough=True)
    resp.call_on_close(rd.close)
    return resp



def _log_priv() -> bytes:
    row = get_db().execute("SELECT log_priv FROM users WHERE id=?", (g.uid,)).fetchone()
    return unwrap(g.umk, row["log_priv"], f"logkey|{g.uid}".encode())


def _owner_item(row, log_priv: bytes) -> dict:
    req = json.loads(open_from(log_priv, row["request"], c_request(row["id"])))
    item = {"id": row["id"], "status": row["status"], **req, "grant": None, "n_files": 0}
    if row["key_owner"] is not None:
        k = unwrap(g.umk, row["key_owner"], c_key(row["id"], "owner"))
        grant = json.loads(unseal(k, row["grant_info"], c_grant(row["id"])))
        if _expired(grant):
            _close(row["id"], "expired")
            item["status"] = "expired"
        else:
            item["grant"] = grant
            item["n_files"] = get_db().execute("SELECT COUNT(*) FROM shared_files WHERE share_id=?",
                                               (row["id"],)).fetchone()[0]
    return item


def _own_share(sid: str, statuses: tuple[str, ...]):
    row = get_db().execute("SELECT * FROM shares WHERE id=? AND owner_id=?", (sid, g.uid)).fetchone()
    if row is None:
        abort(404, "Request not found.")
    if row["status"] not in statuses:
        flash("This request is no longer open.", "info")
        return None
    return row


@bp.get("/sharing")
@login_required
def inbox():
    log_priv = _log_priv()
    rows = get_db().execute("SELECT * FROM shares WHERE owner_id=? ORDER BY rowid DESC", (g.uid,)).fetchall()
    items = [_owner_item(r, log_priv) for r in rows]
    return render_template("share/inbox.html", wants=WANTS,
                           pending=[i for i in items if i["status"] == "pending"],
                           current=[i for i in items if i["status"] in ("approved", "active")],
                           closed=[i for i in items if i["status"] not in OPEN])


@bp.get("/sharing/<sid>/review")
@login_required
def review(sid):
    row = _own_share(sid, ("pending",))
    if row is None:
        return redirect(url_for("sharing.inbox"))
    item = _owner_item(row, _log_priv())
    req_user = get_db().execute("SELECT enc_pub FROM users WHERE id=?", (row["requester_id"],)).fetchone()
    files = list_files(g.uid, g.umk)
    return render_template("share/review.html", item=item, wants=WANTS, files=files, categories=CATEGORIES,
                           has_profile=bool(load_profile(g.uid, g.umk)), days=current_app.config["SHARE_DAYS"],
                           fpr=fingerprint(req_user["enc_pub"]) if req_user["enc_pub"] else None)


def _token_page(row, item: dict, k: bytes, first: bool):
    req_user = get_db().execute("SELECT enc_pub FROM users WHERE id=?", (row["requester_id"],)).fetchone()
    token = encrypt_share_key(req_user["enc_pub"], row["id"], k)
    msg = (f"RekamKu share key for {item['from']} (from {username_of(g.uid, g.umk)}).\n"
           f"Open RekamKu > Shared with me and paste it into 'Add a share key'. "
           f"Only your account's private key can open it.\n\n{token}")
    return render_template("share/token.html", item=item, token=token, first=first,
                           fpr=fingerprint(req_user["enc_pub"]),
                           wa=f"https://wa.me/?text={quote(msg)}",
                           mail=f"mailto:?subject={quote('RekamKu share key')}&body={quote(msg)}")


@bp.post("/sharing/<sid>/approve")
@login_required
def approve(sid):
    row = _own_share(sid, ("pending",))
    if row is None:
        return redirect(url_for("sharing.inbox"))
    db = get_db()
    req_user = db.execute("SELECT enc_pub FROM users WHERE id=?", (row["requester_id"],)).fetchone()
    if req_user["enc_pub"] is None:
        flash("The requester has no encryption key yet. Ask them to sign in to RekamKu once, then try again.",
              "error")
        return redirect(url_for("sharing.review", sid=sid))
    wanted = set(request.form.getlist("files"))
    mine = {r["id"]: r for r in db.execute("SELECT * FROM files WHERE user_id=?", (g.uid,)).fetchall()}
    chosen = [mine[f] for f in wanted if f in mine]
    with_profile = request.form.get("profile") == "1"
    try:
        days = int(request.form.get("days", ""))
    except ValueError:
        days = 0
    if days not in current_app.config["SHARE_DAYS"]:
        flash("Choose how long the access should last.", "error")
        return redirect(url_for("sharing.review", sid=sid))
    if not chosen and not with_profile:
        flash("Choose at least one file or your health profile to share.", "error")
        return redirect(url_for("sharing.review", sid=sid))

    k = new_share_key()
    item = _owner_item(row, _log_priv())
    grant = {"owner": username_of(g.uid, g.umk), "profile": load_profile(g.uid, g.umk) if with_profile else None,
             "approved": now(), "expires": (utcnow() + timedelta(days=days)).isoformat(timespec="seconds"),
             "days": days}
    for f in chosen:
        fek = unwrap(g.umk, f["fek"], ctx_fek(g.uid, f["id"]))
        meta = json.loads(unseal(g.umk, f["meta"], ctx_meta(g.uid, f["id"])))
        db.execute("INSERT INTO shared_files(share_id, file_id, fek, meta) VALUES(?,?,?,?)",
                   (sid, f["id"], wrap(k, fek, c_fek(sid, f["id"])),
                    seal(k, json.dumps(shared_meta(meta)).encode(), c_meta(sid, f["id"]))))
    db.execute("UPDATE shares SET status='approved', grant_info=?, key_owner=? WHERE id=?",
               (seal(k, json.dumps(grant).encode(), c_grant(sid)), wrap(g.umk, k, c_key(sid, "owner")), sid))
    db.commit()
    log_activity(g.uid, "share_approved")
    log_activity(row["requester_id"], "share_request_approved")
    item["grant"] = grant
    item["n_files"] = len(chosen)
    row = db.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
    return _token_page(row, item, k, first=True)


@bp.get("/sharing/<sid>/key")
@login_required
def show_key(sid):
    row = _own_share(sid, ("approved",))
    if row is None:
        return redirect(url_for("sharing.inbox"))
    item = _owner_item(row, _log_priv())
    if item["status"] != "approved":
        return redirect(url_for("sharing.inbox"))
    k = unwrap(g.umk, row["key_owner"], c_key(sid, "owner"))
    return _token_page(row, item, k, first=False)


@bp.post("/sharing/<sid>/decline")
@login_required
def decline(sid):
    row = _own_share(sid, ("pending",))
    if row is not None:
        _close(sid, "declined")
        log_activity(g.uid, "share_declined")
        log_activity(row["requester_id"], "share_request_declined")
        flash("Request declined. Nothing was shared.", "ok")
    return redirect(url_for("sharing.inbox"))


@bp.post("/sharing/<sid>/revoke")
@login_required
def revoke(sid):
    row = _own_share(sid, ("approved", "active"))
    if row is not None:
        _close(sid, "revoked")
        log_activity(g.uid, "share_revoked")
        log_activity(row["requester_id"], "share_revoked_by_owner")
        flash("Access revoked. The share key and every file key wrapped with it were deleted.", "ok")
    return redirect(url_for("sharing.inbox"))
