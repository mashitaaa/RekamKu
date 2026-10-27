from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from urllib.parse import quote, unquote

from flask import (Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, render_template, request,
                   stream_with_context, url_for)
from werkzeug.exceptions import ClientDisconnected

from ..catalog import CATEGORIES, INLINE, MIME, sniff
from ..crypto import BlobReader, IntegrityError, encrypt_stream, seal, unseal
from ..crypto.keys import new_key, unwrap, wrap
from ..db import get_db, log_activity, now, read_activity
from ..security import login_required
from .profile import load_profile

bp = Blueprint("vault", __name__)


def ctx_fek(uid, fid):
    return f"fek|{uid}|{fid}".encode()


def ctx_meta(uid, fid):
    return f"meta|{uid}|{fid}".encode()


def ctx_blob(uid, fid, blob):
    return f"blob|{uid}|{fid}|{blob}".encode()


def blob_path(name: str) -> str:
    return os.path.join(current_app.config["STORAGE_DIR"], name)


def own_file(fid: str):
    row = get_db().execute("SELECT * FROM files WHERE id=? AND user_id=?", (fid, g.uid)).fetchone()
    if row is None:
        abort(404, "File not found.")
    return row


def file_meta(row) -> dict:
    return _enrich(json.loads(unseal(g.umk, row["meta"], ctx_meta(g.uid, row["id"]))), row)


def file_key(row) -> bytes:
    return unwrap(g.umk, row["fek"], ctx_fek(g.uid, row["id"]))


def stored_size(blob_name: str) -> int:
    try:
        return os.path.getsize(blob_path(blob_name))
    except OSError:
        return 0


def _enrich(m: dict, row) -> dict:
    m.update(id=row["id"], created_at=m.get("uploaded", ""), stored_size=stored_size(row["blob_name"]))
    return m


def list_files(uid: str, umk: bytes) -> dict[str, list[dict]]:
    cache = g.setdefault("_files", {})
    if uid in cache:
        return cache[uid]
    out = {k: [] for k in CATEGORIES}
    for r in get_db().execute("SELECT * FROM files WHERE user_id=?", (uid,)).fetchall():
        try:
            m = json.loads(unseal(umk, r["meta"], ctx_meta(uid, r["id"])))
        except IntegrityError:
            m = {"name": "(damaged metadata)", "size": 0, "ext": "", "desc": "", "category": "documents",
                 "uploaded": now(), "damaged": True}
        out.setdefault(m.get("category", "documents"), []).append(_enrich(m, r))
    for items in out.values():
        items.sort(key=lambda f: f["created_at"], reverse=True)
    cache[uid] = out
    return out


@bp.get("/dashboard")
@login_required
def dashboard():
    files = list_files(g.uid, g.umk)
    recent = sorted((f for fs in files.values() for f in fs), key=lambda f: f["created_at"], reverse=True)[:6]
    stored = sum(f["stored_size"] for fs in files.values() for f in fs)
    acts = read_activity(g.uid, g.umk, limit=40)
    logins = [a for a in acts if a["event"] == "login"]
    security = {
        "previous_login": logins[1]["at"] if len(logins) > 1 else None,
        "failed": sum(1 for a in acts if a["event"] == "login_failed"),
        "integrity_failed": sum(1 for a in acts if a["event"] == "integrity_failed"),
    }
    return render_template("vault/dashboard.html", files=files, recent=recent, categories=CATEGORIES,
                           profile=load_profile(g.uid, g.umk), stored=stored, security=security)


@bp.get("/vault/<category>")
@login_required
def folder(category):
    if category not in CATEGORIES:
        abort(404, "Unknown folder.")
    files = list_files(g.uid, g.umk)
    items = files[category]
    return render_template("vault/folder.html", key=category, cat=CATEGORIES[category], categories=CATEGORIES,
                           files=files, items=items, active_folder=category,
                           total_size=sum(f["size"] for f in items))


@bp.get("/files/<fid>")
@login_required
def detail(fid):
    row = own_file(fid)
    m = file_meta(row)
    log_activity(g.uid, "file_viewed")
    return render_template("vault/detail.html", f=m, row=row, key=m["category"], cat=CATEGORIES[m["category"]],
                           inline=m["ext"] in INLINE, mime=MIME.get(m["ext"], ""), active_folder=m["category"])


@bp.post("/files/upload")
@login_required
def upload():
    cat_key = request.args.get("category", "")
    cat = CATEGORIES.get(cat_key)
    if cat is None:
        abort(400, "Unknown category.")
    name = os.path.basename(unquote(request.headers.get("X-Filename", "")).replace("\\", "/")).strip()[:150]
    desc = unquote(request.headers.get("X-Description", "")).strip()[:300]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if not name or ext not in cat["exts"]:
        abort(415, f".{ext or '?'} files are not accepted in {cat['title']}. "
                   f"Use {', '.join(e.upper() for e in cat['exts'])}.")
    length = request.content_length
    if not length:
        abort(411, "The file is empty or its size is unknown.")
    if length > cat["max_mb"] * 1024 * 1024:
        abort(413, f"The file is larger than the {cat['max_mb']} MB limit for a {cat['noun']}.")

    fid, blob = uuid.uuid4().hex, uuid.uuid4().hex
    fek = new_key()
    sha = hashlib.sha256()
    state = {"first": True}

    def on_plain(chunk: bytes):
        if state["first"]:
            state["first"] = False
            if not sniff(ext, chunk[:16]):
                raise ValueError("file content does not match its extension")
        sha.update(chunk)

    final, tmp = blob_path(blob), blob_path(".part-" + blob)
    t0 = time.perf_counter()
    try:
        with open(tmp, "wb") as out:
            n = encrypt_stream(fek, ctx_blob(g.uid, fid, blob), request.stream.read, out.write,
                               chunk_log2=current_app.config["CHUNK_LOG2"], on_plain=on_plain)
        if n != length:
            raise ClientDisconnected()
        os.replace(tmp, final)
    except ValueError:
        _silent_remove(tmp)
        abort(415, f"The file content does not match the .{ext} format. Make sure it is not damaged or renamed.")
    except (ClientDisconnected, OSError):
        _silent_remove(tmp)
        abort(400, "The upload was interrupted. Please try again.")
    elapsed = time.perf_counter() - t0

    meta = {"name": name, "desc": desc, "ext": ext, "category": cat_key, "size": n, "sha256": sha.hexdigest(),
            "uploaded": now(), "enc_seconds": round(elapsed, 3)}
    db = get_db()
    db.execute("INSERT INTO files(id, user_id, fek, meta, blob_name) VALUES(?,?,?,?,?)",
               (fid, g.uid, wrap(g.umk, fek, ctx_fek(g.uid, fid)),
                seal(g.umk, json.dumps(meta).encode(), ctx_meta(g.uid, fid)), blob))
    db.commit()
    log_activity(g.uid, "file_uploaded")
    flash(f"Your file was encrypted and saved to {cat['title']}.", "ok")
    return jsonify(ok=True, id=fid, url=url_for("vault.folder", category=cat_key))


def _silent_remove(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


@bp.get("/files/<fid>/content")
@login_required
def content(fid):
    row = own_file(fid)
    m = file_meta(row)
    key = file_key(row)
    size = m["size"]
    download = request.args.get("download") == "1" or m["ext"] not in INLINE

    start, stop, status = 0, size, 200
    headers = {"Accept-Ranges": "bytes"}
    if request.range and not download:
        r = request.range.range_for_length(size)
        if r is None:
            return Response(status=416, headers={"Content-Range": f"bytes */{size}"})
        start, stop = r
        status = 206
        headers["Content-Range"] = f"bytes {start}-{stop - 1}/{size}"
    headers["Content-Length"] = str(stop - start)
    if download:
        ascii_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in m["name"])
        headers["Content-Disposition"] = (f'attachment; filename="{ascii_name}"; '
                                          f"filename*=UTF-8''{quote(m['name'])}")
        log_activity(g.uid, "file_downloaded")

    try:
        rd = BlobReader(blob_path(row["blob_name"]), key, ctx_blob(g.uid, row["id"], row["blob_name"]))
        try:
            rd.chunk(start // rd.chunk_size)
        except IntegrityError:
            rd.close()
            raise
    except (IntegrityError, FileNotFoundError):
        log_activity(g.uid, "integrity_failed")
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


@bp.post("/files/<fid>/verify")
@login_required
def verify(fid):
    row = own_file(fid)
    m = file_meta(row)
    t0 = time.perf_counter()
    sha = hashlib.sha256()
    try:
        with BlobReader(blob_path(row["blob_name"]), file_key(row),
                        ctx_blob(g.uid, row["id"], row["blob_name"])) as rd:
            for i in range(rd.n_chunks):
                sha.update(rd.chunk(i))
            n_chunks = rd.n_chunks
    except (IntegrityError, FileNotFoundError) as e:
        log_activity(g.uid, "integrity_failed")
        return jsonify(ok=False, error=f"File is not intact: {e}. It was rejected and not sent."), 409
    ok = sha.hexdigest() == m["sha256"]
    log_activity(g.uid, "integrity_checked")
    return jsonify(ok=ok, sha256=sha.hexdigest(), expected=m["sha256"], chunks=n_chunks,
                   seconds=round(time.perf_counter() - t0, 3))


@bp.post("/files/<fid>/delete")
@login_required
def delete(fid):
    row = own_file(fid)
    category = file_meta(row)["category"]
    db = get_db()
    db.execute("DELETE FROM files WHERE id=? AND user_id=?", (fid, g.uid))
    db.commit()
    _silent_remove(blob_path(row["blob_name"]))
    log_activity(g.uid, "file_deleted")
    flash("The file was deleted and its key destroyed. Copies in older backups are not affected.", "ok")
    return redirect(url_for("vault.folder", category=category))
