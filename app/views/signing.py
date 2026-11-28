from __future__ import annotations

import hashlib
import io
import json
import os
import time
import uuid

from flask import Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, url_for

from ..crypto import BlobReader, IntegrityError, encrypt_stream, seal, unseal
from ..crypto.cms import sign_detached
from ..crypto.keys import unwrap
from ..crypto.pdfsign import PDFError, sign_pdf, verify_pdf
from ..crypto.rsasig import SignatureError
from ..crypto.x509 import fingerprint_groups
from ..db import get_db, log_activity, now
from ..keyring import create_signing_identity, signing_fingerprint, signing_identity, username_of
from ..security import login_required
from .sharing import _shared_file, c_key, c_meta, open_share, shared_meta
from .vault import _silent_remove, blob_path, ctx_blob, ctx_meta, file_key, own_file

bp = Blueprint("signing", __name__)


def read_plain(path: str, key: bytes, ctx: bytes) -> bytes:
    with BlobReader(path, key, ctx) as rd:
        return b"".join(rd.chunk(i) for i in range(rd.n_chunks))


def describe(data: bytes, owner_fpr: str | None) -> dict:
    sigs = verify_pdf(data)
    items = []
    for i, s in enumerate(sigs):
        later = any(t.valid for t in sigs[i + 1:])
        items.append({
            "valid": s.valid,
            "whole": s.covers_whole_file,
            "followed": not s.covers_whole_file and later,
            "signer": s.signer,
            "fingerprint": fingerprint_groups(s.fingerprint) if s.fingerprint else "",
            "owner_key": bool(owner_fpr) and s.fingerprint == owner_fpr,
            "time": s.signing_time.isoformat() if s.signing_time else "",
            "hash": s.hash_name.upper().replace("SHA", "SHA-"),
            "errors": s.errors,
        })
    if not items:
        status = "unsigned"
    elif not all(i["valid"] for i in items):
        status = "invalid"
    elif not items[-1]["whole"]:
        status = "modified"
    else:
        status = "valid"
    return {"status": status, "signatures": items}


def _refresh_shares(fid: str, meta: dict):
    db = get_db()
    rows = db.execute("SELECT s.id, s.key_owner FROM shares s JOIN shared_files sf ON sf.share_id = s.id "
                      "WHERE sf.file_id=? AND s.owner_id=? AND s.key_owner IS NOT NULL", (fid, g.uid)).fetchall()
    for r in rows:
        k = unwrap(g.umk, r["key_owner"], c_key(r["id"], "owner"))
        db.execute("UPDATE shared_files SET meta=? WHERE share_id=? AND file_id=?",
                   (seal(k, json.dumps(shared_meta(meta)).encode(), c_meta(r["id"], fid)), r["id"], fid))


@bp.post("/files/<fid>/sign")
@login_required
def sign(fid):
    row = own_file(fid)
    meta = json.loads(unseal(g.umk, row["meta"], ctx_meta(g.uid, fid)))
    back = redirect(url_for("vault.detail", fid=fid))
    if meta["ext"] != "pdf":
        flash("Only PDF documents can be signed.", "error")
        return back
    key = file_key(row)
    try:
        data = read_plain(blob_path(row["blob_name"]), key, ctx_blob(g.uid, fid, row["blob_name"]))
    except (IntegrityError, FileNotFoundError):
        log_activity(g.uid, "integrity_failed")
        abort(409, "This file is not intact, so it was not signed.")
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        abort(409, "This file does not match the fingerprint taken at upload, so it was not signed.")

    ident = signing_identity(g.uid, g.umk)
    created = ident is None
    if created:
        ident = create_signing_identity(g.uid, g.umk)
    priv, cert = ident
    cert_fpr = hashlib.sha256(cert).hexdigest().upper()
    if any(s.valid and s.fingerprint == cert_fpr and s.covers_whole_file for s in verify_pdf(data)):
        flash("You have already signed this version of the document.", "info")
        return back
    me = username_of(g.uid, g.umk)
    t0 = time.perf_counter()
    try:
        signed = sign_pdf(data, lambda digest: sign_detached(digest, cert, priv), signer=me,
                          reason=f"Signed by {me} with their RekamKu signing key")
    except (PDFError, SignatureError) as e:
        flash(f"This PDF could not be signed: {e}.", "error")
        return back
    elapsed = time.perf_counter() - t0

    blob = uuid.uuid4().hex
    final, tmp = blob_path(blob), blob_path(".part-" + blob)
    src = io.BytesIO(signed)
    with open(tmp, "wb") as out:
        encrypt_stream(key, ctx_blob(g.uid, fid, blob), src.read, out.write,
                       chunk_log2=current_app.config["CHUNK_LOG2"])
    os.replace(tmp, final)
    meta.setdefault("sha256_before_signing", meta["sha256"])
    meta.update(size=len(signed), sha256=hashlib.sha256(signed).hexdigest())
    meta.setdefault("signatures", []).append({"by": me, "at": now(), "fpr": cert_fpr, "seconds": round(elapsed, 3)})
    db = get_db()
    db.execute("UPDATE files SET meta=?, blob_name=? WHERE id=? AND user_id=?",
               (seal(g.umk, json.dumps(meta).encode(), ctx_meta(g.uid, fid)), blob, fid, g.uid))
    _refresh_shares(fid, meta)
    db.commit()
    _silent_remove(blob_path(row["blob_name"]))
    log_activity(g.uid, "file_signed")
    flash(("A signing key pair and certificate were generated for you. " if created else "") +
          "The PDF was signed with your private key. The signature is embedded in the file.", "ok")
    return back


def _answer(data: bytes, owner_fpr: str | None, uid: str):
    result = describe(data, owner_fpr)
    log_activity(uid, "signature_failed" if result["status"] in ("invalid", "modified") else "signature_checked")
    return jsonify(result)


@bp.post("/files/<fid>/signature")
@login_required
def verify(fid):
    row = own_file(fid)
    try:
        data = read_plain(blob_path(row["blob_name"]), file_key(row), ctx_blob(g.uid, fid, row["blob_name"]))
    except (IntegrityError, FileNotFoundError):
        log_activity(g.uid, "integrity_failed")
        return jsonify(status="error", error="The stored file is not intact."), 409
    return _answer(data, signing_fingerprint(g.uid), g.uid)


@bp.post("/shared/<sid>/files/<fid>/signature")
@login_required
def verify_shared(sid, fid):
    share, k, _ = open_share(sid)
    r, m, fek = _shared_file(sid, fid, k)
    try:
        data = read_plain(blob_path(r["blob_name"]), fek, ctx_blob(r["user_id"], fid, r["blob_name"]))
    except (IntegrityError, FileNotFoundError):
        return jsonify(status="error", error="The stored file is not intact."), 409
    return _answer(data, signing_fingerprint(share["owner_id"]), g.uid)


@bp.post("/keys/signing")
@login_required
def create_key():
    if signing_identity(g.uid, g.umk) is None:
        create_signing_identity(g.uid, g.umk)
        flash("Your signing key pair and certificate were created.", "ok")
    return redirect(url_for("keys.index"))


@bp.get("/keys/signing.cer")
@login_required
def certificate():
    ident = signing_identity(g.uid, g.umk)
    if ident is None:
        abort(404, "You do not have a signing key yet.")
    name = "".join(c if c.isalnum() or c in "._-" else "_" for c in username_of(g.uid, g.umk))
    return Response(ident[1], mimetype="application/pkix-cert",
                    headers={"Content-Disposition": f'attachment; filename="rekamku-{name}.cer"'})
