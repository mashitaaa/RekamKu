from __future__ import annotations

from flask import Blueprint, g, render_template

from ..db import get_db
from ..crypto.x509 import fingerprint_groups, parse_certificate
from ..keyring import own_key_status, signing_identity
from ..security import login_required

bp = Blueprint("keys", __name__)


@bp.get("/keys")
@login_required
def index():
    db = get_db()
    shares = {
        "given": db.execute("SELECT COUNT(*) FROM shares WHERE owner_id=? AND status IN ('approved','active')",
                            (g.uid,)).fetchone()[0],
        "held": db.execute("SELECT COUNT(*) FROM shares WHERE requester_id=? AND status='active'",
                           (g.uid,)).fetchone()[0],
    }
    fpr, intact = own_key_status(g.uid, g.umk)
    ident = signing_identity(g.uid, g.umk)
    cert = None
    if ident is not None:
        c = parse_certificate(ident[1])
        cert = {"subject": ", ".join(f"{k}={v}" for k, v in c.subject.items()), "not_before": c.not_before,
                "not_after": c.not_after, "fingerprint": fingerprint_groups(c.fingerprint, 16),
                "bits": c.key.n.bit_length()}
    return render_template("keys/index.html", fpr=fpr, intact=intact, shares=shares, cert=cert)
