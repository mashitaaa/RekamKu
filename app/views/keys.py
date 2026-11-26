from __future__ import annotations

from flask import Blueprint, g, render_template

from ..db import get_db
from ..keyring import own_key_status
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
    return render_template("keys/index.html", fpr=fpr, intact=intact, shares=shares)
