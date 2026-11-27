from __future__ import annotations

import csv
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import statistics
import sys
import time
from datetime import timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptography

from app.crypto.asym import decrypt_share_key, encrypt_share_key, new_rsa_keypair, new_share_key, parse_token
from app.crypto.cascade import encrypt_stream
from app.crypto.keys import unwrap
from app.views import sharing
from tests.test_app import Client, make_app

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
OUT = os.path.join(HERE, "results")
QUICK = "--quick" in sys.argv
PW = {"siti": "morning-coffee-on-the-porch-2026", "dr_budi": "blue-bicycle-to-the-market!",
      "mallory": "green-tea-before-the-exam-77"}
REASON = "Neurology follow-up, needs the seizure video and the latest lab result"
FILES = [("documents", "lab_result.pdf"), ("identity", "ktp_specimen.jpg"), ("videos", "symptom_video_3min.mp4")]


def ms(fn, reps):
    out = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return out


def summary(xs):
    q = statistics.quantiles(xs, n=4) if len(xs) > 1 else [xs[0]] * 3
    return round(statistics.median(xs), 2), round(q[0], 2), round(q[2], 2), len(xs)


class World:
    def __init__(self):
        self.app, self.dir = make_app(RSA_BITS=3072)
        self.c = {}
        for name in PW:
            self.c[name] = Client(self.app)
            self.c[name].register(name, PW[name])
        self.ids = {}
        for cat, fn in FILES:
            with open(os.path.join(SAMPLES, fn), "rb") as fh:
                data = fh.read()
            self.ids[fn] = self.c["siti"].upload(cat, fn, data).get_json()["id"]
            self.size = getattr(self, "size", {})
            self.size[fn] = len(data)
        self.c["siti"].post("/profile", name="Siti Rahmawati", conditions="Temporal lobe epilepsy")

    def db(self):
        con = sqlite3.connect(self.app.config["DB_PATH"])
        con.row_factory = sqlite3.Row
        return con

    def last_share(self):
        con = self.db()
        row = con.execute("SELECT * FROM shares ORDER BY rowid DESC").fetchone()
        con.close()
        return row

    def request(self, who="dr_budi", to="siti"):
        self.c[who].post("/shared/request", username=to, reason=REASON, wants=["profile", "documents", "videos"])
        return self.last_share()["id"]

    def approve(self, sid, files, days=7):
        r = self.c["siti"].post(f"/sharing/{sid}/approve", files=[self.ids[f] for f in files], profile="1",
                                days=str(days))
        m = re.search(r'id="token">(RKS1\.[^<]+)<', r.get_data(as_text=True))
        return m.group(1) if m else None

    def redeem(self, token, who="dr_budi"):
        self.c[who].post("/shared/redeem", token=token)
        return self.c[who].c.get("/shared").get_data(as_text=True)

    def revoke(self, sid):
        self.c["siti"].post(f"/sharing/{sid}/revoke")

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def e8_cost(w: World):
    rows = []
    reps = 3 if QUICK else 20
    rows.append(("RSA-3072 key pair generation (once per account)", *summary(ms(lambda: new_rsa_keypair(3072), reps))))
    priv, pub = new_rsa_keypair(3072)
    sid, k = os.urandom(16).hex(), new_share_key()
    tok = encrypt_share_key(pub, sid, k)
    rows.append(("Encrypt share key with RSA-OAEP", *summary(ms(lambda: encrypt_share_key(pub, sid, k), reps * 10))))
    ct = parse_token(tok)[1]
    rows.append(("Decrypt share key with RSA-OAEP", *summary(ms(lambda: decrypt_share_key(priv, sid, ct), reps * 10))))
    sets = {"lab PDF (1.8 MB)": ["lab_result.pdf"],
            "PDF + KTP + 3-min video (92 MB)": [f for _, f in FILES]}
    for label, files in sets.items():
        ap, rd, op = [], [], []
        for _ in range(3 if QUICK else 15):
            sid = w.request()
            t = time.perf_counter()
            token = w.approve(sid, files)
            ap.append((time.perf_counter() - t) * 1000)
            t = time.perf_counter()
            w.c["dr_budi"].post("/shared/redeem", token=token)
            rd.append((time.perf_counter() - t) * 1000)
            fid = w.ids[files[-1]]
            t = time.perf_counter()
            w.c["dr_budi"].c.get(f"/shared/{sid}/files/{fid}/content", headers={"Range": "bytes=0-1048575"}).get_data()
            op.append((time.perf_counter() - t) * 1000)
            w.revoke(sid)
        rows.append((f"Approve request, {label}", *summary(ap)))
        rows.append((f"Add share key (requester), {label}", *summary(rd)))
        rows.append((f"Requester opens first 1 MiB of shared file, {label}", *summary(op)))
        total = 0
        datas = []
        for f in files:
            with open(os.path.join(SAMPLES, f), "rb") as fh:
                datas.append(fh.read())

        def reencrypt():
            for d in datas:
                src, dst = io.BytesIO(d), io.BytesIO()
                encrypt_stream(os.urandom(32), b"bench", src.read, dst.write)
        rows.append((f"Baseline: re-encrypt the same files with the cascade, {label}",
                     *summary(ms(reencrypt, 2 if QUICK else 5))))
    rows.append(("Token length in characters", len(tok), len(tok), len(tok), 1))
    return rows


def e9_attacks(w: World):
    res = []

    def add(name, attacker, expected, observed, ok):
        res.append((name, attacker, expected, observed, "as expected" if ok else "NOT as expected"))

    sid = w.request()
    keys = []
    with mock.patch.object(sharing, "new_share_key", side_effect=lambda: keys.append(new_share_key()) or keys[-1]):
        token = w.approve(sid, ["lab_result.pdf", "symptom_video_3min.mp4"])
    k = keys[-1]

    html = w.redeem(token, "mallory")
    add("Token intercepted on WhatsApp and pasted by another user", "has the token, own account",
        "refused, nothing opened", "refused" if "does not belong to any of your requests" in html else "accepted",
        "does not belong to any of your requests" in html)

    _, ct = parse_token(token)
    m_priv, _ = new_rsa_keypair(3072)
    try:
        decrypt_share_key(m_priv, sid, ct)
        opened = True
    except Exception:
        opened = False
    add("Interceptor tries to decrypt the token offline", "token + any RSA private key except dr_budi's",
        "RSA-OAEP decryption fails", "decryption failed" if not opened else "share key recovered", not opened)

    flipped = token[:-6] + ("A" if token[-6] != "A" else "B") + token[-5:]
    html = w.redeem(flipped)
    add("Token changed by one character in transit", "can edit the message", "refused",
        "refused" if "changed on the way" in html else "accepted", "changed on the way" in html)

    other = w.request("dr_budi", "mallory")
    w.c["mallory"].post(f"/sharing/{other}/approve", days="7", profile="1")
    moved = token.replace(sid, other)
    html = w.redeem(moved)
    add("Token for one request used for another request", "requester with two shares", "refused",
        "refused" if "different request" in html else "accepted", "different request" in html)

    html = w.redeem(token)
    ok_redeem = "Key accepted" in html
    add("Correct requester adds the token", "dr_budi", "accepted", "accepted" if ok_redeem else "refused", ok_redeem)

    unshared = w.ids["ktp_specimen.jpg"]
    st = w.c["dr_budi"].c.get(f"/shared/{sid}/files/{unshared}").status_code
    add("Requester asks for a file the patient did not choose (KTP)", "dr_budi, edits the URL", "HTTP 404",
        f"HTTP {st}", st == 404)

    st1 = w.c["mallory"].c.get(f"/shared/{sid}").status_code
    st2 = w.c["mallory"].c.get(f"/sharing/{sid}/review").status_code
    add("Third user opens the share or the owner's review page", "mallory, knows the share ID", "no access",
        f"HTTP {st1} / {st2}", st1 in (302, 404) and st2 in (302, 404))

    con = w.db()
    raw = open(w.app.config["DB_PATH"], "rb").read()
    leaks = [x for x in (k, b"dr_budi", REASON.encode(), b"lab_result", b"Rahmawati", b"RKS1.") if x in raw]
    add("Database file stolen while the share is active", "full copy of rekamku.db", "no share key or plaintext",
        "found: " + (", ".join(str(x[:12]) for x in leaks) if leaks else "nothing"), not leaks)
    con.close()

    w.revoke(sid)
    st = w.c["dr_budi"].c.get(f"/shared/{sid}/files/{w.ids['lab_result.pdf']}/content").status_code
    con = w.db()
    row = con.execute("SELECT key_owner, key_requester, grant_info FROM shares WHERE id=?", (sid,)).fetchone()
    n = con.execute("SELECT COUNT(*) FROM shared_files WHERE share_id=?", (sid,)).fetchone()[0]
    con.close()
    gone = row["key_owner"] is None and row["key_requester"] is None and row["grant_info"] is None and n == 0
    add("Requester keeps using the share after the patient revokes it", "dr_budi", "no access, keys deleted",
        f"HTTP {st}, keys deleted: {gone}", st in (302, 404) and gone)

    html = w.redeem(token)
    add("Old token pasted again after revocation", "dr_budi", "refused",
        "refused" if "no longer open" in html or "does not belong" in html else "accepted",
        "no longer open" in html or "does not belong" in html)

    sid2 = w.request()
    w.redeem(w.approve(sid2, ["lab_result.pdf"], days=1))
    later = sharing.utcnow() + timedelta(days=1, minutes=1)
    with mock.patch.object(sharing, "utcnow", return_value=later):
        st = w.c["dr_budi"].c.get(f"/shared/{sid2}/files/{w.ids['lab_result.pdf']}/content").status_code
    con = w.db()
    row = con.execute("SELECT status, key_requester FROM shares WHERE id=?", (sid2,)).fetchone()
    con.close()
    add("Requester opens a share after it expired (1 day)", "dr_budi", "no access, keys deleted",
        f"HTTP {st}, status {row['status']}", st in (302, 404, 410) and row["key_requester"] is None)

    con = w.db()
    budi_pub = con.execute("SELECT enc_pub FROM users WHERE rowid=2").fetchone()[0]
    evil_priv, evil_pub = new_rsa_keypair(3072)
    con.execute("UPDATE users SET enc_pub=? WHERE rowid=2", (evil_pub,))
    con.commit()
    sid3 = w.request()
    review = w.c["siti"].c.get(f"/sharing/{sid3}/review").get_data(as_text=True)
    token3 = w.approve(sid3, ["lab_result.pdf"])
    s3, ct3 = parse_token(token3)
    k3 = decrypt_share_key(evil_priv, s3, ct3)
    fek_row = con.execute("SELECT fek, file_id FROM shared_files WHERE share_id=?", (sid3,)).fetchone()
    fek = unwrap(k3, fek_row["fek"], sharing.c_fek(sid3, fek_row["file_id"]))
    add("Server admin swaps dr_budi's public key in the database", "write access to the database",
        "attacker gets the share key", f"share key and file key recovered ({len(fek)}-byte FEK)", len(fek) == 32)
    owner_fpr = re.search(r'class="hash">([0-9A-F ]+)<', review).group(1)
    mine = w.c["dr_budi"].c.get("/shared").get_data(as_text=True)
    budi_fpr = re.search(r'class="hash">([0-9A-F ]+)<', mine).group(1)
    warned = "does not match your private key" in mine
    add("Same swap: fingerprints read out by phone", "same", "fingerprints differ, requester warned",
        f"differ: {owner_fpr != budi_fpr}, warning shown: {warned}", owner_fpr != budi_fpr and warned)
    con.execute("UPDATE users SET enc_pub=? WHERE rowid=2", (budi_pub,))
    con.commit()
    con.close()
    w.revoke(sid3)

    sid4 = w.request()
    w.redeem(w.approve(sid4, ["lab_result.pdf"]))
    copy = w.c["dr_budi"].c.get(f"/shared/{sid4}/files/{w.ids['lab_result.pdf']}/content?download=1").get_data()
    w.revoke(sid4)
    with open(os.path.join(SAMPLES, "lab_result.pdf"), "rb") as fh:
        same = fh.read() == copy
    add("Requester downloaded the file before revocation", "dr_budi", "copy stays with the requester",
        f"downloaded copy identical to original: {same}", same)

    w.c["mallory"].post("/shared/request", username="nobody_here", reason=REASON, wants=["documents"])
    html = w.c["mallory"].c.get("/shared?username=nobody_here").get_data(as_text=True)
    add("Guessing usernames with the request form", "any signed-in user", "tells whether a username exists",
        "reveals it" if "no RekamKu account" in html else "does not reveal", "no RekamKu account" in html)
    return res


def main():
    os.makedirs(OUT, exist_ok=True)
    w = World()
    try:
        cost = e8_cost(w)
        attacks = e9_attacks(w)
    finally:
        w.close()
    with open(os.path.join(OUT, "e8_share_cost.csv"), "w", newline="") as fh:
        cw = csv.writer(fh)
        cw.writerow(["operation", "median_ms", "q1_ms", "q3_ms", "n"])
        cw.writerows(cost)
    with open(os.path.join(OUT, "e9_share_attacks.csv"), "w", newline="") as fh:
        cw = csv.writer(fh)
        cw.writerow(["scenario", "attacker", "expected", "observed", "result"])
        cw.writerows(attacks)
    env = {"cpu": platform.processor() or platform.machine(), "cores": os.cpu_count(),
           "python": platform.python_version(), "os": platform.platform(), "cryptography": cryptography.__version__,
           "date": time.strftime("%Y-%m-%d %H:%M"), "quick": QUICK}
    with open(os.path.join(OUT, "environment_share.json"), "w") as fh:
        json.dump(env, fh, indent=2)
    for r in cost:
        print(f"{r[0]:70} {r[1]:>10}")
    for r in attacks:
        print(f"[{r[4]}] {r[0]} -> {r[3]}")


if __name__ == "__main__":
    main()
