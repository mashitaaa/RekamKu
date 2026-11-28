from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptography
import pypdf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pypdf.annotations import FreeText

from app.crypto.cms import sign_detached
from app.crypto.pdfsign import sign_pdf, verify_pdf
from app.crypto.rsasig import PrivateKey, sign_digest, verify_digest
from app.crypto.x509 import build_self_signed
from app.views.signing import describe
from tests.test_app import Client, make_app

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
OUT = os.path.join(HERE, "results")
QUICK = "--quick" in sys.argv
PW = {"siti": "morning-coffee-on-the-porch-2026", "dr_budi": "blue-bicycle-to-the-market!"}


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


class Signer:
    def __init__(self, cn, bits=3072):
        self.lib = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.key = PrivateKey.from_library(self.lib)
        self.cert = build_self_signed(self.key, cn)
        self.fpr = hashlib.sha256(self.cert).hexdigest().upper()

    def sign(self, data, name="siti"):
        return sign_pdf(data, lambda d: sign_detached(d, self.cert, self.key), signer=name, reason="bench")


def tool_out(args, data):
    if shutil.which(args[0]) is None:
        return "tool not installed"
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "f.pdf")
        with open(p, "wb") as fh:
            fh.write(data)
        r = subprocess.run(args + [p], capture_output=True, text=True)
        return r.stdout + r.stderr


def pdfsig_summary(data):
    out = tool_out(["pdfsig"], data)
    if out == "tool not installed":
        return out
    bits = []
    for line in out.splitlines():
        line = line.strip(" -")
        if line.startswith(("Signature Validation", "Total document", "Not total")):
            bits.append(line.replace("Signature Validation: ", ""))
    return "; ".join(bits) or "no signature reported"


def e10_cost(siti: Signer, lab: bytes):
    rows = []
    reps = 3 if QUICK else 20
    rows.append(("RSA-3072 key pair + self-signed certificate (once per user)",
                 *summary(ms(lambda: Signer("x"), max(3, reps // 2)))))
    d = hashlib.sha256(b"x").digest()
    rows.append(("Our RSA-3072 PKCS#1 v1.5 signature (CRT + blinding)",
                 *summary(ms(lambda: sign_digest(siti.key, d), reps * 5))))
    rows.append(("Library RSA-3072 signature, for comparison",
                 *summary(ms(lambda: siti.lib.sign(b"x", padding.PKCS1v15(), hashes.SHA256()), reps * 5))))
    sig = sign_digest(siti.key, d)
    rows.append(("Our RSA signature verification", *summary(ms(lambda: verify_digest(siti.key.public, d, sig), reps * 5))))
    small = pypdf.PdfWriter()
    small.add_blank_page(width=595, height=842)
    buf = io.BytesIO()
    small.write(buf)
    for label, data in (("1-page PDF", buf.getvalue()), ("lab result PDF, 1.8 MB", lab)):
        signed = siti.sign(data)
        rows.append((f"Sign in memory, {label}", *summary(ms(lambda: siti.sign(data), reps))))
        rows.append((f"Verify in memory, {label}", *summary(ms(lambda: verify_pdf(signed), reps))))
        rows.append((f"Bytes added by the signature, {label}", len(signed) - len(data), len(signed) - len(data),
                     len(signed) - len(data), 1))
    return rows


def app_cost(lab: bytes):
    app, d = make_app(RSA_BITS=3072)
    try:
        c = Client(app)
        c.register("siti", PW["siti"])
        rows, first = [], None
        sign_t, verify_t = [], []
        for i in range(3 if QUICK else 10):
            fid = c.upload("documents", f"lab{i}.pdf", lab).get_json()["id"]
            t = time.perf_counter()
            c.post(f"/files/{fid}/sign")
            sign_t.append((time.perf_counter() - t) * 1000)
            t = time.perf_counter()
            c.c.post(f"/files/{fid}/signature", headers={"X-CSRF-Token": c.csrf("/dashboard")}).get_json()
            verify_t.append((time.perf_counter() - t) * 1000)
            if first is None:
                first = sign_t.pop()
        first = round(first, 2)
        rows.append(("App: first signature incl. key generation, lab PDF", first, first, first, 1))
        rows.append(("App: sign (decrypt, sign, re-encrypt, update shares), lab PDF", *summary(sign_t)))
        rows.append(("App: verify (decrypt + verify), lab PDF", *summary(verify_t)))
        return rows
    finally:
        shutil.rmtree(d, ignore_errors=True)


def e11_attacks(siti: Signer, lab: bytes):
    res = []
    signed = siti.sign(lab)

    def add(name, attacker, expected, data, ok_fn, extra=""):
        r = describe(data, siti.fpr)
        observed = r["status"]
        if r["signatures"]:
            s = r["signatures"][-1]
            observed += f", owner key: {s['owner_key']}"
        if extra:
            observed += f"; {extra}"
        res.append((name, attacker, expected, observed, pdfsig_summary(data),
                    "as expected" if ok_fn(r) else "NOT as expected"))

    add("Untouched signed PDF", "-", "valid, owner key", signed,
        lambda r: r["status"] == "valid" and r["signatures"][0]["owner_key"])

    a, b, c, d = verify_pdf(signed)[0].byte_range
    pos = lab.index(b"stream", len(lab) // 2) + 40
    bad = bytearray(signed)
    bad[pos] ^= 0x01
    add("One bit flipped inside a page content stream", "can edit the file", "invalid", bytes(bad),
        lambda r: r["status"] == "invalid")

    w = pypdf.PdfWriter(io.BytesIO(signed), incremental=True)
    w.add_annotation(page_number=0, annotation=FreeText(text="Fasting glucose: 95 mg/dL (normal)",
                                                        rect=(60, 600, 330, 630), font_size="12pt",
                                                        border_color="ffffff", background_color="ffffff"))
    buf = io.BytesIO()
    w.write(buf)
    add("New content added as an incremental update after signing", "can edit the file",
        "signature still valid, change reported", buf.getvalue(), lambda r: r["status"] == "modified")

    mallory = Signer("siti")
    w = pypdf.PdfWriter(io.BytesIO(lab), incremental=True)
    w.add_annotation(page_number=0, annotation=FreeText(text="No abnormal findings", rect=(60, 600, 330, 630)))
    buf = io.BytesIO()
    w.write(buf)
    forged = mallory.sign(buf.getvalue())
    add("Document changed and re-signed with a new key whose certificate also says CN=siti",
        "own key pair, copies the name", "valid but NOT the owner's key", forged,
        lambda r: r["status"] == "valid" and not r["signatures"][-1]["owner_key"])

    stripped = signed[:len(lab)]
    add("Signature removed by cutting the last revision off", "can edit the file", "reported as unsigned",
        stripped, lambda r: r["status"] == "unsigned")

    other = siti.sign(lab + b"\n% another copy\n")
    m1 = re.search(rb"/Contents <([0-9A-F]+)", signed)
    m2 = re.search(rb"/Contents <([0-9A-F]+)", other)
    transplanted = signed[:m1.start(1)] + m2.group(1)[:len(m1.group(1))].ljust(len(m1.group(1)), b"0") + \
        signed[m1.end(1):]
    add("Signature value copied from another signed document", "has another signed PDF", "invalid",
        transplanted, lambda r: r["status"] == "invalid")

    m = re.search(rb"/ByteRange \[([^\]]*)\]", signed)
    a, b, c, d = (int(x) for x in m.group(1).split())
    edited = signed[:m.start(1)] + f"0 {b} {c} {d - 200}".encode().ljust(len(m.group(1))) + signed[m.end(1):]
    add("ByteRange edited so the last 200 bytes are no longer covered", "can edit the file", "invalid", edited,
        lambda r: r["status"] == "invalid")

    hex_end = signed.index(b">", b)
    wrapped = signed[:hex_end - 40] + b"> (hidden) <" + signed[hex_end - 28:]
    add("Extra bytes hidden inside the unsigned signature gap", "can edit the file", "invalid", wrapped,
        lambda r: r["status"] == "invalid")

    twice = siti.sign(signed)
    add("Signed twice by the owner (second revision)", "-", "both valid, latest covers the file", twice,
        lambda r: r["status"] == "valid" and len(r["signatures"]) == 2)

    app, d = make_app(RSA_BITS=3072)
    try:
        cs, cb = Client(app), Client(app)
        cs.register("siti", PW["siti"])
        cb.register("dr_budi", PW["dr_budi"])
        fid = cs.upload("documents", "lab.pdf", lab).get_json()["id"]
        st = cb.post(f"/files/{fid}/sign").status_code
        res.append(("Another user tries to sign the patient's PDF", "signed-in user, knows the file ID", "HTTP 404",
                    f"HTTP {st}", "-", "as expected" if st == 404 else "NOT as expected"))
        cs.post(f"/files/{fid}/sign")
        raw = open(app.config["DB_PATH"], "rb").read()
        con = sqlite3.connect(app.config["DB_PATH"])
        priv = con.execute("SELECT sig_priv FROM users WHERE sig_priv IS NOT NULL").fetchone()[0]
        con.close()
        leaks = [x.decode() for x in (b"siti", b"Patient signing key") if x in raw]
        ok = priv[:4] == b"RKU1" and not leaks
        res.append(("Database file stolen after signing", "copy of rekamku.db",
                    "private key and certificate encrypted", f"sig_priv starts with {priv[:4]!r}; plaintext found: "
                    f"{leaks or 'none'}", "-", "as expected" if ok else "NOT as expected"))
        w = pypdf.PdfWriter()
        w.add_blank_page(width=200, height=200)
        w.encrypt("secret")
        buf = io.BytesIO()
        w.write(buf)
        fid2 = cs.upload("documents", "locked.pdf", buf.getvalue()).get_json()["id"]
        cs.post(f"/files/{fid2}/sign")
        msg = "could not be signed" in cs.c.get(f"/files/{fid2}").get_data(as_text=True)
        res.append(("Password-protected PDF", "-", "refused, file unchanged", "refused" if msg else "signed", "-",
                    "as expected" if msg else "NOT as expected"))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return res


def main():
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(SAMPLES, "lab_result.pdf"), "rb") as fh:
        lab = fh.read()
    siti = Signer("siti")
    cost = e10_cost(siti, lab) + app_cost(lab)
    attacks = e11_attacks(siti, lab)
    with open(os.path.join(OUT, "e10_sign_cost.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["operation", "median_ms_or_bytes", "q1", "q3", "n"])
        w.writerows(cost)
    with open(os.path.join(OUT, "e11_sign_attacks.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "attacker", "expected", "rekamku", "poppler_pdfsig", "result"])
        w.writerows(attacks)
    env = {"cpu": platform.processor() or platform.machine(), "cores": os.cpu_count(),
           "python": platform.python_version(), "os": platform.platform(), "cryptography": cryptography.__version__,
           "pypdf": pypdf.__version__, "date": time.strftime("%Y-%m-%d %H:%M"), "quick": QUICK}
    with open(os.path.join(OUT, "environment_sign.json"), "w") as fh:
        json.dump(env, fh, indent=2)
    for r in cost:
        print(f"{r[0]:70} {r[1]:>10}")
    for r in attacks:
        print(f"[{r[5]}] {r[0]} -> {r[3]} | pdfsig: {r[4]}")


if __name__ == "__main__":
    main()
