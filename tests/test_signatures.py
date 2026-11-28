import hashlib
import io
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

import pypdf
from cryptography import x509 as lib_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.crypto import der
from app.crypto.cms import sign_detached, verify_detached
from app.crypto.pdfsign import PDFError, sign_pdf, verify_pdf
from app.crypto.rsasig import PrivateKey, sign_digest, verify_digest
from app.crypto.x509 import build_self_signed, parse_certificate

from .test_app import PW_A, PW_B, AppTestBase, Client, make_app

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(os.path.dirname(HERE), "bench", "samples", "lab_result.pdf")


def tool(name):
    return shutil.which(name) is not None


def blank_pdf(pages=2, text=b"") -> bytes:
    w = pypdf.PdfWriter()
    for _ in range(pages):
        w.add_blank_page(width=595, height=842)
    if text:
        w.add_metadata({"/Subject": text.decode()})
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


class Identity:
    def __init__(self, cn="siti", bits=2048):
        self.lib = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.key = PrivateKey.from_library(self.lib)
        self.cert = build_self_signed(self.key, cn)

    def sign(self, data: bytes, **kw) -> bytes:
        return sign_pdf(data, lambda d: sign_detached(d, self.cert, self.key), signer="siti", reason="test", **kw)


class DerEncoding(unittest.TestCase):
    def test_integers_and_oids_round_trip(self):
        for v in (0, 1, 127, 128, 255, 256, 2 ** 64, 2 ** 3071 + 12345):
            self.assertEqual(der.parse_exact(der.integer(v)).int(), v)
        self.assertEqual(der.integer(128).hex(), "02020080")
        for o in ("1.2.840.113549.1.7.2", "2.5.4.3", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.9.16.2.47"):
            self.assertEqual(der.parse_exact(der.oid(o)).oid(), o)
        self.assertEqual(der.oid("1.2.840.113549.1.1.11").hex(), "06092a864886f70d01010b")

    def test_malformed_input_is_rejected(self):
        for bad in (b"\x30", b"\x30\x05\x02\x01", b"\x30\x81\x05\x02\x01\x01\x02\x01", b"\x02\x84\xff\xff\xff\xff"):
            with self.assertRaises(der.DERError):
                der.parse_exact(bad)
        with self.assertRaises(der.DERError):
            der.parse_exact(der.integer(5) + b"\x00")


class RsaSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.id = Identity()

    def test_matches_the_standard(self):
        msg = b"Fasting glucose: 95 mg/dL"
        ours = sign_digest(self.id.key, hashlib.sha256(msg).digest())
        self.assertEqual(ours, self.id.lib.sign(msg, padding.PKCS1v15(), hashes.SHA256()))
        self.id.lib.public_key().verify(ours, msg, padding.PKCS1v15(), hashes.SHA256())

    def test_verification_rejects_changes(self):
        d = hashlib.sha256(b"a").digest()
        s = sign_digest(self.id.key, d)
        pub = self.id.key.public
        self.assertTrue(verify_digest(pub, d, s))
        self.assertFalse(verify_digest(pub, hashlib.sha256(b"b").digest(), s))
        self.assertFalse(verify_digest(pub, d, s[:-1] + bytes([s[-1] ^ 1])))
        self.assertFalse(verify_digest(pub, d, s[1:]))
        self.assertFalse(verify_digest(Identity().key.public, d, s))

    def test_certificate_is_standard(self):
        cert = lib_x509.load_der_x509_certificate(self.id.cert)
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(cert.subject.get_attributes_for_oid(lib_x509.NameOID.COMMON_NAME)[0].value, "siti")
        ku = cert.extensions.get_extension_for_class(lib_x509.KeyUsage)
        self.assertTrue(ku.critical and ku.value.digital_signature and ku.value.content_commitment)
        ours = parse_certificate(self.id.cert)
        self.assertTrue(ours.self_signed_ok())
        self.assertEqual(ours.key.n, self.id.key.n)


class CmsSignedData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.id = Identity()

    def test_round_trip_and_tampering(self):
        data = b"discharge summary"
        cms = sign_detached(hashlib.sha256(data).digest(), self.id.cert, self.id.key)
        ok = verify_detached(cms, [data])
        self.assertTrue(ok.valid)
        self.assertEqual(ok.certificate.common_name, "siti")
        self.assertFalse(verify_detached(cms, [data + b"!"]).valid)
        i = cms.index(hashlib.sha256(data).digest())
        bad = cms[:i] + bytes([cms[i] ^ 1]) + cms[i + 1:]
        self.assertFalse(verify_detached(bad, [data]).valid)

    @unittest.skipUnless(tool("openssl"), "openssl not installed")
    def test_openssl_accepts_it(self):
        data = b"referral letter"
        cms = sign_detached(hashlib.sha256(data).digest(), self.id.cert, self.id.key)
        with tempfile.TemporaryDirectory() as d:
            paths = {n: os.path.join(d, n) for n in ("s.p7", "d.bin", "c.der", "c.pem")}
            for n, v in (("s.p7", cms), ("d.bin", data), ("c.der", self.id.cert)):
                with open(paths[n], "wb") as fh:
                    fh.write(v)
            subprocess.run(["openssl", "x509", "-inform", "der", "-in", paths["c.der"], "-out", paths["c.pem"]],
                           check=True, capture_output=True)
            r = subprocess.run(["openssl", "cms", "-verify", "-inform", "der", "-in", paths["s.p7"], "-content",
                                paths["d.bin"], "-binary", "-CAfile", paths["c.pem"], "-purpose", "any"],
                               capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)


class PdfSigning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.id = Identity()
        with open(SAMPLE, "rb") as fh:
            cls.pdf = fh.read()
        cls.signed = cls.id.sign(cls.pdf)

    def test_signature_is_embedded_and_valid(self):
        self.assertTrue(self.signed.startswith(self.pdf))
        [s] = verify_pdf(self.signed)
        self.assertTrue(s.valid and s.covers_whole_file)
        self.assertEqual(s.signer, "siti")
        self.assertEqual(s.fingerprint, hashlib.sha256(self.id.cert).hexdigest().upper())
        reader = pypdf.PdfReader(io.BytesIO(self.signed))
        self.assertEqual(len(reader.pages), len(pypdf.PdfReader(io.BytesIO(self.pdf)).pages))
        self.assertEqual(reader.trailer["/Root"]["/AcroForm"]["/SigFlags"], 3)
        self.assertEqual(verify_pdf(self.pdf), [])

    def test_any_changed_byte_breaks_it(self):
        a, b, c, d = verify_pdf(self.signed)[0].byte_range
        for pos in (100, b - 50, c + 10, len(self.signed) - 20, b + 200):
            bad = bytearray(self.signed)
            bad[pos] = ord("A") if bad[pos] != ord("A") else ord("B")
            [s] = verify_pdf(bytes(bad))
            self.assertFalse(s.valid, pos)

    def test_content_added_after_signing_is_reported(self):
        extra = b"\n99 0 obj\n(changed after signing)\nendobj\n"
        [s] = verify_pdf(self.signed + extra)
        self.assertTrue(s.valid)
        self.assertFalse(s.covers_whole_file)

    def test_edited_byte_range_is_rejected(self):
        m = re.search(rb"/ByteRange \[([^\]]*)\]", self.signed)
        a, b, c, d = (int(x) for x in m.group(1).split())
        moved = f"0 {b} {c} {d - 10}".encode().ljust(len(m.group(1)))
        bad = self.signed[:m.start(1)] + moved + self.signed[m.end(1):]
        self.assertEqual(len(bad), len(self.signed))
        self.assertFalse(verify_pdf(bad)[0].valid)

    def test_bytes_hidden_in_the_gap_are_rejected(self):
        # Extra bytes inside the unsigned gap are covered by neither the hash nor the RSA signature,
        # so only the "gap must be exactly the hex string" rule can notice them.
        a, b, c, d = verify_pdf(self.signed)[0].byte_range
        end = self.signed.index(b">", b)
        bad = self.signed[:end - 40] + b"> (hidden) <" + self.signed[end - 28:]
        self.assertEqual(len(bad), len(self.signed))
        self.assertFalse(verify_pdf(bad)[0].valid)

    def test_second_signature(self):
        twice = self.id.sign(self.signed)
        first, second = verify_pdf(twice)
        self.assertTrue(first.valid and not first.covers_whole_file)
        self.assertTrue(second.valid and second.covers_whole_file)

    def test_encrypted_pdf_is_refused(self):
        w = pypdf.PdfWriter()
        w.add_blank_page(width=200, height=200)
        w.encrypt("secret")
        buf = io.BytesIO()
        w.write(buf)
        with self.assertRaises(PDFError):
            self.id.sign(buf.getvalue())

    @unittest.skipUnless(tool("qpdf"), "qpdf not installed")
    def test_xref_stream_pdf(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "a.pdf"), os.path.join(d, "b.pdf")
            with open(src, "wb") as fh:
                fh.write(blank_pdf(3))
            subprocess.run(["qpdf", "--object-streams=generate", src, dst], check=True)
            with open(dst, "rb") as fh:
                data = fh.read()
        signed = self.id.sign(self.id.sign(data))
        self.assertTrue(all(s.valid for s in verify_pdf(signed)))
        self.assertEqual(len(pypdf.PdfReader(io.BytesIO(signed)).pages), 3)

    @unittest.skipUnless(tool("pdfsig") and tool("qpdf"), "poppler pdfsig or qpdf not installed")
    def test_third_party_readers_accept_it(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "signed.pdf")
            with open(path, "wb") as fh:
                fh.write(self.signed)
            out = subprocess.run(["pdfsig", path], capture_output=True, text=True).stdout
            self.assertIn("Signature is Valid", out)
            self.assertIn("Total document signed", out)
            self.assertIn("adbe.pkcs7.detached", out)
            check = subprocess.run(["qpdf", "--check", path], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)


class SigningInTheApp(AppTestBase):
    def setUp(self):
        self.app, self.dir = make_app(SIGN_RSA_BITS=2048)
        self.addCleanup(shutil.rmtree, self.dir)
        self.a = Client(self.app)
        self.a.register("siti_a", PW_A)
        self.pdf = blank_pdf(2)
        self.fid = self.a.upload("documents", "consent.pdf", self.pdf).get_json()["id"]

    def db(self):
        con = sqlite3.connect(self.app.config["DB_PATH"])
        con.row_factory = sqlite3.Row
        self.addCleanup(con.close)
        return con

    def sign(self, fid=None):
        return self.a.post(f"/files/{fid or self.fid}/sign")

    def check(self, client=None, path=None):
        client = client or self.a
        r = client.c.post(path or f"/files/{self.fid}/signature", headers={"X-CSRF-Token": client.csrf("/dashboard")})
        return r.get_json()

    def download(self):
        return self.a.c.get(f"/files/{self.fid}/content?download=1").get_data()

    def test_key_pair_is_generated_on_first_signature(self):
        self.assertIsNone(self.db().execute("SELECT sig_cert FROM users").fetchone()[0])
        self.assertIn("Generate signing key pair", self.a.c.get("/keys").get_data(as_text=True))
        self.sign()
        row = self.db().execute("SELECT sig_priv, sig_cert, sig_fpr FROM users").fetchone()
        self.assertEqual(row["sig_priv"][:4], b"RKU1")
        self.assertEqual(row["sig_cert"][:4], b"RKU1")
        self.assertEqual(len(row["sig_fpr"]), 32)
        html = self.a.c.get("/account").get_data(as_text=True)
        self.assertIn("Signing key pair and certificate created", html)
        self.assertIn("A PDF was signed with your private key", html)

    def test_signed_file_is_stored_verified_and_downloadable(self):
        self.sign()
        data = self.download()
        self.assertTrue(data.startswith(self.pdf))
        [s] = verify_pdf(data)
        self.assertTrue(s.valid and s.covers_whole_file)
        self.assertEqual(s.signer, "siti_a")
        res = self.check()
        self.assertEqual(res["status"], "valid")
        self.assertTrue(res["signatures"][0]["owner_key"])
        integrity = self.a.c.post(f"/files/{self.fid}/verify",
                                  headers={"X-CSRF-Token": self.a.csrf("/dashboard")}).get_json()
        self.assertTrue(integrity["ok"])
        cert = self.a.c.get("/keys/signing.cer")
        self.assertEqual(hashlib.sha256(cert.get_data()).hexdigest().upper(), s.fingerprint)
        self.assertEqual(len(os.listdir(self.app.config["STORAGE_DIR"])), 1)

    def test_unsigned_and_foreign_signatures(self):
        self.assertEqual(self.check()["status"], "unsigned")
        foreign = Identity("dr_fake").sign(blank_pdf(1))
        fid = self.a.upload("documents", "from-lab.pdf", foreign).get_json()["id"]
        res = self.check(path=f"/files/{fid}/signature")
        self.assertEqual(res["status"], "valid")
        self.assertFalse(res["signatures"][0]["owner_key"])
        self.assertEqual(res["signatures"][0]["signer"], "dr_fake")

    def test_signing_twice_and_other_files(self):
        self.sign()
        r = self.sign()
        self.assertEqual(len(verify_pdf(self.download())), 1)
        jpg = self.a.upload("identity", "ktp.jpg", b"\xff\xd8\xff\xe0" + os.urandom(5000)).get_json()["id"]
        self.sign(jpg)
        self.assertIn("Only PDF documents can be signed", self.a.c.get("/dashboard").get_data(as_text=True))
        self.assertEqual(r.status_code, 302)

    def test_other_users_cannot_sign_or_verify(self):
        b = Client(self.app)
        b.register("dr_budi", PW_B)
        self.assertEqual(b.post(f"/files/{self.fid}/sign").status_code, 404)
        r = b.c.post(f"/files/{self.fid}/signature", headers={"X-CSRF-Token": b.csrf("/dashboard")})
        self.assertEqual(r.status_code, 404)

    def test_requester_verifies_a_shared_signed_pdf(self):
        b = Client(self.app)
        b.register("dr_budi", PW_B)
        b.post("/shared/request", username="siti_a", reason="Check the signed consent", wants=["documents"])
        sid = self.db().execute("SELECT id FROM shares").fetchone()[0]
        html = self.a.post(f"/sharing/{sid}/approve", files=[self.fid], days="7").get_data(as_text=True)
        token = re.search(r'id="token">(RKS1\.[^<]+)<', html).group(1)
        b.post("/shared/redeem", token=token)
        self.sign()
        got = b.c.get(f"/shared/{sid}/files/{self.fid}/content?download=1").get_data()
        self.assertEqual(got, self.download())
        res = self.check(b, f"/shared/{sid}/files/{self.fid}/signature")
        self.assertEqual(res["status"], "valid")
        self.assertTrue(res["signatures"][0]["owner_key"])

    def test_generate_key_from_keys_page_and_no_plaintext(self):
        self.a.post("/keys/signing")
        self.assertIn("Download certificate", self.a.c.get("/keys").get_data(as_text=True))
        with open(self.app.config["DB_PATH"], "rb") as fh:
            raw = fh.read()
        for leak in (b"siti_a", b"RekamKu", b"Patient signing key"):
            self.assertNotIn(leak, raw)


if __name__ == "__main__":
    unittest.main()
