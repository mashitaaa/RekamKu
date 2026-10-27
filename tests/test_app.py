import hashlib
import os
import re
import shutil
import sqlite3
import tempfile
import time
import unittest

from app import create_app
from app.crypto.keys import KdfParams

PW_A, PW_B = "morning-coffee-on-the-porch-2026", "blue-bicycle-to-the-market!"

JPG = b"\xff\xd8\xff\xe0" + os.urandom(300_000)
PDF = b"%PDF-1.7\n" + os.urandom(1_500_000)
DOCX = b"PK\x03\x04" + os.urandom(60_000)
XLSX = b"PK\x03\x04" + os.urandom(40_000)
MP4 = b"\x00\x00\x00\x20ftypisom" + os.urandom(3 * 1024 * 1024 + 12345)


def make_app(**extra):
    d = tempfile.mkdtemp()
    cfg = {"INSTANCE_DIR": d, "DB_PATH": os.path.join(d, "t.db"), "STORAGE_DIR": os.path.join(d, "storage"),
           "SERVER_KEY_PATH": os.path.join(d, "server.key"), "KDF": KdfParams(n=2 ** 12, r=8, p=1)}
    cfg.update(extra)
    return create_app(cfg), d


class Client:
    def __init__(self, app):
        self.c = app.test_client()

    def csrf(self, path="/login"):
        html = self.c.get(path).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def register(self, user, pw):
        tok = self.csrf("/register")
        r = self.c.post("/register", data={"csrf": tok, "username": user, "password": pw, "password2": pw,
                                           "consent": "1"})
        code = re.search(r'id="rcode">([A-Z2-9-]+)<', r.get_data(as_text=True))
        return r, code.group(1) if code else None

    def login(self, user, pw):
        return self.c.post("/login", data={"csrf": self.csrf(), "username": user, "password": pw})

    def logout(self):
        return self.c.post("/logout", data={"csrf": self.csrf("/dashboard")})

    def upload(self, cat, name, data, csrf=True):
        headers = {"X-Filename": name, "Content-Type": "application/octet-stream"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf("/dashboard")
        return self.c.post(f"/files/upload?category={cat}", data=data, headers=headers)

    def post(self, path, **data):
        data["csrf"] = self.csrf("/dashboard")
        return self.c.post(path, data=data)

    def verify(self, fid):
        return self.c.post(f"/files/{fid}/verify", headers={"X-CSRF-Token": self.csrf("/dashboard")})


class AppTestBase(unittest.TestCase):
    def setUp(self):
        self.app, self.dir = make_app()
        self.addCleanup(shutil.rmtree, self.dir)
        self.a = Client(self.app)
        r, self.code_a = self.a.register("siti_a", PW_A)
        self.assertEqual(r.status_code, 200)

    def ids(self, client):
        html = "".join(client.c.get(f"/vault/{c}").get_data(as_text=True) for c in ("identity", "documents", "videos"))
        return re.findall(r'href="/files/([0-9a-f]{32})"', html)


class Authentication(AppTestBase):
    def test_register_shows_recovery_code_and_signs_in(self):
        self.assertRegex(self.code_a, r"^([A-Z2-9]{4}-){4}[A-Z2-9]{4}$")
        self.assertEqual(self.a.c.get("/dashboard").status_code, 200)

    def test_pages_require_login(self):
        anon = Client(self.app)
        for path in ("/dashboard", "/vault/documents", "/profile", "/account", "/files/" + "0" * 32,
                     "/files/" + "0" * 32 + "/content"):
            r = anon.c.get(path)
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/login", r.headers["Location"])

    def test_wrong_password_and_unknown_user_look_the_same(self):
        self.a.logout()
        r1 = self.a.login("siti_a", "wrong-wrong-wrong")
        r2 = self.a.login("nobody_here", "wrong-wrong-wrong")
        self.assertEqual((r1.status_code, r2.status_code), (401, 401))
        self.assertIn("Incorrect username or password", r1.get_data(as_text=True))
        self.assertIn("Incorrect username or password", r2.get_data(as_text=True))

    def test_lockout_after_five_failures(self):
        self.a.logout()
        for _ in range(5):
            self.a.login("siti_a", "wrong-wrong-wrong")
        self.assertEqual(self.a.login("siti_a", PW_A).status_code, 429)

    def test_logout_destroys_key(self):
        self.a.logout()
        self.assertEqual(self.a.c.get("/dashboard").status_code, 302)

    def test_idle_timeout(self):
        app, d = make_app(IDLE_TIMEOUT=1)
        self.addCleanup(shutil.rmtree, d)
        c = Client(app)
        c.register("budi", PW_B)
        self.assertEqual(c.c.get("/dashboard").status_code, 200)
        time.sleep(1.2)
        self.assertEqual(c.c.get("/dashboard").status_code, 302)

    def test_csrf_required(self):
        self.assertEqual(self.a.c.post("/logout").status_code, 400)
        self.assertEqual(self.a.upload("identity", "ktp.jpg", JPG, csrf=False).status_code, 400)

    def test_security_headers(self):
        h = self.a.c.get("/dashboard").headers
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_no_inline_styles_or_scripts(self):
        self.a.upload("identity", "ktp.jpg", JPG)
        for path in ("/", "/dashboard", "/vault/identity", "/profile", "/account", "/privacy"):
            html = self.a.c.get(path).get_data(as_text=True)
            self.assertNotRegex(html, r'\sstyle="', path)
            self.assertNotIn("<script>", html, path)


class FileRoundTrip(AppTestBase):
    def test_all_data_types_come_back_intact(self):
        samples = [("identity", "ktp.jpg", JPG), ("documents", "lab-result.pdf", PDF),
                   ("documents", "summary.docx", DOCX), ("documents", "bp-log.xlsx", XLSX),
                   ("videos", "seizure.mp4", MP4)]
        for cat, name, data in samples:
            r = self.a.upload(cat, name, data)
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            fid = r.get_json()["id"]
            got = self.a.c.get(f"/files/{fid}/content?download=1")
            self.assertEqual(got.status_code, 200)
            self.assertEqual(hashlib.sha256(got.data).hexdigest(), hashlib.sha256(data).hexdigest(), name)
            self.assertIn("attachment", got.headers["Content-Disposition"])
            self.assertTrue(self.a.verify(fid).get_json()["ok"])
        for path in ("/dashboard", "/vault/identity", "/vault/documents", "/vault/videos"):
            self.assertEqual(self.a.c.get(path).status_code, 200)

    def test_video_range_requests(self):
        fid = self.a.upload("videos", "seizure.mp4", MP4).get_json()["id"]
        for a, b in [(0, 99), (1048570, 1048600), (len(MP4) - 10, len(MP4) - 1)]:
            r = self.a.c.get(f"/files/{fid}/content", headers={"Range": f"bytes={a}-{b}"})
            self.assertEqual(r.status_code, 206)
            self.assertEqual(r.data, MP4[a:b + 1])
            self.assertEqual(r.headers["Content-Range"], f"bytes {a}-{b}/{len(MP4)}")
        r = self.a.c.get(f"/files/{fid}/content", headers={"Range": f"bytes={len(MP4) + 5}-"})
        self.assertEqual(r.status_code, 416)

    def test_type_and_size_validation(self):
        self.assertEqual(self.a.upload("identity", "ktp.exe", b"MZ" + bytes(100)).status_code, 415)
        self.assertEqual(self.a.upload("identity", "ktp.jpg", b"<html>" + bytes(100)).status_code, 415)
        self.assertEqual(self.a.upload("documents", "x.pdf", b"PK\x03\x04" + bytes(10)).status_code, 415)
        self.assertEqual(self.a.upload("identity", "big.jpg", b"\xff\xd8\xff" + bytes(10 * 1024 * 1024)).status_code,
                         413)
        self.assertEqual(self.a.upload("other", "ktp.jpg", JPG).status_code, 400)
        leftovers = [f for f in os.listdir(self.app.config["STORAGE_DIR"]) if f.startswith(".part-")]
        self.assertEqual(leftovers, [])

    def test_filename_path_traversal_neutralised(self):
        fid = self.a.upload("documents", "..%2F..%2Fetc%2Fpasswd.pdf", PDF).get_json()["id"]
        html = self.a.c.get(f"/files/{fid}").get_data(as_text=True)
        self.assertIn("passwd.pdf", html)
        self.assertNotIn("../", html)


class AccessControl(AppTestBase):
    def setUp(self):
        super().setUp()
        self.fid = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        self.b = Client(self.app)
        self.b.register("budi_b", PW_B)

    def test_other_user_cannot_access_by_id(self):
        tok = self.b.csrf("/dashboard")
        attempts = [self.b.c.get(f"/files/{self.fid}"),
                    self.b.c.get(f"/files/{self.fid}/content"),
                    self.b.c.get(f"/files/{self.fid}/content?download=1"),
                    self.b.c.post(f"/files/{self.fid}/verify", headers={"X-CSRF-Token": tok}),
                    self.b.c.post(f"/files/{self.fid}/delete", data={"csrf": tok})]
        for r in attempts:
            self.assertEqual(r.status_code, 404)
        self.assertEqual(self.a.c.get(f"/files/{self.fid}/content?download=1").data, PDF)

    def test_b_does_not_see_a_files(self):
        self.assertEqual(self.ids(self.b), [])

    def test_blob_swapped_on_disk_is_rejected(self):
        fid_b = self.b.upload("documents", "b-file.pdf", b"%PDF-1.4\n" + os.urandom(5000)).get_json()["id"]
        con = sqlite3.connect(self.app.config["DB_PATH"])
        blob_a = con.execute("SELECT blob_name FROM files WHERE id=?", (self.fid,)).fetchone()[0]
        blob_b = con.execute("SELECT blob_name FROM files WHERE id=?", (fid_b,)).fetchone()[0]
        con.close()
        st = self.app.config["STORAGE_DIR"]
        shutil.copy(os.path.join(st, blob_b), os.path.join(st, blob_a))
        self.assertEqual(self.a.verify(self.fid).status_code, 409)
        self.assertEqual(self.a.c.get(f"/files/{self.fid}/content?download=1").status_code, 409)


class Tampering(AppTestBase):
    def _blob(self, fid):
        con = sqlite3.connect(self.app.config["DB_PATH"])
        name = con.execute("SELECT blob_name FROM files WHERE id=?", (fid,)).fetchone()[0]
        con.close()
        return os.path.join(self.app.config["STORAGE_DIR"], name)

    def _flip(self, path, offset):
        with open(path, "r+b") as fh:
            fh.seek(offset)
            b = fh.read(1)
            fh.seek(offset)
            fh.write(bytes([b[0] ^ 1]))

    def test_single_bit_flip_in_content_detected(self):
        fid = self.a.upload("videos", "seizure.mp4", MP4).get_json()["id"]
        self._flip(self._blob(fid), 32 + (1 << 20) + 32 + 500)
        self.assertEqual(self.a.verify(fid).status_code, 409)
        with self.assertRaises(Exception):
            self.a.c.get(f"/files/{fid}/content?download=1").data

    def test_header_flip_rejected_before_sending(self):
        fid = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        self._flip(self._blob(fid), 10)
        self.assertEqual(self.a.c.get(f"/files/{fid}/content?download=1").status_code, 409)

    def test_truncated_blob_rejected(self):
        fid = self.a.upload("videos", "seizure.mp4", MP4).get_json()["id"]
        path = self._blob(fid)
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.truncate(size - (size - 32) % ((1 << 20) + 32))
        self.assertEqual(self.a.verify(fid).status_code, 409)


class NothingInPlaintext(AppTestBase):
    def test_database_and_storage_hold_no_plaintext(self):
        nik, name = "3578012304990007", "Siti Rahmawati"
        self.a.post("/profile", name=name, nik=nik, conditions="Temporal lobe epilepsy", blood_type="O+")
        marker = b"PATIENT-SECRET-" * 100
        self.a.upload("documents", "epilepsy-siti.pdf", b"%PDF-1.7\n" + marker)
        blobs = b""
        for root, _, files in os.walk(self.dir):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    blobs += fh.read()
        for secret in (nik.encode(), name.encode(), b"epilepsy", b"PATIENT-SECRET", b"epilepsy-siti", b"siti_a",
                       PW_A.encode(), self.code_a.encode()):
            self.assertNotIn(secret, blobs, secret)


class EverythingStoredIsEncrypted(AppTestBase):
    READABLE = {"users": {"id", "username_idx", "kdf", "pw_salt", "rc_salt", "log_pub"},
                "files": {"id", "user_id", "blob_name"},
                "activity": {"id", "user_id"}}

    def setUp(self):
        super().setUp()
        self.a.post("/profile", name="Siti Rahmawati", conditions="Temporal lobe epilepsy")
        self.fid = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        self.a.logout()
        self.a.login("siti_a", "wrong-wrong-wrong")
        self.a.login("siti_a", PW_A)

    def test_every_other_column_is_a_cascade_object(self):
        con = sqlite3.connect(self.app.config["DB_PATH"])
        for table, readable in self.READABLE.items():
            cols = [c[1] for c in con.execute(f"PRAGMA table_info({table})")]
            for row in con.execute(f"SELECT * FROM {table}"):
                for col, val in zip(cols, row):
                    if col in readable or val is None:
                        continue
                    blob = val[32:] if table == "activity" else val
                    self.assertEqual(blob[:4], b"RKU1", f"{table}.{col} is not encrypted")
        con.close()

    def test_no_metadata_in_clear(self):
        with open(self.app.config["DB_PATH"], "rb") as fh:
            raw = fh.read()
        today = time.strftime("%Y-%m-%d", time.gmtime()).encode()
        for leak in (b"login_failed", b"file_uploaded", b"account_created", b'"documents"', b"lab-result",
                     today, b"siti_a"):
            self.assertNotIn(leak, raw, leak)

    def test_owner_can_read_failed_sign_in_from_encrypted_log(self):
        html = self.a.c.get("/account").get_data(as_text=True)
        self.assertIn("Failed sign-in attempt", html)
        self.assertIn("1 failed sign-in", self.a.c.get("/dashboard").get_data(as_text=True))

    def test_file_name_not_in_session_cookie(self):
        self.a.upload("documents", "secret-diagnosis.pdf", PDF)
        cookie = self.a.c.get_cookie("rk_session").value
        data = self.app.session_interface.get_signing_serializer(self.app).loads(cookie)
        self.assertNotIn("secret-diagnosis", str(data))


class DataSubjectRights(AppTestBase):
    def test_profile_roundtrip_and_validation(self):
        r = self.a.post("/profile", name="Siti", nik="123")
        self.assertIn("NIK must be exactly 16 digits", r.get_data(as_text=True))
        self.a.post("/profile", name="Siti Rahmawati", nik="3578012304990007", blood_type="O+")
        self.assertIn("3578012304990007", self.a.c.get("/profile").get_data(as_text=True))
        self.assertIn("Hello, Siti", self.a.c.get("/dashboard").get_data(as_text=True))

    def test_change_password_keeps_files(self):
        fid = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        new = "sunrise-over-the-east-77"
        self.a.post("/account/password", current=PW_A, password=new, password2=new)
        self.a.logout()
        self.assertEqual(self.a.login("siti_a", PW_A).status_code, 401)
        self.assertEqual(self.a.login("siti_a", new).status_code, 302)
        self.assertEqual(self.a.c.get(f"/files/{fid}/content?download=1").data, PDF)

    def test_recovery_code_resets_password_and_is_single_use(self):
        fid = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        self.a.logout()
        new = "forgot-my-password-again-26"
        tok = self.a.csrf("/recover")
        r = self.a.c.post("/recover", data={"csrf": tok, "username": "siti_a", "code": self.code_a.lower(),
                                            "password": new, "password2": new})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.a.c.get(f"/files/{fid}/content?download=1").data, PDF)
        self.a.logout()
        tok = self.a.csrf("/recover")
        r = self.a.c.post("/recover", data={"csrf": tok, "username": "siti_a", "code": self.code_a,
                                            "password": new + "x", "password2": new + "x"})
        self.assertEqual(r.status_code, 401)

    def test_delete_file_removes_blob_and_key(self):
        fid = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        before = set(os.listdir(self.app.config["STORAGE_DIR"]))
        self.a.post(f"/files/{fid}/delete")
        self.assertEqual(len(before) - 1, len(os.listdir(self.app.config["STORAGE_DIR"])))
        con = sqlite3.connect(self.app.config["DB_PATH"])
        self.assertIsNone(con.execute("SELECT 1 FROM files WHERE id=?", (fid,)).fetchone())
        con.close()

    def test_delete_account_erases_everything(self):
        self.a.upload("documents", "lab-result.pdf", PDF)
        self.a.upload("videos", "seizure.mp4", MP4)
        r = self.a.post("/account/delete", current=PW_A, confirm="DELETE")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(os.listdir(self.app.config["STORAGE_DIR"]), [])
        con = sqlite3.connect(self.app.config["DB_PATH"])
        self.assertEqual(con.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM activity").fetchone()[0], 0)
        con.close()
        self.assertEqual(self.a.login("siti_a", PW_A).status_code, 401)


if __name__ == "__main__":
    unittest.main()
