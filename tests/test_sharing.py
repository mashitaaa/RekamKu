import os
import re
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from app.crypto.asym import TokenError, decrypt_share_key, encrypt_share_key, new_rsa_keypair, new_share_key, parse_token
from app.views import sharing

from .test_app import JPG, MP4, PDF, PW_A, PW_B, AppTestBase, Client

PW_C = "green-tea-before-the-exam-77"
REASON = "Neurology follow-up on 20 November"


class ShareKeyToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_b, cls.pub_b = new_rsa_keypair(2048)
        cls.priv_c, cls.pub_c = new_rsa_keypair(2048)

    def test_round_trip(self):
        sid, k = os.urandom(16).hex(), new_share_key()
        token = encrypt_share_key(self.pub_b, sid, k)
        self.assertTrue(token.startswith("RKS1." + sid + "."))
        got_sid, ct = parse_token(token)
        self.assertEqual(got_sid, sid)
        self.assertEqual(len(ct), 256)
        self.assertEqual(decrypt_share_key(self.priv_b, sid, ct), k)

    def test_oaep_is_randomised(self):
        sid, k = os.urandom(16).hex(), new_share_key()
        self.assertNotEqual(encrypt_share_key(self.pub_b, sid, k), encrypt_share_key(self.pub_b, sid, k))

    def test_other_private_key_cannot_open(self):
        sid = os.urandom(16).hex()
        _, ct = parse_token(encrypt_share_key(self.pub_b, sid, new_share_key()))
        with self.assertRaises(TokenError):
            decrypt_share_key(self.priv_c, sid, ct)

    def test_token_bound_to_its_share(self):
        sid, other = os.urandom(16).hex(), os.urandom(16).hex()
        _, ct = parse_token(encrypt_share_key(self.pub_b, sid, new_share_key()))
        with self.assertRaises(TokenError):
            decrypt_share_key(self.priv_b, other, ct)

    def test_tampered_or_garbage_token(self):
        sid = os.urandom(16).hex()
        token = encrypt_share_key(self.pub_b, sid, new_share_key())
        flipped = token[:-6] + ("A" if token[-6] != "A" else "B") + token[-5:]
        _, ct = parse_token(flipped)
        with self.assertRaises(TokenError):
            decrypt_share_key(self.priv_b, sid, ct)
        for bad in ("", "hello", "RKS1.xyz.abc", "RKS2." + sid + ".AAAA"):
            with self.assertRaises(TokenError):
                parse_token(bad)

    def test_whitespace_from_chat_apps_is_ignored(self):
        sid, k = os.urandom(16).hex(), new_share_key()
        token = encrypt_share_key(self.pub_b, sid, k)
        wrapped = "\n".join(token[i:i + 60] for i in range(0, len(token), 60))
        self.assertEqual(decrypt_share_key(self.priv_b, *parse_token(wrapped)), k)


class SharingBase(AppTestBase):
    def setUp(self):
        super().setUp()
        self.a.post("/profile", name="Siti Rahmawati", conditions="Temporal lobe epilepsy")
        self.pdf = self.a.upload("documents", "lab-result.pdf", PDF).get_json()["id"]
        self.jpg = self.a.upload("identity", "ktp.jpg", JPG).get_json()["id"]
        self.mp4 = self.a.upload("videos", "seizure.mp4", MP4).get_json()["id"]
        self.b = Client(self.app)
        self.b.register("dr_budi", PW_B)

    def db(self):
        con = sqlite3.connect(self.app.config["DB_PATH"])
        con.row_factory = sqlite3.Row
        self.addCleanup(con.close)
        return con

    def request(self, client=None, to="siti_a", wants=("profile", "documents", "videos")):
        client = client or self.b
        return client.post("/shared/request", username=to, reason=REASON, wants=list(wants))

    def last_share(self):
        return self.db().execute("SELECT * FROM shares ORDER BY rowid DESC").fetchone()

    def approve(self, sid, files, profile=True, days=7):
        data = {"files": files, "days": str(days)}
        if profile:
            data["profile"] = "1"
        r = self.a.post(f"/sharing/{sid}/approve", **data)
        self.assertEqual(r.status_code, 200)
        return re.search(r'id="token">(RKS1\.[^<]+)<', r.get_data(as_text=True)).group(1)

    def redeem(self, token, client=None):
        return (client or self.b).post("/shared/redeem", token=token)

    def active_share(self, files=None):
        self.request()
        sid = self.last_share()["id"]
        token = self.approve(sid, files if files is not None else [self.pdf, self.mp4])
        self.redeem(token)
        return sid, token


class RequestFlow(SharingBase):
    def test_owner_sees_request_with_requester_and_reason(self):
        self.request()
        row = self.last_share()
        self.assertEqual(row["status"], "pending")
        html = self.a.c.get("/sharing").get_data(as_text=True)
        self.assertIn("dr_budi", html)
        self.assertIn(REASON, html)
        self.assertIn('class="count count--alert">1<', self.a.c.get("/dashboard").get_data(as_text=True))

    def test_bad_requests_are_refused(self):
        self.request(to="nobody_here")
        self.request(client=self.a, to="siti_a")
        self.b.post("/shared/request", username="siti_a", reason="x", wants=["profile"])
        self.b.post("/shared/request", username="siti_a", reason=REASON)
        self.assertIsNone(self.last_share())
        self.request()
        self.request()
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM shares").fetchone()[0], 1)

    def test_only_the_owner_can_review_or_approve(self):
        self.request()
        sid = self.last_share()["id"]
        self.assertEqual(self.b.c.get(f"/sharing/{sid}/review").status_code, 404)
        self.assertEqual(self.b.post(f"/sharing/{sid}/approve", files=[self.pdf], days="7").status_code, 404)
        self.assertEqual(self.last_share()["status"], "pending")

    def test_cannot_share_files_of_someone_else(self):
        c = Client(self.app)
        c.register("eve_c", PW_C)
        other = c.upload("documents", "eve.pdf", PDF).get_json()["id"]
        self.request()
        sid = self.last_share()["id"]
        self.approve(sid, [other, self.pdf], profile=False)
        files = [r[0] for r in self.db().execute("SELECT file_id FROM shared_files WHERE share_id=?", (sid,))]
        self.assertEqual(files, [self.pdf])

    def test_decline(self):
        self.request()
        sid = self.last_share()["id"]
        self.a.post(f"/sharing/{sid}/decline")
        self.assertEqual(self.last_share()["status"], "declined")
        self.assertIn("Declined", self.b.c.get("/shared").get_data(as_text=True))


class KeyDistribution(SharingBase):
    def test_full_flow(self):
        self.request()
        sid = self.last_share()["id"]
        token = self.approve(sid, [self.pdf, self.mp4])
        row = self.last_share()
        self.assertEqual(row["status"], "approved")
        self.assertIsNotNone(row["key_owner"])
        self.assertIsNone(row["key_requester"])
        self.assertEqual(self.b.c.get(f"/shared/{sid}").status_code, 404)

        r = self.redeem(token)
        self.assertEqual(r.status_code, 302)
        row = self.last_share()
        self.assertEqual(row["status"], "active")
        self.assertEqual(row["key_requester"][:4], b"RKU1")

        html = self.b.c.get(f"/shared/{sid}").get_data(as_text=True)
        for text in ("Siti Rahmawati", "Temporal lobe epilepsy", "lab-result.pdf", "seizure.mp4"):
            self.assertIn(text, html)
        self.assertNotIn("ktp.jpg", html)
        got = self.b.c.get(f"/shared/{sid}/files/{self.pdf}/content?download=1").data
        self.assertEqual(got, PDF)
        part = self.b.c.get(f"/shared/{sid}/files/{self.mp4}/content", headers={"Range": "bytes=2000000-2000099"})
        self.assertEqual(part.status_code, 206)
        self.assertEqual(part.data, MP4[2000000:2000100])

    def test_unshared_file_not_reachable_through_share(self):
        sid, _ = self.active_share()
        for path in (f"/shared/{sid}/files/{self.jpg}", f"/shared/{sid}/files/{self.jpg}/content"):
            self.assertEqual(self.b.c.get(path).status_code, 404)
        self.assertEqual(self.b.c.get(f"/files/{self.pdf}").status_code, 404)

    def test_token_useless_to_another_user(self):
        self.request()
        sid = self.last_share()["id"]
        token = self.approve(sid, [self.pdf])
        c = Client(self.app)
        c.register("eve_c", PW_C)
        self.redeem(token, client=c)
        self.assertEqual(self.last_share()["status"], "approved")
        self.assertEqual(c.c.get(f"/shared/{sid}").status_code, 404)

    def test_tampered_token_rejected(self):
        self.request()
        sid = self.last_share()["id"]
        token = self.approve(sid, [self.pdf])
        bad = token[:-10] + ("A" if token[-10] != "A" else "B") + token[-9:]
        html = self.b.post("/shared/redeem", token=bad).headers["Location"]
        self.assertEqual(self.last_share()["status"], "approved")
        self.redeem(token)
        self.assertEqual(self.last_share()["status"], "active")

    def test_owner_can_show_key_again_until_redeemed(self):
        self.request()
        sid = self.last_share()["id"]
        self.approve(sid, [self.pdf])
        html = self.a.c.get(f"/sharing/{sid}/key").get_data(as_text=True)
        token2 = re.search(r'id="token">(RKS1\.[^<]+)<', html).group(1)
        self.redeem(token2)
        self.assertEqual(self.last_share()["status"], "active")
        self.assertEqual(self.a.c.get(f"/sharing/{sid}/key").status_code, 302)


class RevocationAndExpiry(SharingBase):
    def test_revoke_deletes_keys_and_access(self):
        sid, token = self.active_share()
        self.a.post(f"/sharing/{sid}/revoke")
        row = self.last_share()
        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["key_owner"])
        self.assertIsNone(row["key_requester"])
        self.assertIsNone(row["grant_info"])
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM shared_files").fetchone()[0], 0)
        self.assertEqual(self.b.c.get(f"/shared/{sid}").status_code, 404)
        self.assertEqual(self.b.c.get(f"/shared/{sid}/files/{self.pdf}/content").status_code, 404)
        self.redeem(token)
        self.assertEqual(self.last_share()["status"], "revoked")

    def test_expired_share_closes_itself(self):
        sid, _ = self.active_share()
        later = datetime.now(timezone.utc) + timedelta(days=8)
        with mock.patch.object(sharing, "utcnow", return_value=later):
            self.assertEqual(self.b.c.get(f"/shared/{sid}").status_code, 410)
        row = self.last_share()
        self.assertEqual(row["status"], "expired")
        self.assertIsNone(row["key_requester"])

    def test_requester_can_withdraw(self):
        sid, _ = self.active_share()
        self.b.post(f"/shared/{sid}/withdraw")
        self.assertEqual(self.last_share()["status"], "withdrawn")
        self.assertEqual(self.b.c.get(f"/shared/{sid}").status_code, 404)

    def test_deleting_a_file_removes_it_from_shares(self):
        sid, _ = self.active_share()
        self.a.post(f"/files/{self.pdf}/delete")
        self.assertEqual(self.b.c.get(f"/shared/{sid}/files/{self.pdf}/content").status_code, 404)
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM shared_files").fetchone()[0], 1)

    def test_owner_log_shows_requester_activity(self):
        sid, _ = self.active_share()
        self.b.c.get(f"/shared/{sid}/files/{self.pdf}")
        html = self.a.c.get("/account").get_data(as_text=True)
        self.assertIn("A shared file was opened by the requester", html)
        self.assertIn("Your share key was added by the requester", html)


class SharedDataStaysEncrypted(SharingBase):
    def test_new_columns_hold_no_plaintext(self):
        self.active_share()
        readable = {"shares": {"id", "owner_id", "requester_id", "status"},
                    "shared_files": {"share_id", "file_id"},
                    "users": {"id", "username_idx", "kdf", "pw_salt", "rc_salt", "log_pub", "enc_pub"}}
        con = self.db()
        for table, ok in readable.items():
            cols = [c[1] for c in con.execute(f"PRAGMA table_info({table})")]
            for row in con.execute(f"SELECT * FROM {table}"):
                for col, val in zip(cols, row):
                    if col in ok or val is None:
                        continue
                    blob = val[32:] if (table, col) == ("shares", "request") else val
                    self.assertEqual(blob[:4], b"RKU1", f"{table}.{col} is not encrypted")
        with open(self.app.config["DB_PATH"], "rb") as fh:
            raw = fh.read()
        for leak in (b"dr_budi", b"siti_a", REASON.encode(), b"lab-result", b"Rahmawati", b"BEGIN PRIVATE", b"RKS1."):
            self.assertNotIn(leak, raw, leak)

    def test_private_keys_are_encrypted_with_the_account_key(self):
        con = self.db()
        for row in con.execute("SELECT enc_pub, enc_priv FROM users"):
            self.assertEqual(row["enc_pub"][:1], b"\x30")
            self.assertEqual(row["enc_priv"][:4], b"RKU1")


class ExistingAccountsGetKeys(AppTestBase):
    def test_key_pair_created_at_next_sign_in(self):
        con = sqlite3.connect(self.app.config["DB_PATH"])
        con.execute("UPDATE users SET enc_pub=NULL, enc_priv=NULL")
        con.commit()
        self.a.logout()
        self.a.login("siti_a", PW_A)
        self.assertIsNotNone(con.execute("SELECT enc_pub FROM users").fetchone()[0])
        con.close()


class SwappedPublicKey(SharingBase):
    def test_requester_fingerprint_comes_from_the_private_key(self):
        fpr_before = re.search(r'class="hash">([0-9A-F ]+)<', self.b.c.get("/shared").get_data(as_text=True)).group(1)
        _, evil_pub = new_rsa_keypair(2048)
        con = self.db()
        con.execute("UPDATE users SET enc_pub=? WHERE rowid=2", (evil_pub,))
        con.commit()
        self.request()
        sid = self.last_share()["id"]
        owner_view = self.a.c.get(f"/sharing/{sid}/review").get_data(as_text=True)
        mine = self.b.c.get("/shared").get_data(as_text=True)
        self.assertEqual(re.search(r'class="hash">([0-9A-F ]+)<', mine).group(1), fpr_before)
        self.assertIn("does not match your private key", mine)
        self.assertNotIn(fpr_before, owner_view)
        self.assertIn("Mismatch", self.b.c.get("/keys").get_data(as_text=True))
        self.assertNotIn("does not match your private key", self.a.c.get("/shared").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
