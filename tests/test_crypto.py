import io
import os
import unittest
import warnings

from app.crypto import primitives as P
from app.crypto.cascade import (CHUNK_OVERHEAD, HEADER_LEN, BlobReader, IntegrityError, ciphertext_size,
                                encrypt_stream, seal, unseal)
from app.crypto.keys import KdfParams, ServerKeys, new_key, new_recovery_code, normalize_recovery_code, unwrap, wrap

SMALL = 10
CS = 1 << SMALL


def enc_bytes(key, data, ctx, log2=SMALL):
    out = io.BytesIO()
    encrypt_stream(key, ctx, io.BytesIO(data).read, out.write, chunk_log2=log2)
    return out.getvalue()


class KnownAnswerTests(unittest.TestCase):
    def test_des_fips81_cbc(self):
        key = bytes.fromhex("0123456789abcdef")
        iv = bytes.fromhex("1234567890abcdef")
        pt = b"Now is the time for all "
        ct = P.des_cbc_encrypt(key, iv, pt)
        self.assertEqual(ct[:24].hex(), "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6")
        self.assertEqual(P.des_cbc_decrypt(key, iv, ct), pt)

    def test_rc4_rfc6229(self):
        from cryptography.hazmat.primitives.ciphers import Cipher
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        ks = Cipher(ARC4(bytes.fromhex("0102030405")), None).encryptor().update(bytes(16))
        self.assertEqual(ks.hex(), "b2396305f03dc027ccc3524a0a1118a8")

    def test_rc4_drop_skips_3072_bytes(self):
        from cryptography.hazmat.primitives.ciphers import Cipher
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        k = os.urandom(16)
        raw = Cipher(ARC4(k), None).encryptor().update(bytes(P.RC4_DROP + 64))
        self.assertEqual(P.rc4_xor(k, bytes(64)), raw[P.RC4_DROP:])

    def test_aes256_gcm_nist_case14(self):
        ct = P.gcm_encrypt(bytes(32), bytes(12), bytes(16), b"")
        self.assertEqual(ct.hex(), "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919")


class CascadeRoundTrip(unittest.TestCase):
    def setUp(self):
        self.key = new_key()
        self.ctx = b"file|user-a|file-1"

    def test_roundtrip_boundaries(self):
        for n in (0, 1, 7, 8, 9, CS - 1, CS, CS + 1, 3 * CS, 3 * CS + 5):
            with self.subTest(size=n):
                data = os.urandom(n)
                blob = enc_bytes(self.key, data, self.ctx)
                self.assertEqual(len(blob), ciphertext_size(n, SMALL))
                self.assertEqual(unseal(self.key, blob, self.ctx), data)

    def test_seal_default_chunk(self):
        data = os.urandom(3 * (1 << 20) + 123)
        self.assertEqual(unseal(self.key, seal(self.key, data, self.ctx), self.ctx), data)

    def test_probabilistic(self):
        data = b"A" * 5000
        self.assertNotEqual(enc_bytes(self.key, data, self.ctx), enc_bytes(self.key, data, self.ctx))

    def test_no_plaintext_patterns(self):
        data = b"KTP-1234567890ABCDEF" * 500
        blob = enc_bytes(self.key, data, self.ctx)
        blocks = [blob[i:i + 16] for i in range(HEADER_LEN, len(blob) - 15, 16)]
        self.assertEqual(len(blocks), len(set(blocks)))
        self.assertNotIn(b"KTP-1234", blob)

    def test_range_reads(self):
        data = os.urandom(5 * CS + 77)
        path = os.path.join(self._tmp(), "blob")
        with open(path, "wb") as fh:
            fh.write(enc_bytes(self.key, data, self.ctx))
        with BlobReader(path, self.key, self.ctx) as r:
            self.assertEqual(r.n_chunks, 6)
            for a, b in [(0, 1), (0, CS), (CS - 3, CS + 3), (2 * CS + 10, 4 * CS), (5 * CS, len(data)),
                         (100, 10 ** 9)]:
                self.assertEqual(b"".join(r.iter_range(a, b)), data[a:b])
            self.assertEqual(r.read_all(), data)

    def _tmp(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        return d


class CascadeIntegrity(unittest.TestCase):
    def setUp(self):
        self.key = new_key()
        self.ctx = b"file|user-a|file-1"
        self.data = os.urandom(3 * CS + 100)
        self.blob = enc_bytes(self.key, self.data, self.ctx)

    def assertRejected(self, blob, key=None, ctx=None):
        with self.assertRaises((IntegrityError, ValueError)):
            unseal(key or self.key, blob, ctx or self.ctx)

    def test_bitflip_anywhere_is_detected(self):
        positions = [0, 5, 10, 31, HEADER_LEN, HEADER_LEN + 3, HEADER_LEN + 500,
                     HEADER_LEN + CS + CHUNK_OVERHEAD - 1, len(self.blob) - 1]
        for pos in positions:
            with self.subTest(pos=pos):
                b = bytearray(self.blob)
                b[pos] ^= 0x01
                self.assertRejected(bytes(b))

    def test_truncation_detected(self):
        ecs = CS + CHUNK_OVERHEAD
        self.assertRejected(self.blob[:HEADER_LEN + 2 * ecs])
        self.assertRejected(self.blob[:-1])
        self.assertRejected(self.blob[:HEADER_LEN])

    def test_reorder_detected(self):
        ecs = CS + CHUNK_OVERHEAD
        h, c = self.blob[:HEADER_LEN], self.blob[HEADER_LEN:]
        chunks = [c[i:i + ecs] for i in range(0, len(c), ecs)]
        chunks[0], chunks[1] = chunks[1], chunks[0]
        self.assertRejected(h + b"".join(chunks))

    def test_chunk_splice_between_files_detected(self):
        other = enc_bytes(self.key, os.urandom(len(self.data)), self.ctx)
        ecs = CS + CHUNK_OVERHEAD
        spliced = self.blob[:HEADER_LEN] + other[HEADER_LEN:HEADER_LEN + ecs] + self.blob[HEADER_LEN + ecs:]
        self.assertRejected(spliced)

    def test_wrong_context_detected(self):
        self.assertRejected(self.blob, ctx=b"file|user-b|file-1")

    def test_wrong_key_detected(self):
        self.assertRejected(self.blob, key=new_key())


class KeyManagement(unittest.TestCase):
    FAST = KdfParams(n=2 ** 12, r=8, p=1)

    def test_wrap_roundtrip_and_context_binding(self):
        kek, umk = new_key(), new_key()
        w = wrap(kek, umk, b"umk|abc")
        self.assertEqual(unwrap(kek, w, b"umk|abc"), umk)
        with self.assertRaises(IntegrityError):
            unwrap(kek, w, b"umk|other")

    def test_kek_depends_on_server_pepper(self):
        s1, s2 = ServerKeys(os.urandom(32)), ServerKeys(os.urandom(32))
        salt = os.urandom(16)
        self.assertNotEqual(s1.derive_kek("pw", salt, self.FAST, b"pw"), s2.derive_kek("pw", salt, self.FAST, b"pw"))
        self.assertEqual(s1.derive_kek("pw", salt, self.FAST, b"pw"), s1.derive_kek("pw", salt, self.FAST, b"pw"))

    def test_username_index_case_insensitive(self):
        s = ServerKeys(os.urandom(32))
        self.assertEqual(s.username_index("Siti_A"), s.username_index("siti_a "))

    def test_recovery_code(self):
        c = new_recovery_code()
        self.assertRegex(c, r"^([A-Z2-9]{4}-){4}[A-Z2-9]{4}$")
        self.assertEqual(normalize_recovery_code(c.lower().replace("-", " ")), c)

    def test_kdf_params_encoding(self):
        self.assertEqual(KdfParams.decode(self.FAST.encode()), self.FAST)


if __name__ == "__main__":
    unittest.main()
