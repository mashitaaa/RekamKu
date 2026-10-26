from __future__ import annotations

import csv
import gc
import hashlib
import io
import json
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.backends.openssl import backend as ossl
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto import primitives as P
from app.crypto.cascade import (HEADER_LEN, BlobReader, IntegrityError, ciphertext_size,
                                encrypt_stream, unseal)

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
OUT = os.path.join(HERE, "results")
CS = 1 << 20
QUICK = "--quick" in sys.argv

FILES = [
    ("bp_sugar_log.xlsx", "BP & sugar log (XLSX)"),
    ("discharge_summary.docx", "Discharge summary (DOCX)"),
    ("ktp_specimen.jpg", "KTP scan (JPG)"),
    ("lab_result.pdf", "Lab result (PDF)"),
    ("symptom_video_30s.mp4", "Video 30 s (MP4)"),
    ("symptom_video_3min.mp4", "Video 3 min (MP4)"),
]


def reps_for(size: int) -> int:
    if QUICK:
        return 3
    return 40 if size < 4 * CS else (12 if size < 32 * CS else 7)


def chunks(data: bytes):
    return [data[i:i + CS] for i in range(0, max(len(data), 1), CS)]


class Single:
    def __init__(self):
        self.k_aes, self.k_des, self.k_rc4 = os.urandom(32), os.urandom(8), os.urandom(32)
        self.aes = AESGCM(self.k_aes)

    def aes_enc(self, parts):
        return [self.aes.encrypt(i.to_bytes(12, "big"), p, b"") for i, p in enumerate(parts)]

    def aes_dec(self, cts):
        return [self.aes.decrypt(i.to_bytes(12, "big"), c, b"") for i, c in enumerate(cts)]

    def des_enc(self, parts):
        out = []
        for p in parts:
            iv = os.urandom(8)
            out.append(iv + P.des_cbc_encrypt(self.k_des, iv, p))
        return out

    def des_dec(self, cts):
        return [P.des_cbc_decrypt(self.k_des, c[:8], c[8:]) for c in cts]

    def rc4_enc(self, parts):
        return [P.rc4_xor(P.rc4_subkey(self.k_rc4, b"rc4", i), p) for i, p in enumerate(parts)]

    rc4_dec = rc4_enc


def cascade_enc(key, data):
    out = io.BytesIO()
    encrypt_stream(key, b"bench", io.BytesIO(data).read, out.write)
    return out.getvalue()


def cascade_dec(key, blob):
    return unseal(key, blob, b"bench")


def timed(fn, *args):
    t = time.perf_counter_ns()
    fn(*args)
    return (time.perf_counter_ns() - t) / 1e6


def summarize(xs):
    q = statistics.quantiles(xs, n=4) if len(xs) >= 4 else [min(xs), statistics.median(xs), max(xs)]
    return statistics.median(xs), q[0], q[2]


def e1_throughput(datasets):
    s = Single()
    ckey = os.urandom(32)
    rows, raw = [], []
    for fname, label, data in datasets:
        parts = chunks(data)
        pre = {"AES-256-GCM": s.aes_enc(parts), "DES-CBC": s.des_enc(parts), "RC4-drop3072": s.rc4_enc(parts),
               "Cascade": cascade_enc(ckey, data)}
        ops = {
            ("AES-256-GCM", "encrypt"): lambda: s.aes_enc(parts),
            ("AES-256-GCM", "decrypt"): lambda: s.aes_dec(pre["AES-256-GCM"]),
            ("DES-CBC", "encrypt"): lambda: s.des_enc(parts),
            ("DES-CBC", "decrypt"): lambda: s.des_dec(pre["DES-CBC"]),
            ("RC4-drop3072", "encrypt"): lambda: s.rc4_enc(parts),
            ("RC4-drop3072", "decrypt"): lambda: s.rc4_dec(pre["RC4-drop3072"]),
            ("Cascade", "encrypt"): lambda: cascade_enc(ckey, data),
            ("Cascade", "decrypt"): lambda: cascade_dec(ckey, pre["Cascade"]),
        }
        assert b"".join(s.aes_dec(pre["AES-256-GCM"])) == data
        assert b"".join(s.des_dec(pre["DES-CBC"])) == data
        assert b"".join(s.rc4_dec(pre["RC4-drop3072"])) == data
        assert cascade_dec(ckey, pre["Cascade"]) == data
        samples = {k: [] for k in ops}
        for k, fn in ops.items():
            for _ in range(2):
                fn()
        R = reps_for(len(data))
        gc.disable()
        try:
            for _ in range(R):
                order = list(ops)
                random.shuffle(order)
                for k in order:
                    samples[k].append(timed(ops[k]))
        finally:
            gc.enable()
        for (cipher, op), xs in samples.items():
            med, q1, q3 = summarize(xs)
            mb = len(data) / 1e6
            rows.append({"file": label, "size_MB": round(mb, 3), "cipher": cipher, "operation": op, "n": len(xs),
                         "median_ms": round(med, 3), "q1_ms": round(q1, 3), "q3_ms": round(q3, 3),
                         "MB_per_s": round(mb / (med / 1000), 1) if med > 0 else None})
            raw += [{"file": label, "cipher": cipher, "operation": op, "ms": round(x, 4)} for x in xs]
        print(f"  E1 {label:26} done ({R} repetitions)")
    return rows, raw


def e2_breakdown(data):
    from app.crypto.cascade import _derive
    k = _derive(os.urandom(32), os.urandom(24))
    parts = chunks(data)
    R = reps_for(len(data))
    res = {"encrypt": {"DES-CBC": [], "RC4-drop3072": [], "AES-256-GCM": []},
           "decrypt": {"DES-CBC": [], "RC4-drop3072": [], "AES-256-GCM": []}}
    for rep in range(R + 2):
        gc.disable()
        t_des = t_rc4 = t_aes = 0
        cts = []
        for i, p in enumerate(parts):
            t0 = time.perf_counter_ns(); iv = os.urandom(8); c1 = iv + P.des_cbc_encrypt(k.des, iv, p)
            t1 = time.perf_counter_ns(); c2 = P.rc4_xor(P.rc4_subkey(k.rc4, b"rc4", i), c1)
            t2 = time.perf_counter_ns(); c3 = k.aes.encrypt(i.to_bytes(12, "big"), c2, b"x" * 41)
            t3 = time.perf_counter_ns()
            t_des += t1 - t0; t_rc4 += t2 - t1; t_aes += t3 - t2
            cts.append(c3)
        d_des = d_rc4 = d_aes = 0
        for i, c in enumerate(cts):
            t0 = time.perf_counter_ns(); c2 = k.aes.decrypt(i.to_bytes(12, "big"), c, b"x" * 41)
            t1 = time.perf_counter_ns(); c1 = P.rc4_xor(P.rc4_subkey(k.rc4, b"rc4", i), c2)
            t2 = time.perf_counter_ns(); P.des_cbc_decrypt(k.des, c1[:8], c1[8:])
            t3 = time.perf_counter_ns()
            d_aes += t1 - t0; d_rc4 += t2 - t1; d_des += t3 - t2
        gc.enable()
        if rep < 2:
            continue
        for op, (a, b, c) in {"encrypt": (t_des, t_rc4, t_aes), "decrypt": (d_des, d_rc4, d_aes)}.items():
            res[op]["DES-CBC"].append(a / 1e6)
            res[op]["RC4-drop3072"].append(b / 1e6)
            res[op]["AES-256-GCM"].append(c / 1e6)
    rows = []
    for op, d in res.items():
        tot = sum(statistics.median(v) for v in d.values())
        for layer, xs in d.items():
            m = statistics.median(xs)
            rows.append({"operation": op, "layer": layer, "median_ms": round(m, 2), "percent": round(100 * m / tot, 1)})
    return rows


def e3_end_to_end(datasets, tmp):
    import re
    import shutil
    from app import create_app
    app = create_app({"INSTANCE_DIR": tmp, "DB_PATH": os.path.join(tmp, "b.db"),
                      "STORAGE_DIR": os.path.join(tmp, "storage"), "SERVER_KEY_PATH": os.path.join(tmp, "k")})
    c = app.test_client()
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/register").get_data(as_text=True)).group(1)
    pw = "performance-test-long-passphrase-2026"
    t = time.perf_counter()
    c.post("/register", data={"csrf": tok, "username": "bench", "password": pw, "password2": pw, "consent": "1"})
    reg_ms = (time.perf_counter() - t) * 1000
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/dashboard").get_data(as_text=True)).group(1)
    cat = {"xlsx": "documents", "docx": "documents", "pdf": "documents", "jpg": "identity", "mp4": "videos"}
    rows = []
    for fname, label, data in datasets:
        ext = fname.rsplit(".", 1)[1]
        R = 3 if QUICK else (10 if len(data) < 32 * CS else 5)
        up, down, plain_w, plain_r, seek = [], [], [], [], []
        for _ in range(R):
            t = time.perf_counter()
            r = c.post(f"/files/upload?category={cat[ext]}", data=data,
                       headers={"X-Filename": fname, "X-CSRF-Token": tok, "Content-Type": "application/octet-stream"})
            up.append((time.perf_counter() - t) * 1000)
            fid = r.get_json()["id"]
            t = time.perf_counter()
            got = c.get(f"/files/{fid}/content?download=1").data
            down.append((time.perf_counter() - t) * 1000)
            assert hashlib.sha256(got).digest() == hashlib.sha256(data).digest()
            if ext == "mp4":
                mid = len(data) // 2
                t = time.perf_counter()
                c.get(f"/files/{fid}/content", headers={"Range": f"bytes={mid}-{mid + CS - 1}"}).data
                seek.append((time.perf_counter() - t) * 1000)
            p = os.path.join(tmp, "plain.bin")
            t = time.perf_counter()
            with open(p, "wb") as fh:
                fh.write(data)
                fh.flush(); os.fsync(fh.fileno())
            plain_w.append((time.perf_counter() - t) * 1000)
            t = time.perf_counter()
            with open(p, "rb") as fh:
                fh.read()
            plain_r.append((time.perf_counter() - t) * 1000)
            c.post(f"/files/{fid}/delete", data={"csrf": tok})
        mb = len(data) / 1e6
        rows.append({"file": label, "size_MB": round(mb, 3),
                     "upload_ms": round(statistics.median(up), 1), "download_ms": round(statistics.median(down), 1),
                     "plain_write_ms": round(statistics.median(plain_w), 1),
                     "plain_read_ms": round(statistics.median(plain_r), 1),
                     "seek_1MiB_ms": round(statistics.median(seek), 1) if seek else "",
                     "upload_at_10Mbps_s": round(len(data) * 8 / 10e6, 1)})
        print(f"  E3 {label:26} done")
    shutil.rmtree(tmp, ignore_errors=True)
    return rows, round(reg_ms, 1)


def e4_memory(path):
    size = os.path.getsize(path)
    key = os.urandom(32)
    out = path + ".enc"
    res = []

    tracemalloc.start()
    with open(path, "rb") as src, open(out, "wb") as dst:
        encrypt_stream(key, b"m", src.read, dst.write)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    res.append({"approach": "Streaming, 1 MiB chunks (RekamKu)", "peak_MB": round(peak / 1e6, 1)})

    tracemalloc.start()
    with open(out, "rb") as fh:
        rd = BlobReader(out, key, b"m")
        sink = hashlib.sha256()
        for i in range(rd.n_chunks):
            sink.update(rd.chunk(i))
        rd.close()
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    res.append({"approach": "Streaming decryption (RekamKu)", "peak_MB": round(peak / 1e6, 1)})

    tracemalloc.start()
    with open(path, "rb") as fh:
        data = fh.read()
    s = Single()
    iv = os.urandom(8)
    c1 = iv + P.des_cbc_encrypt(s.k_des, iv, data)
    c2 = P.rc4_xor(os.urandom(16), c1)
    del c1
    c3 = s.aes.encrypt(os.urandom(12), c2, b"")
    del c2, c3, data
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    res.append({"approach": "Whole file at once (first version)", "peak_MB": round(peak / 1e6, 1)})
    os.remove(out)
    for r in res:
        r["file_size_MB"] = round(size / 1e6, 1)
    return res


def e5_overhead(datasets):
    rows = []
    for fname, label, data in datasets:
        n = len(data)
        ct = ciphertext_size(n)
        n_chunks = max(1, -(-n // CS))
        rows.append({"file": label, "plaintext_B": n, "ciphertext_B": ct, "overhead_B": ct - n,
                     "overhead_percent": round(100 * (ct - n) / n, 4),
                     "AES-GCM_only_B": n + 16 * n_chunks, "DES-CBC_only_B": n + sum(8 + 8 - len(p) % 8
                                                                                    for p in chunks(data)),
                     "RC4_only_B": n})
    return rows


def e6_tamper():
    msg = b"Patient: Example | Fasting glucose: 95 mg/dL | Conclusion: normal, continue therapy"
    pos = msg.index(b"95")
    delta = bytes([ord("9") ^ ord("3")])
    rows = []

    k = os.urandom(16)
    ct = bytearray(P.rc4_xor(k, msg))
    ct[pos] ^= delta[0]
    out = P.rc4_xor(k, bytes(ct))
    rows.append({"cipher": "RC4-drop3072", "attack": "flip 1 ciphertext byte", "detected": "no",
                 "decrypted": out[pos - 17:pos + 8].decode(errors="replace")})

    kd, iv = os.urandom(8), os.urandom(8)
    ct = P.des_cbc_encrypt(kd, iv, msg)
    blk, off = divmod(pos, 8)
    tampered = bytearray(ct)
    tampered[(blk - 1) * 8 + off] ^= delta[0]
    out = P.des_cbc_decrypt(kd, iv, bytes(tampered))
    rows.append({"cipher": "DES-CBC", "attack": "flip byte in previous block", "detected": "no",
                 "decrypted": out[pos - 17:pos + 8].decode(errors="replace")})

    ka, n = os.urandom(32), os.urandom(12)
    ct = bytearray(AESGCM(ka).encrypt(n, msg, b""))
    ct[pos] ^= delta[0]
    try:
        AESGCM(ka).decrypt(n, bytes(ct), b"")
        det, txt = "no", "?"
    except Exception:
        det, txt = "yes", "(rejected, no plaintext released)"
    rows.append({"cipher": "AES-256-GCM", "attack": "flip 1 ciphertext byte", "detected": det,
                 "decrypted": txt})

    from app.crypto.cascade import seal
    key = os.urandom(32)
    blob = bytearray(seal(key, msg, b"ctx"))
    blob[HEADER_LEN + 8 + pos] ^= delta[0]
    try:
        unseal(key, bytes(blob), b"ctx")
        det, txt = "no", "?"
    except IntegrityError:
        det, txt = "yes", "(rejected, no plaintext released)"
    rows.append({"cipher": "Cascade RekamKu", "attack": "flip 1 ciphertext byte", "detected": det,
                 "decrypted": txt})

    k = os.urandom(16)
    p1, p2 = b"Diagnosis: epilepsy     ", b"Diagnosis: ?????????????"
    x = bytes(a ^ b for a, b in zip(P.rc4_xor(k, p1), P.rc4_xor(k, p2)))
    leak = bytes(a ^ b for a, b in zip(x, p2))
    rows.append({"cipher": "RC4 with a reused key", "attack": "c1 XOR c2 XOR known p2",
                 "detected": "-", "decrypted": leak[:20].decode(errors="replace")})
    return rows


def e7_kdf():
    import hashlib as h
    rows = []
    for log2n in (14, 15, 16, 17):
        xs = []
        for _ in range(3 if QUICK else 7):
            t = time.perf_counter()
            h.scrypt(b"example-password-12", salt=os.urandom(16), n=2 ** log2n, r=8, p=1, maxmem=256 * 2 ** 20, dklen=32)
            xs.append((time.perf_counter() - t) * 1000)
        mem = 128 * 8 * 2 ** log2n
        med = statistics.median(xs)
        rows.append({"N": f"2^{log2n}", "memory_MB": round(mem / 2 ** 20), "median_ms": round(med, 1),
                     "guesses_per_second_per_core": round(1000 / med, 1)})
    return rows


def e8_openssl_speed():
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return []
    rows = []
    for name in ("aes-256-gcm", "rc4", "des-cbc", "des-ede3-cbc"):
        try:
            out = subprocess.run(["openssl", "speed", "-provider", "legacy", "-provider", "default", "-seconds",
                                  "1" if QUICK else "3", "-bytes", str(CS), "-evp", name],
                                 capture_output=True, text=True, timeout=60).stdout.strip().splitlines()
            kbps = float(out[-1].split()[-1].rstrip("k"))
            rows.append({"cipher": name.upper(), "MB_per_s": round(kbps / 1000, 1)})
        except Exception as e:
            rows.append({"cipher": name.upper(), "MB_per_s": f"unavailable ({type(e).__name__})"})
    return rows


def environment():
    import cryptography
    cpu = platform.processor() or ""
    try:
        with open("/proc/cpuinfo") as fh:
            info = fh.read()
        cpu = next((ln.split(":", 1)[1].strip() for ln in info.splitlines() if ln.startswith("model name")), cpu)
        aesni = " aes " in info
    except OSError:
        aesni = None
    return {"cpu": cpu, "cores": os.cpu_count(), "aes_ni": aesni, "python": platform.python_version(),
            "os": platform.platform(), "cryptography": cryptography.__version__,
            "openssl": ossl.openssl_version_text(), "chunk_bytes": CS, "quick": QUICK,
            "date": time.strftime("%Y-%m-%d %H:%M")}


def write_csv(name, rows):
    if not rows:
        return
    with open(os.path.join(OUT, name), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    random.seed(1)
    os.makedirs(OUT, exist_ok=True)
    datasets = []
    for fname, label in FILES:
        p = os.path.join(SAMPLES, fname)
        if not os.path.exists(p):
            sys.exit(f"Sample file {fname} is missing. Run first: python bench/make_samples.py")
        with open(p, "rb") as fh:
            datasets.append((fname, label, fh.read()))
    env = environment()
    print("Environment:", json.dumps(env, indent=1))
    with open(os.path.join(OUT, "environment.json"), "w") as fh:
        json.dump(env, fh, indent=2)

    print("E6 ciphertext tampering"); write_csv("e6_tamper.csv", e6_tamper())
    print("E5 overhead");                 write_csv("e5_overhead.csv", e5_overhead(datasets))
    print("E7 scrypt");                   write_csv("e7_kdf.csv", e7_kdf())
    print("E4 memory");                   write_csv("e4_memory.csv", e4_memory(os.path.join(SAMPLES, FILES[-1][0])))
    print("E8 openssl speed");            write_csv("e8_openssl_speed.csv", e8_openssl_speed())
    print("E1 throughput per cipher")
    rows, raw = e1_throughput(datasets)
    write_csv("e1_throughput.csv", rows); write_csv("e1_raw.csv", raw)
    print("E2 cascade layer breakdown");  write_csv("e2_breakdown.csv", e2_breakdown(datasets[4][2]))
    print("E3 end-to-end through the app")
    import tempfile
    e3, reg_ms = e3_end_to_end(datasets, tempfile.mkdtemp())
    write_csv("e3_end_to_end.csv", e3)
    with open(os.path.join(OUT, "environment.json"), "w") as fh:
        json.dump(dict(env, register_ms_scrypt_2x=reg_ms), fh, indent=2)
    print("Done. Results in", OUT)


if __name__ == "__main__":
    main()
