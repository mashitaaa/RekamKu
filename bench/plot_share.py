"""Figure for the Assignment 2 report: what sharing costs.

Reads bench/results/e8_share_cost.csv (written by bench/share_bench.py)
and writes docs/fig_share_cost.png.  Run from the repository root:
    python bench/plot_share.py
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "results", "e8_share_cost.csv")
OUT = os.path.join(HERE, "..", "docs", "fig_share_cost.png")

rows = {r["operation"]: r for r in csv.DictReader(open(SRC, newline="", encoding="utf-8"))}


def find(*words):
    """Row whose operation name contains every word (so the script survives small label edits)."""
    for name, r in rows.items():
        if all(w.lower() in name.lower() for w in words):
            return r
    raise KeyError(words)


def med(r):
    return float(r["median_ms"])


def err(r):  # interquartile range as asymmetric error bar
    m = med(r)
    return [[max(0.0, m - float(r["q1_ms"]))], [max(0.0, float(r["q3_ms"]) - m)]]


plt.rcParams.update({"font.family": "serif", "font.size": 8})
fig, (a, b) = plt.subplots(1, 2, figsize=(7.0, 2.35), gridspec_kw={"width_ratios": [1.15, 1]})

# (a) approving vs re-encrypting, for a small and a large share
sizes = [("1.8 MB PDF", "lab PDF"), ("92 MB (PDF + KTP + video)", "92 MB")]
approve = [find("Approve", key) for _, key in sizes]
redo = [find("Baseline", key) for _, key in sizes]
x = range(len(sizes))
w = 0.34
for i, (r1, r2) in enumerate(zip(approve, redo)):
    a.bar(i - w / 2 - 0.01, med(r1), w, yerr=err(r1), capsize=2, color="#2e8b6e", label="Approve (wrap 32-byte keys)" if i == 0 else None)
    a.bar(i + w / 2 + 0.01, med(r2), w, yerr=err(r2), capsize=2, color="#b8b8b8", label="Re-encrypt with cascade" if i == 0 else None)
    a.text(i - w / 2 - 0.01, float(r1["q3_ms"]) * 1.2, f"{med(r1):.0f} ms", ha="center", va="bottom")
    a.text(i + w / 2 + 0.01, float(r2["q3_ms"]) * 1.2, f"{med(r2):.0f} ms" if med(r2) < 1000 else f"{med(r2) / 1000:.1f} s", ha="center", va="bottom")
a.set_yscale("log")
a.set_ylim(5, 30000)
a.set_xticks(list(x))
a.set_xticklabels([s for s, _ in sizes])
a.set_ylabel("median time (ms, log scale)")
a.set_title("(a) Approving does not grow with file size", fontsize=8.5)
a.legend(frameon=False, fontsize=7, loc="upper left")

# (b) RSA operations
ops = [("Key pair\n(once)", find("key pair generation")),
       ("Encrypt share\nkey (patient)", find("Encrypt share key")),
       ("Decrypt share\nkey (requester)", find("Decrypt share key"))]
for i, (lab, r) in enumerate(ops):
    b.bar(i, med(r), 0.55, yerr=err(r), capsize=2, color="#3b6ea8")
    b.text(i, float(r["q3_ms"]) * 1.2, f"{med(r):.2f} ms" if med(r) < 1 else f"{med(r):.0f} ms", ha="center", va="bottom")
b.set_yscale("log")
b.set_ylim(0.03, 1000)
b.set_xticks(range(len(ops)))
b.set_xticklabels([l for l, _ in ops])
b.set_title("(b) RSA-3072: the private key is the slow part", fontsize=8.5)

for ax in (a, b):
    ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
os.makedirs(os.path.dirname(OUT), exist_ok=True)
fig.savefig(OUT, dpi=300)
print("wrote", os.path.normpath(OUT))
