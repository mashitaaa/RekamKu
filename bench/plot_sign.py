"""Figure for the Assignment 3 report: what signing and verifying cost.

Reads bench/results/e10_sign_cost.csv (written by bench/sign_bench.py) and
writes docs/fig_sign_cost.png.  Run from the repository root:
    python bench/plot_sign.py
Optional: python bench/plot_sign.py <csv> <png>
"""
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results", "e10_sign_cost.csv")
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "docs", "fig_sign_cost.png")

rows = {r["operation"]: r for r in csv.DictReader(open(SRC, newline="", encoding="utf-8"))}


def find(*words):
    """Row whose operation name contains every word (so the script survives small label edits)."""
    hits = [r for name, r in rows.items() if all(w.lower() in name.lower() for w in words)]
    if len(hits) != 1:
        raise KeyError(f"{words}: {len(hits)} rows match")
    return hits[0]


def med(r):
    return float(r["median_ms_or_bytes"])


def err(r):  # interquartile range as asymmetric error bar
    m = med(r)
    return [[max(0.0, m - float(r["q1"]))], [max(0.0, float(r["q3"]) - m)]]


def label(r):
    m = med(r)
    return f"{m:.2f} ms" if m < 1 else (f"{m:.1f} ms" if m < 10 else f"{m:.0f} ms")


plt.rcParams.update({"font.family": "serif", "font.size": 8})
fig, (a, b) = plt.subplots(1, 2, figsize=(7.0, 2.2), gridspec_kw={"width_ratios": [1, 1.1]})

# (a) the RSA-3072 operations on their own
ops = [("Our signature\n(CRT, blinding)", find("our rsa-3072"), "#2e8b6e"),
       ("OpenSSL\nsignature", find("library rsa-3072"), "#b8b8b8"),
       ("Our\nverification", find("our rsa signature verification"), "#3b6ea8")]
for i, (lab, r, col) in enumerate(ops):
    a.bar(i, med(r), 0.55, yerr=err(r), capsize=2, color=col)
    a.text(i, float(r["q3"]) * 1.25, label(r), ha="center", va="bottom")
a.set_yscale("log")
a.set_ylim(0.2, 120)
a.set_xticks(range(len(ops)))
a.set_xticklabels([o[0] for o in ops])
a.set_ylabel("median time (ms, log scale)")
a.set_title("(a) RSA-3072: the arithmetic is small", fontsize=8.5)

# (b) the same 1.8 MB lab PDF, in memory and inside the app
groups = [("Sign", find("sign in memory", "lab"), find("app: sign")),
          ("Verify", find("verify in memory", "lab"), find("app: verify"))]
w = 0.34
for i, (lab, mem, app) in enumerate(groups):
    b.bar(i - w / 2 - 0.01, med(mem), w, yerr=err(mem), capsize=2, color="#2e8b6e",
          label="In memory (PDF only)" if i == 0 else None)
    b.bar(i + w / 2 + 0.01, med(app), w, yerr=err(app), capsize=2, color="#3b6ea8",
          label="In the app (decrypt, re-encrypt, shares)" if i == 0 else None)
    b.text(i - w / 2 - 0.01, float(mem["q3"]) * 1.25, label(mem), ha="center", va="bottom")
    b.text(i + w / 2 + 0.01, float(app["q3"]) * 1.25, label(app), ha="center", va="bottom")
b.set_yscale("log")
b.set_ylim(1.5, 30000)
b.set_xticks(range(len(groups)))
b.set_xticklabels([g[0] for g in groups])
b.set_title("(b) 1.8 MB lab PDF: the vault dominates", fontsize=8.5)
b.legend(frameon=False, fontsize=7, loc="upper left")

for ax in (a, b):
    ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
os.makedirs(os.path.dirname(os.path.abspath(OUT)), exist_ok=True)
fig.savefig(OUT, dpi=300)
print("wrote", os.path.normpath(OUT))
