import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#8a8984", "#e6e5e0"
SERIES = {"AES-256-GCM": "#2a78d6", "RC4-drop3072": "#eb6834", "DES-CBC": "#1baf7a", "Cascade": "#6250d6"}
LABEL = {"AES-256-GCM": "AES-256-GCM", "RC4-drop3072": "RC4-drop3072", "DES-CBC": "DES-CBC",
         "Cascade": "Cascade (DES→RC4→AES)"}
SHORT = {"BP & sugar log (XLSX)": "XLSX", "Discharge summary (DOCX)": "DOCX", "KTP scan (JPG)": "KTP",
         "Lab result (PDF)": "Lab PDF", "Video 30 s (MP4)": "Video\n30 s", "Video 3 min (MP4)": "Video\n3 min"}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8.5, "axes.edgecolor": MUTED, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "figure.dpi": 200, "savefig.bbox": "tight", "savefig.pad_inches": 0.04,
})


def load(name):
    with open(os.path.join(R, name), encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def ms_fmt(v, _):
    return f"{v / 1000:g} s" if v >= 1000 else f"{v:g} ms"


def size_txt(mb):
    if mb < 1:
        return f"{mb * 1000:.0f} KB"
    return f"{mb:.1f} MB" if mb < 10 else f"{mb:.0f} MB"


def latency(ax, op="encrypt"):
    rows = [r for r in load("e1_throughput.csv") if r["operation"] == op]
    files = list(dict.fromkeys(r["file"] for r in rows))
    size = {r["file"]: float(r["size_MB"]) for r in rows}
    for cipher, color in SERIES.items():
        pts = sorted(((size[r["file"]], float(r["median_ms"]), float(r["q1_ms"]), float(r["q3_ms"]))
                      for r in rows if r["cipher"] == cipher))
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        ax.fill_between(xs, [p[2] for p in pts], [p[3] for p in pts], color=color, alpha=0.15, linewidth=0)
        ax.plot(xs, ys, color=color, lw=2 if cipher != "Cascade" else 2.4,
                ls="-" if cipher != "Cascade" else (0, (4, 1.5)), marker="o", ms=4, label=LABEL[cipher])
        txt = f"{ys[-1] / 1000:.1f} s" if ys[-1] >= 1000 else f"{ys[-1]:.0f} ms"
        dy = {"Cascade": 6, "DES-CBC": -6}.get(cipher, 0)
        ax.annotate(txt, (xs[-1], ys[-1]), xytext=(5, dy), textcoords="offset points",
                    va="center", fontsize=7.5, color=INK)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.yaxis.set_major_formatter(FuncFormatter(ms_fmt))
    ax.set_xlabel("Scenario file (size, log scale)")
    ax.set_ylabel(f"Time to {op} (median, log scale)")
    ticks = [size[f] for f in files]
    ax.set_xticks(ticks)
    labels = ax.set_xticklabels([f"{SHORT[f]}\n{size_txt(size[f])}" for f in files], fontsize=7)
    labels[0].set_horizontalalignment("right")
    labels[1].set_horizontalalignment("left")
    ax.minorticks_off()
    ax.set_xlim(ticks[0] * 0.7, ticks[-1] * 2.6)
    ax.legend(frameon=False, fontsize=7.5, loc="upper left")


def layers(ax):
    rows = load("e2_breakdown.csv")
    ops = ["encrypt", "decrypt"]
    for i, op in enumerate(ops):
        left = 0
        for layer in ["DES-CBC", "RC4-drop3072", "AES-256-GCM"]:
            r = next(x for x in rows if x["operation"] == op and x["layer"] == layer)
            w = float(r["percent"])
            ax.barh(i, w, left=left, color=SERIES[layer], height=0.55, edgecolor="white", linewidth=1.5)
            if w > 20:
                ax.text(left + w / 2, i, f"DES {w:.0f}%", ha="center", va="center", color="white",
                        fontsize=7.5, fontweight="bold")
            left += w
    ax.set_yticks(range(len(ops)))
    ax.set_yticklabels([o.capitalize() for o in ops])
    ax.set_xlim(0, 100)
    rc4 = [float(x["percent"]) for x in rows if x["layer"] == "RC4-drop3072"]
    aes = [float(x["percent"]) for x in rows if x["layer"] == "AES-256-GCM"]
    lo, hi = round(min(rc4)), round(max(rc4))
    rc4_txt = f"{lo}%" if lo == hi else f"{lo}-{hi}%"
    ax.set_xlabel(f"% of cascade time, 30 s video; orange = RC4 {rc4_txt}, AES-GCM <{max(aes) + 0.5:.0f}%",
                  fontsize=7.5)
    ax.grid(axis="y", visible=False)
    ax.invert_yaxis()


def memory(ax):
    rows = load("e4_memory.csv")
    labels = ["Streaming encrypt", "Streaming decrypt", "All at once (first version)"]
    ys = [float(r["peak_MB"]) for r in rows]
    ax.barh(labels, ys, color=["#2a78d6", "#2a78d6", "#8a8984"], height=0.55)
    for i, y in enumerate(ys):
        ax.text(y + max(ys) * 0.02, i, f"{y:.0f} MB", va="center", fontsize=7.5, color=INK)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7.5)
    ax.set_xlim(0, max(ys) * 1.25)
    ax.invert_yaxis(); ax.grid(axis="y", visible=False)
    ax.set_xlabel(f"Peak memory (MB), {rows[0]['file_size_MB']} MB video", fontsize=7.5)


if __name__ == "__main__":
    fig, ax = plt.subplots(figsize=(4.2, 3.0)); latency(ax); fig.savefig(os.path.join(R, "fig_latency.png"))
    fig, ax = plt.subplots(figsize=(4.2, 1.4)); layers(ax); fig.savefig(os.path.join(R, "fig_layers.png"))
    fig, ax = plt.subplots(figsize=(3.6, 1.5)); memory(ax); fig.savefig(os.path.join(R, "fig_memory.png"))
    fig = plt.figure(figsize=(7.2, 2.55))
    gs = fig.add_gridspec(2, 2, width_ratios=[1.5, 1], height_ratios=[1, 1.15], wspace=0.36, hspace=0.95)
    a = fig.add_subplot(gs[:, 0]); latency(a)
    a.set_title("(a) Encryption time per scenario file", loc="left", fontsize=8.5, color=INK)
    b = fig.add_subplot(gs[0, 1]); layers(b)
    b.set_title("(b) Where the cascade spends its time", loc="left", fontsize=8.5, color=INK)
    c = fig.add_subplot(gs[1, 1]); memory(c)
    c.set_title("(c) Server memory", loc="left", fontsize=8.5, color=INK)
    fig.savefig(os.path.join(R, "fig_report.png"))
    print("charts saved in", R)
