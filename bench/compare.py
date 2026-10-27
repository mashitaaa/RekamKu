import csv
from collections import defaultdict

def load(path):
    d = {}
    for r in csv.DictReader(open(path, encoding="utf-8")):
        d[(r["file"], r["cipher"], r["operation"])] = float(r["median_ms"])
    return d

a = load("bench/results_1/e1_throughput.csv")
b = load("bench/results/e1_throughput.csv")
worst = defaultdict(float)
for k in a:
    diff = abs(a[k] - b[k]) / a[k] * 100
    worst[k[1]] = max(worst[k[1]], diff)
for cipher, pct in worst.items():
    print(f"{cipher:16s} selisih median maksimum antar-run: {pct:.1f}%")