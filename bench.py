#!/usr/bin/env python3
"""Timing benchmark: convert and verify each session log REPEATS times and keep the minimum
(the minimum is the standard estimate of cost under background load).
Usage: bench.py out.json NAME=GLOB[:EXCLUDE] [NAME=GLOB[:EXCLUDE] ...]"""
import glob, json, os, statistics as st, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s2a
from evaluate import files_for
REPEATS = 3
pts = []
for spec in sys.argv[2:]:
    name, fs = files_for(spec)
    for f in fs:
        conv, ver = [], []
        for _ in range(REPEATS):
            t0 = time.perf_counter(); meta, evs, _ = s2a.parse(f); rec = s2a.build(meta, evs); h = s2a.to_html(rec); t1 = time.perf_counter()
            if not evs: break
            out = os.path.join(tempfile.gettempdir(), "s2a_bench.html"); open(out, "w", encoding="utf-8").write(h)
            t2 = time.perf_counter(); s2a.verify(out); t3 = time.perf_counter()
            conv.append((t1 - t0) * 1e3); ver.append((t3 - t2) * 1e3)
        if conv: pts.append({"corpus": name, "raw_MB": os.path.getsize(f) / 1e6, "events": len(evs), "convert_ms": min(conv), "verify_ms": min(ver)})
xs = [p["raw_MB"] for p in pts]; ys = [p["convert_ms"] for p in pts]
mx, my = st.mean(xs), st.mean(ys)
b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
r = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys)) ** 0.5
summary = {"sessions": len(pts), "repeats": REPEATS, "convert_ms_median": st.median(ys), "convert_ms_max": max(ys),
           "verify_ms_median": st.median(p["verify_ms"] for p in pts), "verify_ms_max": max(p["verify_ms"] for p in pts),
           "ms_per_MB_slope": b, "intercept_ms": my - b * mx, "pearson_r": r, "largest_MB": max(xs),
           "throughput_MB_per_s_largest": max(xs) / (ys[xs.index(max(xs))] / 1e3)}
json.dump({"summary": summary, "points": pts}, open(sys.argv[1], "w"), indent=1)
print(json.dumps(summary, indent=1))
