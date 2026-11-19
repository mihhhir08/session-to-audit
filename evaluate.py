#!/usr/bin/env python3
"""Pilot evaluation of S2A over a directory of Claude Code sessions.
Usage: evaluate.py <out_dir> [sessions_root] [exclude_substring]
Defaults: sessions_root=~/.claude/projects. Prints aggregate statistics only (no session content)."""
import json, os, sys, time, glob, copy, random, statistics as st, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s2a
root = os.path.expanduser(sys.argv[2] if len(sys.argv) > 2 else "~/.claude/projects")
exclude = sys.argv[3] if len(sys.argv) > 3 else None
files = sorted(f for f in glob.glob(root + "/*/*.jsonl") if not (exclude and exclude in f))
outdir = sys.argv[1]; os.makedirs(outdir, exist_ok=True)
rows, rulec, kindc, toolc = [], collections.Counter(), collections.Counter(), collections.Counter()
tamper = {"trials": 0, "detected": 0}
random.seed(7)
for f in files:
    raw = os.path.getsize(f)
    t0 = time.perf_counter(); meta, evs = s2a.parse(f); rec = s2a.build(meta, evs); h = s2a.to_html(rec); t1 = time.perf_counter()
    out = os.path.join(outdir, os.path.basename(f).replace(".jsonl", ".html")); open(out, "w").write(h)
    t2 = time.perf_counter(); ok, _ = s2a.verify(out); t3 = time.perf_counter()
    for e in rec["events"]:
        kindc[e["kind"]] += 1; toolc[e["tool"]] += 1
        for fl in e["risk_flags"]: rulec[fl["rule"] + " " + fl["name"]] += 1
    # tamper trials: mutate one random field of a random event, recompute nothing, verify must fail
    if rec["events"]:
        for _ in range(20):
            r2 = copy.deepcopy(rec); e = random.choice(r2["events"])
            choice = random.choice(["outcome", "flags", "content", "delete", "reorder"])
            if choice == "outcome": e["outcome"]["status"] = "success" if e["outcome"]["status"] != "success" else "failure"
            elif choice == "flags": e["risk_flags"] = [] if e["risk_flags"] else [{"rule": "R0", "name": "x", "severity": "low"}]
            elif choice == "content": e["ts"] = "1970-01-01T00:00:00Z"
            elif choice == "delete": r2["events"].remove(e)
            elif choice == "reorder" and len(r2["events"]) > 1:
                i = r2["events"].index(e); j = (i + 1) % len(r2["events"]); r2["events"][i], r2["events"][j] = r2["events"][j], r2["events"][i]
            else: e["ts"] = "x"
            tamper["trials"] += 1; tamper["detected"] += (not s2a.verify_record(r2)[0])
    s = rec["summary"]
    rows.append(dict(s, raw_bytes=raw, html_bytes=len(h.encode()), convert_ms=(t1-t0)*1000, verify_ms=(t3-t2)*1000,
                     verified=ok, user_turns=meta["user_turns"], typed=sum(e["kind"] != "other" for e in rec["events"])))
if not rows: sys.exit("no sessions found under " + root)
def agg(k): v=[r[k] for r in rows]; return {"sum": sum(v), "median": st.median(v), "min": min(v), "max": max(v)}
res = {"sessions": len(rows), "sessions_with_events": sum(r["events"] > 0 for r in rows),
 "per_session": {k: agg(k) for k in ["events","commands","file_changes","files_touched","lines_added","lines_removed","failures","risk_flags","high_risk_events","user_turns","raw_bytes","html_bytes","convert_ms","verify_ms"]},
 "all_verified": all(r["verified"] for r in rows), "typed_coverage": sum(r["typed"] for r in rows)/max(1,sum(r["events"] for r in rows)),
 "size_ratio_median": st.median(r["html_bytes"]/r["raw_bytes"] for r in rows if r["raw_bytes"]),
 "failure_rate_overall": sum(r["failures"] for r in rows)/max(1,sum(r["events"] for r in rows)),
 "kinds": dict(kindc), "rules": dict(rulec.most_common()), "tamper": tamper, "tools": dict(toolc.most_common(15))}
print(json.dumps(res, indent=1))
