#!/usr/bin/env python3
"""Diff-fidelity comparison between S2A v0.1 (diffs reconstructed from tool input) and v0.2
(diffs taken from the agent's own structured patch when available) on Claude Code sessions.
Usage: compare_v01.py <path/to/v0.1/s2a.py> <glob> [exclude_substring]
Get v0.1 with: git show v0.1:s2a.py > s2a_v01.py   (or commit 8a5e755)"""
import sys, glob, os, json, collections, importlib.util
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
v1 = load("v1", sys.argv[1]); v2 = load("v2", os.path.join(os.path.dirname(os.path.abspath(__file__)), "s2a.py"))
ex = sys.argv[3] if len(sys.argv) > 3 else None
fs = [f for f in sorted(glob.glob(os.path.expanduser(sys.argv[2]))) if not (ex and ex in f)]
r = collections.Counter(); ops = collections.Counter()
for f in fs:
    m, e = v1.parse(f); R1 = v1.build(m, e)
    m2, e2, _ = v2.parse(f); R2 = v2.build(m2, e2)
    F1 = [x for x in R1["events"] if x["kind"] == "file_change"]; F2 = [x for x in R2["events"] if x["kind"] == "file_change"]
    assert len(F1) == len(F2)
    for x, y in zip(F1, F2):
        r["v01_added"] += x["added"]; r["v01_removed"] += x["removed"]; r["v02_added"] += y["added"]; r["v02_removed"] += y["removed"]
        r["events"] += 1; r["events_with_different_counts"] += (x["added"], x["removed"]) != (y["added"], y["removed"])
        r["diff_from_agent_patch"] += y["diff_source"] == "agent_structured_patch"
        ops["%s/%s" % (y["tool"], y.get("op"))] += 1
print(json.dumps({"sessions": len(fs), **r, "ops": ops}, indent=1))
