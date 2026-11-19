#!/usr/bin/env python3
"""Evaluation harness for S2A v0.2. Prints aggregate statistics only (never session content).

Usage:
  evaluate.py <out_dir> --corpus NAME=GLOB[:EXCLUDE] [--corpus ...] [--sample annotation.json] [--v01 path/to/v0.1/s2a.py]

Each corpus is a glob of session logs (recursive ** allowed) with an optional substring to exclude.
Codex "guardian" auto-review threads are always excluded because they contain no agent actions.
"""
import json, os, sys, time, glob, copy, random, statistics as st, collections, re, subprocess, tempfile, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s2a

PROVIDER_FAMILIES = {"private_key_block", "aws_access_key", "github_token", "anthropic_key", "openai_key",
                     "stripe_key", "slack_token", "google_api_key", "jwt"}

def args():
    a, corp, opt = sys.argv[1:], [], {}
    out = a[0]; i = 1
    while i < len(a):
        if a[i] == "--corpus": corp.append(a[i + 1]); i += 2
        else: opt[a[i]] = a[i + 1]; i += 2
    return out, corp, opt

def is_guardian(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        first = f.readline()
    return '"guardian"' in first[:4000]

def files_for(spec):
    name, rest = spec.split("=", 1)
    pat, excl = (rest.split(":", 1) + [None])[:2] if ":" in rest else (rest, None)
    fs = sorted(f for f in glob.glob(os.path.expanduser(pat), recursive=True)
                if not (excl and excl in f) and not is_guardian(f))
    return name, fs

def raw_secret_values(path):
    """Distinct provider-format credential strings present in a raw log (kept in memory only)."""
    t = open(path, encoding="utf-8", errors="replace").read()
    vals, fams = set(), collections.Counter()
    for fam, rx in s2a.SECRET_PATTERNS:
        if fam not in PROVIDER_FAMILIES: continue
        for m in re.finditer(rx, t):
            v = m.group(0)
            if len(v) >= 20 and "\\" not in v[:40]: vals.add(v[:40]); fams[fam] += 1
    return vals, fams

# ------------------------------------------------------------------ tamper ---
def recompute(rec, upto=None):
    prev = s2a.GENESIS
    for i, ev in enumerate(rec["events"]):
        ev["seq"], ev["prev_hash"] = i, prev
        ev["hash"] = prev = s2a.sha(prev + s2a.canon({k: v for k, v in ev.items() if k != "hash"}))
    rec["chain_head"] = prev
    rec["record_digest"] = s2a.sha(s2a.canon({k: v for k, v in rec.items() if k != "record_digest"}))

def mutate(rec, kind, rnd):
    evs = rec["events"]; e = rnd.choice(evs)
    if kind == "flip_outcome": e["outcome"]["status"] = "success" if e["outcome"]["status"] != "success" else "failure"
    elif kind == "drop_flags": e["risk_flags"] = [] if e["risk_flags"] else [{"rule": "R0", "name": "x", "severity": "low"}]
    elif kind == "edit_content":
        k = "command" if "command" in e else "diff" if "diff" in e else "target" if "target" in e else "ts"
        e[k] = str(e.get(k, "")) + " "
    elif kind == "edit_timestamp": e["ts"] = "1970-01-01T00:00:00Z"
    elif kind == "delete_event": evs.remove(e)
    elif kind == "insert_event":
        x = copy.deepcopy(e); x["command"] = "true"; evs.insert(evs.index(e) + 1, x)
    elif kind == "reorder" and len(evs) > 1:
        i = evs.index(e); j = (i + 1) % len(evs); evs[i], evs[j] = evs[j], evs[i]
    elif kind == "truncate_tail": del evs[max(0, len(evs) - rnd.randint(1, 3)):]
    elif kind == "edit_summary": rec["summary"]["failures"] = rec["summary"]["failures"] + 1
    elif kind == "edit_session_meta": rec["session"]["cwd"] = "/tmp/elsewhere"

NAIVE = ["flip_outcome", "drop_flags", "edit_content", "edit_timestamp", "delete_event", "insert_event",
         "reorder", "truncate_tail", "edit_summary", "edit_session_meta"]

def main():
    outdir, corpora, opt = args(); os.makedirs(outdir, exist_ok=True)
    rnd = random.Random(7)
    results, sample_pool = {"corpora": {}}, []
    perf = []
    tamper = {k: {"trials": 0, "detected": 0} for k in NAIVE}
    adaptive = {"trials": 0, "pass_integrity": 0, "pass_signature": 0}
    keydir = tempfile.mkdtemp(); key = os.path.join(keydir, "k")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "s2a-eval", "-f", key], check=True)
    signers = os.path.join(keydir, "allowed")
    open(signers, "w").write("eval@s2a " + open(key + ".pub").read())
    sign_ms, sigverify_ms, signed_ok = [], [], 0
    redaction = {"sessions_with_provider_secrets": 0, "distinct_secret_strings": 0, "leaked_into_artifact": 0, "families": collections.Counter()}

    for spec in corpora:
        name, files = files_for(spec)
        C = {"sessions": 0, "sessions_with_events": 0, "events": 0, "kinds": collections.Counter(), "rules": collections.Counter(),
             "outcomes": collections.Counter(), "high_risk_events": 0, "flagged_events": 0, "user_turns": [], "events_per_session": [],
             "models": collections.Counter(), "versions": set(), "dates": [], "diff_sources": collections.Counter(),
             "file_ops": collections.Counter(), "lines_added": 0, "lines_removed": 0, "codemode": collections.Counter(),
             "raw_bytes": 0, "html_bytes": 0, "size_ratios": [], "tools_distinct": set(), "other_tools": collections.Counter(),
             "via_code_mode_events": 0, "code_mode_unknown": 0, "sessions_flagged": 0}
        for f in files:
            raw = os.path.getsize(f)
            t0 = time.perf_counter(); meta, evs, stats = s2a.parse(f); rec = s2a.build(meta, evs); h = s2a.to_html(rec); t1 = time.perf_counter()
            out = os.path.join(outdir, name + "_" + os.path.basename(f).replace(".jsonl", ".html"))
            open(out, "w", encoding="utf-8").write(h)
            t2 = time.perf_counter(); ok, _ = s2a.verify(out); t3 = time.perf_counter()
            assert ok, f
            perf.append({"corpus": name, "raw_bytes": raw, "events": len(evs), "convert_ms": (t1 - t0) * 1000, "verify_ms": (t3 - t2) * 1000, "html_bytes": len(h.encode())})
            # secrets: every provider-format credential string in the raw log must be absent from the artifact
            vals, fams = raw_secret_values(f)
            if vals:
                redaction["sessions_with_provider_secrets"] += 1; redaction["distinct_secret_strings"] += len(vals)
                redaction["families"].update({k: 1 for k in fams})
                redaction["leaked_into_artifact"] += sum(1 for v in vals if v in h)
            C["sessions"] += 1; C["sessions_with_events"] += bool(evs); C["events"] += len(evs)
            C["events_per_session"].append(len(evs)); C["user_turns"].append(meta["user_turns"])
            C["models"].update(meta["models"]); C["versions"].add(str(meta["agent_version"]))
            if meta["started"]: C["dates"].append(meta["started"][:10])
            C["raw_bytes"] += raw; C["html_bytes"] += len(h.encode())
            if raw > 50_000: C["size_ratios"].append(len(h.encode()) / raw)
            for k, v in stats.items(): C["codemode"][k] += v
            C["sessions_flagged"] += any(e["risk_flags"] for e in rec["events"])
            for e in rec["events"]:
                C["kinds"][e["kind"]] += 1; C["outcomes"][e["outcome"]["status"]] += 1; C["tools_distinct"].add(e["tool"])
                if e["kind"] == "other": C["other_tools"][re.sub(r"^mcp__([^_]+(?:_[^_]+)*?)__.*", r"mcp:\1", e["tool"])] += 1
                if e.get("via") == "code_mode":
                    C["via_code_mode_events"] += 1; C["code_mode_unknown"] += e["outcome"]["status"] == "unknown"
                if e["kind"] == "file_change":
                    C["diff_sources"][e.get("diff_source")] += 1; C["file_ops"][e.get("op")] += 1
                    C["lines_added"] += e.get("added", 0); C["lines_removed"] += e.get("removed", 0)
                for fl in e["risk_flags"]: C["rules"][fl["rule"]] += 1
                C["flagged_events"] += bool(e["risk_flags"])
                C["high_risk_events"] += any(fl["severity"] == "high" for fl in e["risk_flags"])
                if e["kind"] in ("command", "file_change"):
                    sample_pool.append({"corpus": name, "kind": e["kind"], "tool": e["tool"], "rules": [fl["rule"] for fl in e["risk_flags"]],
                                        "text": (e.get("command") or "")[:1500] if e["kind"] == "command" else
                                                (e.get("op", "") + " " + e.get("path", "") + "\n" + (e.get("diff") or "")[:600]),
                                        "cwd": meta["cwd"], "status": e["outcome"]["status"]})
            # integrity experiments
            if len(rec["events"]) >= 2:
                for kind in NAIVE:
                    for _ in range(3):
                        r2 = copy.deepcopy(rec); mutate(r2, kind, rnd)
                        tamper[kind]["trials"] += 1; tamper[kind]["detected"] += not s2a.verify_record(r2)[0]
                # signing on the honest artifact, then an adaptive forgery that recomputes the whole chain
                ts0 = time.perf_counter(); s2a.sign(out, key, "eval@s2a"); ts1 = time.perf_counter()
                okv, _ = s2a.verify(out, signers, "eval@s2a"); ts2 = time.perf_counter()
                signed_ok += okv; sign_ms.append((ts1 - ts0) * 1000); sigverify_ms.append((ts2 - ts1) * 1000)
                signed_html = open(out, encoding="utf-8").read()
                for kind in ("flip_outcome", "drop_flags", "delete_event", "truncate_tail"):
                    r3 = copy.deepcopy(rec); mutate(r3, kind, rnd); recompute(r3)
                    forged = s2a.to_html(r3)
                    m = s2a.SIG_RX.search(signed_html)  # attacker copies the original signature block
                    forged = forged.replace("</body></html>", m.group(0) + "</body></html>")
                    fp = os.path.join(keydir, "forged.html"); open(fp, "w", encoding="utf-8").write(forged)
                    adaptive["trials"] += 1
                    adaptive["pass_integrity"] += s2a.verify(fp)[0]
                    adaptive["pass_signature"] += s2a.verify(fp, signers, "eval@s2a")[0]
        dates = sorted(C["dates"])
        known = C["outcomes"]["success"] + C["outcomes"]["failure"]
        results["corpora"][name] = {
            "sessions": C["sessions"], "sessions_with_events": C["sessions_with_events"], "events": C["events"],
            "events_per_session_median": st.median(C["events_per_session"]) if C["events_per_session"] else 0,
            "events_per_session_max": max(C["events_per_session"] or [0]),
            "user_turns_total": sum(C["user_turns"]), "date_range": [dates[0], dates[-1]] if dates else None,
            "agent_versions": sorted(C["versions"]), "models": dict(C["models"]), "distinct_tools": len(C["tools_distinct"]),
            "kinds": dict(C["kinds"]), "typed_coverage": 1 - C["kinds"]["other"] / max(1, C["events"]),
            "other_tools_top": dict(C["other_tools"].most_common(8)),
            "outcomes": dict(C["outcomes"]), "outcome_determinacy": known / max(1, C["events"]),
            "failure_rate_of_determinate": C["outcomes"]["failure"] / max(1, known),
            "file_changes": C["kinds"]["file_change"], "diff_sources": dict(C["diff_sources"]), "file_ops": dict(C["file_ops"]),
            "lines_added": C["lines_added"], "lines_removed": C["lines_removed"],
            "code_mode": dict(C["codemode"]), "via_code_mode_events": C["via_code_mode_events"], "code_mode_unknown": C["code_mode_unknown"],
            "rules": dict(C["rules"].most_common()), "flagged_events": C["flagged_events"], "high_risk_events": C["high_risk_events"],
            "sessions_with_any_flag": C["sessions_flagged"],
            "raw_bytes": C["raw_bytes"], "html_bytes": C["html_bytes"],
            "size_ratio_median_logs_over_50KB": st.median(C["size_ratios"]) if C["size_ratios"] else None,
        }
    # performance summary + least squares fit of convert time on raw size
    xs = [p["raw_bytes"] / 1e6 for p in perf]; ys = [p["convert_ms"] for p in perf]
    mx, my = st.mean(xs), st.mean(ys)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    r = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sum((x - mx) ** 2 for x in xs) ** .5 * sum((y - my) ** 2 for y in ys) ** .5)
    results["performance"] = {"sessions": len(perf), "convert_ms_median": st.median(ys), "convert_ms_max": max(ys),
                              "verify_ms_median": st.median(p["verify_ms"] for p in perf), "verify_ms_max": max(p["verify_ms"] for p in perf),
                              "ms_per_MB": slope, "pearson_r": r, "largest_log_MB": max(xs),
                              "sign_ms_median": st.median(sign_ms), "sig_verify_ms_median": st.median(sigverify_ms),
                              "signed_and_verified": signed_ok, "signed_attempts": len(sign_ms)}
    results["tamper_naive"] = tamper
    results["tamper_naive_total"] = {"trials": sum(v["trials"] for v in tamper.values()), "detected": sum(v["detected"] for v in tamper.values())}
    results["tamper_adaptive"] = adaptive
    results["redaction_real_logs"] = dict(redaction, families=dict(redaction["families"]))
    json.dump(perf, open(os.path.join(outdir, "perf_points.json"), "w"))
    if "--sample" in opt:
        rs = random.Random(11); out = []
        by_rule = collections.defaultdict(list)
        for x in sample_pool:
            for rid in x["rules"]: by_rule[rid].append(x)
        for rid, xs_ in sorted(by_rule.items()):
            for x in rs.sample(xs_, min(25, len(xs_))): out.append(dict(x, sampled_for=rid))
        unflagged = [x for x in sample_pool if not x["rules"] and x["kind"] == "command" and x["text"].strip()]
        for x in rs.sample(unflagged, min(150, len(unflagged))): out.append(dict(x, sampled_for="UNFLAGGED"))
        for i, x in enumerate(out): x["id"] = i
        json.dump(out, open(opt["--sample"], "w"), indent=1)
        results["annotation_sample"] = {"flagged_items": sum(x["sampled_for"] != "UNFLAGGED" for x in out),
                                        "unflagged_items": sum(x["sampled_for"] == "UNFLAGGED" for x in out),
                                        "population_unflagged_commands": len(unflagged),
                                        "population_by_rule": {k: len(v) for k, v in sorted(by_rule.items())}}
    print(json.dumps(results, indent=1, default=list))

if __name__ == "__main__":
    main()
