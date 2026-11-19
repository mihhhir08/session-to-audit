#!/usr/bin/env python3
"""Session-to-Audit (S2A) v0.1 reference implementation.
Converts a coding-agent session log (Claude Code JSONL) into a self-contained,
hash-chained HTML audit artifact, and verifies such artifacts.
Usage: s2a.py convert <session.jsonl> <out.html>
       s2a.py verify <artifact.html>
"""
import json, sys, re, hashlib, html, difflib, os, time

SCHEMA_VERSION = "s2a/0.1"
GENESIS = "0" * 64

RISK_RULES = [
 ("R1", "destructive_fs", "high", r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\b|\bfind\b.*\s-delete\b|\bshred\b|\bmkfs\b|\bdd\s+if="),
 ("R2", "vcs_history_rewrite", "high", r"\bgit\s+push\b.*(--force|\s-f\b)|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+branch\s+-D\b|\bgit\s+checkout\s+--\s"),
 ("R3", "remote_code_exec", "high", r"(curl|wget)[^|;&]*\|\s*(ba|z)?sh\b"),
 ("R4", "privilege_escalation", "high", r"\bsudo\b|\bchmod\s+(-R\s+)?777\b|\bchown\s+-R\b"),
 ("R5", "secret_exposure", "high", r"AKIA[0-9A-Z]{16}|\bsk-[A-Za-z0-9_\-]{20,}|\bghp_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[bp]-[A-Za-z0-9\-]{10,}"),
 ("R6", "network_egress", "medium", r"\bcurl\b[^\n]*(-X\s*(POST|PUT|PATCH|DELETE)|--data|-d\s|-F\s)|\bscp\b|\brsync\b[^\n]*:"),
 ("R7", "dependency_install", "medium", r"\b(npm|pnpm|yarn)\s+(i|install|add)\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bnpx\s+\S+"),
 ("R8", "publish_or_deploy", "medium", r"\bgit\s+push\b|\bnpm\s+publish\b|\bvercel\b[^\n]*--prod|\bdocker\s+push\b|\bgh\s+(pr|release)\s+create\b"),
]
PATH_RULES = [
 ("R9", "out_of_workspace_write", "medium"),
 ("R10", "sensitive_file_write", "high", r"(^|/)(\.env[^/]*|id_rsa[^/]*|\.npmrc|\.pypirc|credentials[^/]*|\.ssh/[^/]+)$"),
 ("R11", "manifest_change", "low", r"(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|pyproject\.toml|Cargo\.(toml|lock)|go\.(mod|sum)|Gemfile(\.lock)?)$"),
]
REDACT = re.compile(RISK_RULES[4][3])

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def redact(s):
    return REDACT.sub("[REDACTED-SECRET]", s) if isinstance(s, str) else s

def exit_code(text):
    m = re.search(r"Exit code (\d+)", text or "")
    return int(m.group(1)) if m else None

def result_text(c):
    if isinstance(c, str): return c
    if isinstance(c, list):
        return "\n".join(b.get("text", "") for b in c if isinstance(b, dict))
    return ""

def flags_for_text(text):
    out = []
    for rid, name, sev, rx in RISK_RULES:
        if re.search(rx, text or ""):
            out.append({"rule": rid, "name": name, "severity": sev})
    return out

def flags_for_path(path, cwd):
    out = []
    if path and cwd and not os.path.abspath(path).startswith(os.path.abspath(cwd) + os.sep):
        out.append({"rule": "R9", "name": "out_of_workspace_write", "severity": "medium"})
    for rid, name, sev, rx in PATH_RULES[1:]:
        if path and re.search(rx, path):
            out.append({"rule": rid, "name": name, "severity": sev})
    return out

def unified(old, new, path):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile="a/" + path, tofile="b/" + path, n=2))

def parse(path):
    meta = {"source_format": "claude-code-jsonl", "session_id": None, "cwd": None,
            "agent_version": None, "git_branch": None, "started": None, "ended": None,
            "models": set(), "user_turns": 0}
    events, pending = [], {}
    for line in open(path, encoding="utf-8"):
        try: o = json.loads(line)
        except Exception: continue
        ts = o.get("timestamp")
        if ts:
            meta["started"] = meta["started"] or ts; meta["ended"] = ts
        for k, src in (("session_id", "sessionId"), ("cwd", "cwd"), ("agent_version", "version"), ("git_branch", "gitBranch")):
            if o.get(src) and not meta[k]: meta[k] = o[src]
        msg = o.get("message") or {}
        if o.get("type") == "assistant" and msg.get("model"): meta["models"].add(msg["model"])
        content = msg.get("content")
        if o.get("type") == "user" and isinstance(content, str): meta["user_turns"] += 1
        if not isinstance(content, list): continue
        if o.get("type") == "user" and any(b.get("type") == "text" for b in content if isinstance(b, dict)) \
           and not any(b.get("type") == "tool_result" for b in content if isinstance(b, dict)):
            meta["user_turns"] += 1
        for b in content:
            if not isinstance(b, dict): continue
            if b.get("type") == "tool_use":
                ev = to_event(b, ts, meta["cwd"]); events.append(ev); pending[b.get("id")] = ev
            elif b.get("type") == "tool_result":
                ev = pending.get(b.get("tool_use_id"))
                if not ev: continue
                txt = result_text(b.get("content"))
                code = exit_code(txt)
                failed = bool(b.get("is_error")) or (code is not None and code != 0)
                ev["outcome"] = {"status": "failure" if failed else "success", "exit_code": code,
                                 "output_excerpt": redact(txt[:600])}
    for ev in events:
        ev.setdefault("outcome", {"status": "unknown", "exit_code": None, "output_excerpt": ""})
    meta["models"] = sorted(meta["models"])
    return meta, events

def to_event(b, ts, cwd):
    name, inp = b.get("name", ""), b.get("input") or {}
    ev = {"ts": ts, "tool": name, "kind": "other", "risk_flags": []}
    if name == "Bash":
        cmd = inp.get("command", "")
        ev.update(kind="command", command=redact(cmd), description=inp.get("description"))
        ev["risk_flags"] = flags_for_text(cmd)
    elif name in ("Edit", "MultiEdit", "Write", "NotebookEdit"):
        p = inp.get("file_path") or inp.get("notebook_path") or ""
        if name == "Edit":
            d = unified(inp.get("old_string", ""), inp.get("new_string", ""), p)
        elif name == "MultiEdit":
            d = "".join(unified(e.get("old_string", ""), e.get("new_string", ""), p) for e in inp.get("edits", []))
        elif name == "Write":
            d = unified("", inp.get("content", ""), p)
        else:
            d = unified("", inp.get("new_source", ""), p)
        ev.update(kind="file_change", path=p, diff=redact(d),
                  added=sum(1 for l in d.splitlines() if l.startswith("+") and not l.startswith("+++")),
                  removed=sum(1 for l in d.splitlines() if l.startswith("-") and not l.startswith("---")))
        ev["risk_flags"] = flags_for_path(p, cwd) + flags_for_text(d)
    elif name in ("Read", "Glob", "Grep", "LS"):
        ev.update(kind="read", target=str(inp.get("file_path") or inp.get("pattern") or inp.get("path") or ""))
    elif name in ("WebFetch", "WebSearch"):
        ev.update(kind="network", target=str(inp.get("url") or inp.get("query") or ""))
    else:
        ev.update(target=redact(canon(inp)[:300]))
    return ev

def build(meta, events):
    prev = GENESIS
    for i, ev in enumerate(events):
        ev["seq"] = i
        ev["prev_hash"] = prev
        body = {k: v for k, v in ev.items() if k != "hash"}
        ev["hash"] = prev = sha(prev + canon(body))
    summary = {
        "events": len(events),
        "commands": sum(e["kind"] == "command" for e in events),
        "file_changes": sum(e["kind"] == "file_change" for e in events),
        "files_touched": len({e["path"] for e in events if e["kind"] == "file_change"}),
        "lines_added": sum(e.get("added", 0) for e in events),
        "lines_removed": sum(e.get("removed", 0) for e in events),
        "failures": sum(e["outcome"]["status"] == "failure" for e in events),
        "risk_flags": sum(len(e["risk_flags"]) for e in events),
        "high_risk_events": sum(any(f["severity"] == "high" for f in e["risk_flags"]) for e in events),
    }
    rec = {"schema": SCHEMA_VERSION, "session": meta, "summary": summary, "events": events, "chain_head": prev}
    rec["record_digest"] = sha(canon({k: v for k, v in rec.items() if k != "record_digest"}))
    return rec

CSS = """body{font:14px/1.45 -apple-system,Segoe UI,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1d1d1f}
h1{font-size:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}
.ev{border:1px solid #ddd;border-radius:6px;margin:10px 0;padding:8px}.failure{border-left:5px solid #c62828}.success{border-left:5px solid #2e7d32}
.unknown{border-left:5px solid #9e9e9e}.flag{display:inline-block;background:#fdecea;color:#b71c1c;border-radius:4px;padding:1px 6px;margin-right:4px;font-size:12px}
.flag.medium{background:#fff4e5;color:#8a4b00}.flag.low{background:#eef3fb;color:#1a4d8f}pre{background:#f6f8fa;padding:6px;overflow-x:auto;white-space:pre-wrap;font-size:12px}
.add{color:#1b5e20}.del{color:#b71c1c}.h{color:#777;font-size:11px;word-break:break-all}"""

def render_diff(d):
    out = []
    for l in d.splitlines():
        cls = "add" if l.startswith("+") and not l.startswith("+++") else "del" if l.startswith("-") and not l.startswith("---") else ""
        out.append('<span class="%s">%s</span>' % (cls, html.escape(l)))
    return "<pre>" + "\n".join(out) + "</pre>"

def to_html(rec):
    s, m = rec["summary"], rec["session"]
    rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (html.escape(k), html.escape(str(v))) for k, v in list(m.items()) + list(s.items()))
    evs = []
    for e in rec["events"]:
        flags = "".join('<span class="flag %s">%s %s</span>' % (f["severity"], f["rule"], f["name"]) for f in e["risk_flags"])
        if e["kind"] == "command": body = "<pre>$ %s</pre>" % html.escape(e["command"])
        elif e["kind"] == "file_change": body = "<div>%s (+%d/-%d)</div>%s" % (html.escape(e["path"]), e["added"], e["removed"], render_diff(e["diff"]))
        else: body = "<div>%s</div>" % html.escape(str(e.get("target", "")))
        out = e["outcome"]
        outp = "<details><summary>output (%s, exit=%s)</summary><pre>%s</pre></details>" % (out["status"], out["exit_code"], html.escape(out["output_excerpt"])) if out["output_excerpt"] else ""
        evs.append('<div class="ev %s" id="e%d"><b>#%d %s</b> · %s · %s %s%s%s<div class="h">hash %s</div></div>' % (
            out["status"], e["seq"], e["seq"], html.escape(e["kind"]), html.escape(e["tool"]), html.escape(str(e["ts"])), flags, body, outp, e["hash"]))
    data = canon(rec).replace("</", "<\\/")
    return ("<!doctype html><html><head><meta charset='utf-8'><meta name='s2a-schema' content='%s'>"
            "<meta name='s2a-record-digest' content='%s'><title>S2A audit %s</title><style>%s</style></head><body>"
            "<h1>Session-to-Audit report</h1><table>%s<tr><th>chain_head</th><td class='h'>%s</td></tr></table>"
            "<h2>Events</h2>%s<script type='application/json' id='s2a-record'>%s</script></body></html>") % (
            SCHEMA_VERSION, rec["record_digest"], html.escape(str(m["session_id"])), CSS, rows, rec["chain_head"], "".join(evs), data)

def extract(path):
    t = open(path, encoding="utf-8").read()
    m = re.search(r"<script type='application/json' id='s2a-record'>(.*?)</script>", t, re.S)
    return json.loads(m.group(1).replace("<\\/", "</")), t

def verify_record(rec):
    prev = GENESIS
    for i, ev in enumerate(rec["events"]):
        if ev["seq"] != i or ev["prev_hash"] != prev: return False, "chain broken at event %d" % i
        body = {k: v for k, v in ev.items() if k != "hash"}
        if sha(prev + canon(body)) != ev["hash"]: return False, "hash mismatch at event %d" % i
        prev = ev["hash"]
    if prev != rec["chain_head"]: return False, "chain head mismatch"
    if sha(canon({k: v for k, v in rec.items() if k != "record_digest"})) != rec["record_digest"]:
        return False, "record digest mismatch"
    return True, "ok"

def verify(path):
    rec, text = extract(path)
    ok, why = verify_record(rec)
    if ok and ("content='%s'" % rec["record_digest"]) not in text: return False, "meta digest mismatch"
    return ok, why

if __name__ == "__main__":
    if sys.argv[1] == "convert":
        meta, evs = parse(sys.argv[2]); rec = build(meta, evs)
        open(sys.argv[3], "w", encoding="utf-8").write(to_html(rec)); print(json.dumps(rec["summary"]))
    elif sys.argv[1] == "verify":
        ok, why = verify(sys.argv[2]); print(why); sys.exit(0 if ok else 1)
