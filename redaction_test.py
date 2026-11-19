#!/usr/bin/env python3
"""Seeded redaction benchmark for S2A.

Synthesises format-valid (but random, non-functional) credentials of every supported family,
injects each one into every field an artifact can carry (command, file content, tool output,
network target, session metadata) for both adapters, converts, and checks that
(a) the credential string never appears in the artifact and (b) the event carries R5.
It also checks a fixed list of benign look-alikes that must NOT be redacted.
Usage: redaction_test.py [trials_per_family]
"""
import json, os, random, string, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s2a

R = random.Random(2026)
A = string.ascii_letters + string.digits
def rs(n, alpha=A): return "".join(R.choice(alpha) for _ in range(n))
def b64url(n): return rs(n, A + "-_")

GEN = {
 "private_key_block": lambda: "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n%s\n-----END OPENSSH PRIVATE KEY-----" % (rs(64, A + "+/"), rs(40, A + "+/")),
 "aws_access_key": lambda: "AKIA" + rs(16, string.ascii_uppercase + string.digits),
 "github_token": lambda: R.choice(["ghp_", "gho_", "ghs_"]) + rs(36),
 "github_fine_grained": lambda: "github_pat_" + rs(22) + "_" + rs(59),
 "anthropic_key": lambda: "sk-ant-api03-" + b64url(80),
 "openai_key": lambda: "sk-proj-" + b64url(48),
 "stripe_key": lambda: "sk_live_" + rs(24),
 "slack_token": lambda: "xoxb-" + rs(11, string.digits) + "-" + rs(12, string.digits) + "-" + rs(24),
 "google_api_key": lambda: "AIza" + b64url(35),
 "jwt": lambda: "eyJ" + b64url(30) + ".eyJ" + b64url(40) + "." + b64url(43),
 "bearer_header": lambda: "Authorization: Bearer " + b64url(40),
 "url_credentials": lambda: "postgres://admin:%s@db.internal:5432/app" % rs(16),
 "assigned_secret": lambda: "DB_PASSWORD=" + rs(10) + str(R.randint(10, 99)) + rs(4),
 "json_token_field": lambda: '{"url": "https://git.example.org/r.git", "token": "%s%d%s"}' % (rs(8), R.randint(10, 99), rs(30)),
}
# the substring that must disappear (for header/url/assignment families only the secret part)
def secret_part(fam, s):
    if fam == "bearer_header": return s.split("Bearer ", 1)[1]
    if fam == "url_credentials": return s.split("admin:", 1)[1].split("@", 1)[0]
    if fam == "assigned_secret": return s.split("=", 1)[1]
    if fam == "json_token_field": return s.split('"token": "', 1)[1][:-2]
    if fam == "private_key_block": return s.splitlines()[1]
    return s

BENIGN = [
 "pip install scikit-learn task-runner-abcdefghijklmnopqrstu", "risk-assessment-framework-module-v2-final",
 "password: string;", "const apiKey = process.env.OPENAI_API_KEY", "let apiKey = Bun.env.ANTHROPIC_API_KEY",
 "api_key = os.environ['API_KEY']", "const token = await getAccessToken(session)", "https://github.com/octo/repo.git",
 "postgres://localhost:5432/app", "-----BEGIN PUBLIC KEY-----", "Authorization: Bearer ${TOKEN}",
 "git checkout 3f9c2a1b7d4e5f60718293a4b5c6d7e8f9012345", "id=550e8400-e29b-41d4-a716-446655440000",
 "AKIA_PLACEHOLDER", "sk-test", "ghp_xxx", "export PASSWORD_MIN_LENGTH=12", "secretKey: z.string().min(1)",
 "accessToken?: string | null", '"max_tokens": 5000', '"token_count": 42', '{"token": "<your-token>"}', ".env.example:3:SUPABASE_SECRET_KEY=\nsrc/lib/auth.ts:22: if (!env)", "AIzaSy (truncated example)", "eyJhbGciOiJIUzI1NiJ9 header only",
]

def cc_session(secret_text, benign=False):
    sid = "seeded"; cwd = "/work/app"
    def L(o): o.update(sessionId=sid, cwd=cwd, version="test", timestamp="2026-01-01T00:00:00Z"); return json.dumps(o)
    U = lambda c: L({"type": "user", "message": {"role": "user", "content": c}})
    A_ = lambda c: L({"type": "assistant", "message": {"role": "assistant", "model": "m", "content": c}})
    tu = lambda i, n, inp: {"type": "tool_use", "id": i, "name": n, "input": inp}
    tr = lambda i, t: {"type": "tool_result", "tool_use_id": i, "content": t}
    lines = [U("go"),
             A_([tu("1", "Bash", {"command": "echo " + secret_text})]), U([tr("1", "ok")]),
             A_([tu("2", "Write", {"file_path": cwd + "/config.txt", "content": "x\n" + secret_text + "\n"})]), U([tr("2", "written")]),
             A_([tu("3", "Bash", {"command": "cat config.txt"})]), U([tr("3", "value: " + secret_text)]),
             A_([tu("4", "WebFetch", {"url": "https://example.org/?q=" + secret_text.replace("\n", " ")})]), U([tr("4", "page")])]
    return "\n".join(lines) + "\n", ["command", "file_content", "tool_output", "network_target"]

def cx_session(secret_text):
    rows = [{"type": "session_meta", "payload": {"id": "seeded", "cwd": "/work/app", "cli_version": "test", "source": "vscode"}},
            {"type": "turn_context", "payload": {"model": "m", "cwd": "/work/app"}}]
    def call(cid, name, args, out, custom=False):
        if custom: rows.append({"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": cid, "name": name, "input": args}})
        else: rows.append({"type": "response_item", "payload": {"type": "function_call", "call_id": cid, "name": name, "arguments": json.dumps(args)}})
        rows.append({"type": "response_item", "payload": {"type": ("custom_tool_call_output" if custom else "function_call_output"), "call_id": cid, "output": out}})
    call("1", "exec_command", {"cmd": "echo " + secret_text}, "Process exited with code 0\nOutput:\nok")
    patch = "*** Begin Patch\n*** Add File: /work/app/config.txt\n" + "".join("+" + l + "\n" for l in ("x\n" + secret_text).splitlines()) + "*** End Patch"
    call("2", "apply_patch", patch, json.dumps({"output": "Success.", "metadata": {"exit_code": 0}}), custom=True)
    call("3", "exec_command", {"cmd": "cat config.txt"}, "Process exited with code 0\nOutput:\nvalue: " + secret_text)
    call("4", "exec", "text(await tools.exec_command({cmd:%s}));" % json.dumps("echo " + secret_text), "Script completed\nProcess exited with code 0", custom=True)
    return "\n".join(json.dumps(dict(r, timestamp="2026-01-01T00:00:00Z")) for r in rows) + "\n", ["command", "file_content", "tool_output", "code_mode_command"]

def run_one(builder, text):
    d = tempfile.mkdtemp(); src = os.path.join(d, "s.jsonl"); open(src, "w").write(builder(text)[0])
    meta, evs, _ = s2a.parse(src); rec = s2a.build(meta, evs); return s2a.to_html(rec), rec

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    res = {}
    for fam, g in GEN.items():
        tot = leaked = flagged = 0
        for _ in range(n):
            s = g(); part = secret_part(fam, s)
            for builder in (cc_session, cx_session):
                h, rec = run_one(builder, s)
                sites = builder(s)[1]
                tot += len(sites)
                # count leaks per injection site by checking the event that carries it
                leaked += sum(1 for e in rec["events"] if part in s2a.canon(e))
                leaked += (part in h and not any(part in s2a.canon(e) for e in rec["events"]))
                flagged += sum(1 for e in rec["events"] if any(f["rule"] == "R5" for f in e["risk_flags"]))
        res[fam] = {"injections": tot, "leaked_events": leaked, "events_flagged_R5": flagged}
    # propagation: a token first recognised in a header, later reused bare (no keyword, no known prefix)
    prop_tot = prop_leak = 0
    for _ in range(n):
        tok = b64url(43)
        def both(_t, tok=tok):
            return cc_session("x")[0].replace('"echo x"', json.dumps('curl -H "Authorization: Bearer %s" https://api.example.org/v1' % tok), 1) \
                .replace('"cat config.txt"', json.dumps("T=%s; curl -H \"Authorization: Bearer $T\" -d @f https://api.example.org" % tok), 1), []
        h, rec = run_one(both, "")
        prop_tot += 1; prop_leak += tok in h
    res["propagated_bare_reuse"] = {"injections": prop_tot, "leaked_events": prop_leak, "events_flagged_R5": None}
    fp = []
    for b in BENIGN:
        for builder in (cc_session, cx_session):
            h, rec = run_one(builder, b)
            if s2a.REDACTED in h: fp.append(b)
    out = {"trials_per_family": n, "families": res,
           "total_injections": sum(v["injections"] for v in res.values()),
           "total_leaks": sum(v["leaked_events"] for v in res.values()),
           "benign_strings": len(BENIGN), "benign_wrongly_redacted": sorted(set(fp))}
    print(json.dumps(out, indent=1))

if __name__ == "__main__":
    main()
