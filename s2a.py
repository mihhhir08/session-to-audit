#!/usr/bin/env python3
"""Session-to-Audit (S2A) v0.2 reference implementation.

Converts a coding-agent session log into a self-contained, hash-chained HTML
audit artifact, and verifies such artifacts. Standard library only.

Supported source formats (auto-detected):
  claude-code-jsonl   Claude Code session logs (~/.claude/projects/*/*.jsonl)
  codex-rollout-jsonl OpenAI Codex rollout logs (~/.codex/sessions/**/rollout-*.jsonl)

Usage:
  s2a.py convert <session.jsonl> <out.html>
  s2a.py verify  <artifact.html> [--signers <allowed_signers> --identity <id>]
  s2a.py sign    <artifact.html> <ssh_private_key> <identity>
"""
import json, sys, re, hashlib, html, difflib, os, subprocess, tempfile

SCHEMA_VERSION = "s2a/0.2"
GENESIS = "0" * 64
EXCERPT = 600
SIG_NAMESPACE = "s2a"

# ---------------------------------------------------------------- secrets ---
# Families of credentials redacted before hashing. Each entry: (family, regex).
SECRET_PATTERNS = [
    ("private_key_block", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"),
    ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai_key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"),
    ("stripe_key", r"\b[rs]k_live_[A-Za-z0-9]{20,}\b"),
    ("slack_token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("bearer_header", r"(?<=[Aa]uthorization: [Bb]earer )[A-Za-z0-9._~+/=\-]{20,}"),
    ("url_credentials", r"(?<=://)[^/\s:@\\`'\"\[\]]{1,64}:[^/\s@\\`'\"\[\]]{6,}(?=@)"),
    ("assigned_secret", r"(?i:(?<![A-Za-z0-9])(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|token)[\"']?[ \t]*[:=][ \t]*[\"']?)(?!\[REDACTED|process\.env|Bun\.env|os\.environ|ENV\[|getenv|import\.meta)(?=[A-Za-z0-9_\-+/=.]*\d)[A-Za-z0-9_\-+/=.]{12,}(?![\w(/:])"),
]
SECRET_RX = re.compile("|".join("(?:%s)" % rx for _, rx in SECRET_PATTERNS))
SECRET_PATTERNS_C = [(n, re.compile(rx)) for n, rx in SECRET_PATTERNS]
REDACTED = "[REDACTED-SECRET]"

def has_secret(s):
    return isinstance(s, str) and SECRET_RX.search(s) is not None

ASSIGN_PREFIX = re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|token)[\"']?[ \t]*[:=][ \t]*[\"']?")

def _redact_match(m):
    k = ASSIGN_PREFIX.match(m.group(0))  # keep the variable name, drop only the value
    return (k.group(0) if k else "") + REDACTED

def redact(s):
    return SECRET_RX.sub(_redact_match, s) if isinstance(s, str) else s

def redact_obj(o):
    if isinstance(o, str): return redact(o)
    if isinstance(o, list): return [redact_obj(x) for x in o]
    if isinstance(o, dict): return {k: redact_obj(v) for k, v in o.items()}
    return o

# ------------------------------------------------------------------ rules ---
# Rules were fixed before any annotation was performed (see paper, Sec. VII).
COMMAND_RULES = [
 ("R1", "destructive_fs", "high", r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\b|\bfind\b.*\s-delete\b|\bshred\b|\bmkfs\b|\bdd\s+if="),
 ("R2", "vcs_history_rewrite", "high", r"\bgit\s+push\b.*(--force|\s-f\b)|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+branch\s+-D\b|\bgit\s+checkout\s+--\s"),
 ("R3", "remote_code_exec", "high", r"(curl|wget)[^|;&]*\|\s*(ba|z)?sh\b"),
 ("R4", "privilege_escalation", "high", r"\bsudo\b|\bchmod\s+(-R\s+)?777\b|\bchown\s+-R\b"),
 ("R6", "network_egress", "medium", r"\bcurl\b[^\n]*(-X\s*(POST|PUT|PATCH|DELETE)|--data|-d\s|-F\s)|\bscp\b|\brsync\b[^\n]*:"),
 ("R7", "dependency_install", "medium", r"\b(npm|pnpm|yarn)\s+(i|install|add)\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bnpx\s+\S+"),
 ("R8", "publish_or_deploy", "medium", r"\bgit\s+push\b|\bnpm\s+publish\b|\bvercel\b[^\n]*--prod|\bdocker\s+push\b|\bgh\s+(pr|release)\s+create\b"),
]
# R8 also applies to tool calls whose *name* denotes a publish/deploy side effect.
TOOL_NAME_RULES = [("R8", "publish_or_deploy", "medium", r"(?i)deploy|publish|create_pull_request|create_release|merge_pull_request|push_files|create_or_update_file|github_create_file")]
SENSITIVE_PATH = r"(^|/)(\.env[^/]*|id_rsa[^/]*|id_ed25519[^/]*|\.npmrc|\.pypirc|\.netrc|credentials[^/]*|\.ssh/[^/]+|\.aws/[^/]+)$"
MANIFEST_PATH = r"(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|pyproject\.toml|Cargo\.(toml|lock)|go\.(mod|sum)|Gemfile(\.lock)?|Podfile(\.lock)?|Package\.swift|Package\.resolved)$"
RULE_TABLE = [  # id, name, severity, applies to
 ("R1", "destructive_fs", "high", "command"), ("R2", "vcs_history_rewrite", "high", "command"),
 ("R3", "remote_code_exec", "high", "command"), ("R4", "privilege_escalation", "high", "command"),
 ("R5", "secret_exposure", "high", "any field"), ("R6", "network_egress", "medium", "command"),
 ("R7", "dependency_install", "medium", "command"), ("R8", "publish_or_deploy", "medium", "command, tool name"),
 ("R9", "out_of_workspace_write", "medium", "file change"), ("R10", "sensitive_file_write", "high", "file change"),
 ("R11", "manifest_change", "low", "file change"),
]

def _flag(rid, name, sev): return {"rule": rid, "name": name, "severity": sev}

def flags_for_command(cmd):
    return [_flag(r, n, s) for r, n, s, rx in COMMAND_RULES if re.search(rx, cmd or "")]

def flags_for_path(path, cwd):
    out = []
    if path and cwd and os.path.isabs(path):
        p, c = os.path.normpath(path), os.path.normpath(cwd)
        if p != c and not p.startswith(c.rstrip(os.sep) + os.sep):
            out.append(_flag("R9", "out_of_workspace_write", "medium"))
    if path and re.search(SENSITIVE_PATH, path): out.append(_flag("R10", "sensitive_file_write", "high"))
    if path and re.search(MANIFEST_PATH, path): out.append(_flag("R11", "manifest_change", "low"))
    return out

def flags_for_tool(name):
    return [_flag(r, n, s) for r, n, s, rx in TOOL_NAME_RULES if re.search(rx, name or "")]

def dedupe(flags):
    seen, out = set(), []
    for f in flags:
        if f["rule"] not in seen: seen.add(f["rule"]); out.append(f)
    return out

# ---------------------------------------------------------------- helpers ---
def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def unified(old, new, path):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile="a/" + path, tofile="b/" + path, n=2))

def diff_counts(d):
    lines = d.splitlines()
    return (sum(1 for l in lines if l.startswith("+") and not l.startswith("+++")),
            sum(1 for l in lines if l.startswith("-") and not l.startswith("---")))

def text_of(c):
    if isinstance(c, str): return c
    if isinstance(c, list):
        return "\n".join((b.get("text") or "") for b in c if isinstance(b, dict))
    if isinstance(c, dict): return c.get("text") or c.get("output") or canon(c)
    return ""

def new_event(ts, tool, kind, **kw):
    ev = {"ts": ts, "tool": tool, "kind": kind, "risk_flags": [],
          "outcome": {"status": "unknown", "exit_code": None, "output_excerpt": ""}}
    ev.update(kw)
    return ev

def set_outcome(ev, status, code, text):
    ev["outcome"] = {"status": status, "exit_code": code, "output_excerpt": (text or "")[:EXCERPT]}

def _strings(o):
    if isinstance(o, str): yield o
    elif isinstance(o, dict):
        for v in o.values(): yield from _strings(v)
    elif isinstance(o, list):
        for v in o: yield from _strings(v)

def finalize(ev, cwd, raw_texts=()):
    """Attach risk flags (computed on unredacted text) then redact every string field."""
    fl = list(ev.get("risk_flags", []))
    if ev["kind"] == "command": fl += flags_for_command(ev.get("command", ""))
    if ev["kind"] == "file_change": fl += flags_for_path(ev.get("path", ""), cwd)
    fl += flags_for_tool(ev["tool"])
    # scan the raw string values (not their JSON encoding, whose escaping would hide quoted key/value pairs)
    blob = "\n".join(_strings({k: v for k, v in ev.items() if k != "risk_flags"})) + "\n" + "\n".join(t or "" for t in raw_texts)
    if has_secret(blob):
        fl.append(_flag("R5", "secret_exposure", "high"))
        for m in SECRET_RX.finditer(blob):  # remember the value so later bare reuses are caught too
            v = m.group(0)[len(ASSIGN_PREFIX.match(m.group(0)).group(0)):] if ASSIGN_PREFIX.match(m.group(0)) else m.group(0)
            # propagate only values that are unambiguous credentials: provider formats, bearer tokens and
            # long assigned values; short assigned values and URL passwords are too collision-prone
            fam = next((n for n, rx in SECRET_PATTERNS_C if rx.fullmatch(m.group(0))), None)
            if len(v) >= (24 if fam in ("assigned_secret", "url_credentials", None) else 16): _SEEN.add(v)
    ev["risk_flags"] = dedupe(fl)
    return redact_obj(ev)

# ---------------------------------------------------- Claude Code adapter ---
CC_EDIT = ("Edit", "MultiEdit", "Write", "NotebookEdit")
CC_READ = ("Read", "Glob", "Grep", "LS", "NotebookRead")
CC_NET = ("WebFetch", "WebSearch")
CC_DELEGATE = ("Task", "Agent")

def cc_patch_to_diff(hunks, path):
    out = ["--- a/%s\n" % path, "+++ b/%s\n" % path]
    for h in hunks or []:
        out.append("@@ -%s,%s +%s,%s @@\n" % (h.get("oldStart"), h.get("oldLines"), h.get("newStart"), h.get("newLines")))
        out += [l + "\n" for l in h.get("lines", [])]
    return "".join(out) if len(out) > 2 else ""

def cc_event(b, ts, cwd):
    name, inp = b.get("name", ""), b.get("input") or {}
    if name == "Bash":
        return new_event(ts, name, "command", command=inp.get("command", ""), description=inp.get("description"))
    if name in CC_EDIT:
        p = inp.get("file_path") or inp.get("notebook_path") or ""
        if name == "Edit": d = unified(inp.get("old_string", ""), inp.get("new_string", ""), p)
        elif name == "MultiEdit": d = "".join(unified(e.get("old_string", ""), e.get("new_string", ""), p) for e in inp.get("edits", []))
        elif name == "Write": d = unified("", inp.get("content", ""), p)
        else: d = unified("", inp.get("new_source", ""), p)
        return new_event(ts, name, "file_change", path=p, op="write" if name == "Write" else "edit",
                         diff=d, diff_source="reconstructed_from_input")
    if name in CC_READ:
        return new_event(ts, name, "read", target=str(inp.get("file_path") or inp.get("pattern") or inp.get("path") or ""))
    if name in CC_NET:
        return new_event(ts, name, "network", target=str(inp.get("url") or inp.get("query") or ""))
    if name in CC_DELEGATE:
        return new_event(ts, name, "delegation", target=str(inp.get("description") or inp.get("subagent_type") or "")[:300])
    return new_event(ts, name, "other", target=canon(inp)[:300])

def parse_claude_code(path):
    meta = {"source_format": "claude-code-jsonl", "agent": "claude-code", "session_id": None, "cwd": None,
            "agent_version": None, "git_branch": None, "started": None, "ended": None, "models": set(), "user_turns": 0}
    events, pending = [], {}
    for line in open(path, encoding="utf-8", errors="replace"):
        try: o = json.loads(line)
        except Exception: continue
        if not isinstance(o, dict): continue
        ts = o.get("timestamp")
        if ts: meta["started"] = meta["started"] or ts; meta["ended"] = ts
        for k, src in (("session_id", "sessionId"), ("cwd", "cwd"), ("agent_version", "version"), ("git_branch", "gitBranch")):
            if o.get(src) and not meta[k]: meta[k] = o[src]
        msg = o.get("message") or {}
        if not isinstance(msg, dict): continue
        if o.get("type") == "assistant" and msg.get("model") and not str(msg["model"]).startswith("<"): meta["models"].add(msg["model"])
        content = msg.get("content")
        if o.get("type") == "user" and isinstance(content, str): meta["user_turns"] += 1
        if not isinstance(content, list): continue
        blocks = [b for b in content if isinstance(b, dict)]
        if o.get("type") == "user" and any(b.get("type") == "text" for b in blocks) and not any(b.get("type") == "tool_result" for b in blocks):
            meta["user_turns"] += 1
        for b in blocks:
            if b.get("type") == "tool_use":
                ev = cc_event(b, ts, meta["cwd"]); events.append(ev); pending[b.get("id")] = ev
            elif b.get("type") == "tool_result":
                ev = pending.get(b.get("tool_use_id"))
                if not ev: continue
                txt = text_of(b.get("content"))
                m = re.search(r"Exit code (\d+)", txt or "")
                code = int(m.group(1)) if m else None
                if code is None and ev["kind"] == "command" and not b.get("is_error"): code = 0
                failed = bool(b.get("is_error")) or (code is not None and code != 0)
                set_outcome(ev, "failure" if failed else "success", code, txt)
                tur = o.get("toolUseResult")
                if ev["kind"] == "file_change" and isinstance(tur, dict) and tur.get("structuredPatch") is not None and not failed:
                    d = cc_patch_to_diff(tur.get("structuredPatch"), ev["path"])
                    if not d and tur.get("type") == "create": d = unified("", tur.get("content") or "", ev["path"])
                    if d or tur.get("type") == "update":
                        ev["diff"], ev["diff_source"] = d, "agent_structured_patch"
                    if tur.get("type") in ("create", "update"): ev["op"] = tur["type"]
                    elif tur.get("originalFile") is not None: ev["op"] = "update"
    meta["models"] = sorted(meta["models"])
    return meta, [finalize(e, meta["cwd"]) for e in events], {}

# ---------------------------------------------------------- Codex adapter ---
CODEX_DELEGATE = re.compile(r"spawn_agent|send_message|wait_agent|followup_task|list_agents|interrupt_agent|send_input")
CODEX_READ = ("view_image",)
CODEX_NET = re.compile(r"^(run|web__run|web_search|.*github_(fetch|search|get|list).*)$")

def js_string_at(s, i):
    """Parse a JS string literal starting at s[i]; return (value, end) or (None, i)."""
    if i >= len(s) or s[i] not in "\"'`": return None, i
    q, j, out = s[i], i + 1, []
    esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "\"": "\"", "'": "'", "`": "`", "$": "$", "0": "\0"}
    while j < len(s):
        c = s[j]
        if c == "\\" and j + 1 < len(s):
            n = s[j + 1]
            if n == "u" and re.match(r"[0-9a-fA-F]{4}", s[j + 2:j + 6]): out.append(chr(int(s[j + 2:j + 6], 16))); j += 6; continue
            out.append(esc.get(n, n)); j += 2; continue
        if q == "`" and c == "$" and s[j + 1:j + 2] == "{": return None, i  # interpolated template: not static
        if c == q: return "".join(out), j + 1
        out.append(c); j += 1
    return None, i

def js_value(script, s, i):
    """Resolve a literal, or an identifier bound once to a literal by const/let/var."""
    while i < len(s) and s[i] in " \n\t": i += 1
    v, _ = js_string_at(s, i)
    if v is not None: return v
    m = re.match(r"[A-Za-z_$][\w$]*", s[i:])
    if not m: return None
    binds = re.findall(r"(?:const|let|var)\s+%s\s*=\s*" % re.escape(m.group(0)), script)
    if len(binds) != 1: return None
    k = re.search(r"(?:const|let|var)\s+%s\s*=\s*" % re.escape(m.group(0)), script).end()
    return js_string_at(script, k)[0]

def codemode_calls(script):
    """Statically recover inner tool calls from a Codex code-mode script.
    Returns (calls, unresolved) where calls = [(tool, payload_dict)]."""
    calls, unresolved = [], 0
    for m in re.finditer(r"tools\.(\w+)\(", script):
        tool, k = m.group(1), m.end()
        if tool == "exec_command":
            mm = re.match(r"\s*\{\s*[\"']?cmd[\"']?\s*:\s*", script[k:])
            v = js_value(script, script, k + mm.end()) if mm else None
            wd = re.match(r"[\s\S]{0,4000}?[\"']?workdir[\"']?\s*:\s*", script[k:])
            calls.append((tool, {"cmd": v, "workdir": js_value(script, script, k + wd.end()) if wd else None}))
            unresolved += v is None
        elif tool == "apply_patch":
            mm = re.match(r"\s*(?:\{\s*[\"']?input[\"']?\s*:\s*)?", script[k:])
            v = js_value(script, script, k + mm.end())
            calls.append((tool, {"input": v})); unresolved += v is None
        else:
            calls.append((tool, {}))
    return calls, unresolved

def parse_apply_patch(patch):
    """Split an apply_patch envelope into per-file (op, path, diff)."""
    files, cur = [], None
    for line in (patch or "").splitlines():
        m = re.match(r"\*\*\* (Add|Update|Delete) File: (.+)$", line)
        if m:
            cur = {"op": {"Add": "create", "Update": "update", "Delete": "delete"}[m.group(1)], "path": m.group(2).strip(), "lines": []}
            files.append(cur); continue
        mv = re.match(r"\*\*\* Move to: (.+)$", line)
        if mv and cur: cur["op"] = "move"; cur["to"] = mv.group(1).strip(); continue
        if line.startswith("*** End Patch") or line.startswith("*** Begin Patch") or cur is None: continue
        cur["lines"].append(line)
    out = []
    for f in files:
        body = "\n".join(f["lines"])
        out.append((f["op"], f["path"], "--- a/%s\n+++ b/%s\n%s\n" % (f["path"], f.get("to", f["path"]), body) if body else ""))
    return out

def codex_outcome(txt):
    if txt is None: return "unknown", None
    m = re.search(r"Process exited with code (-?\d+)|^Exit code: (-?\d+)", txt, re.M)
    if m:
        code = int(m.group(1) or m.group(2)); return ("success" if code == 0 else "failure"), code
    if re.match(r"\s*(Script failed|apply_patch verification failed|exec_command failed|write_stdin failed|aborted by user|Internal Error)", txt): return "failure", None
    if re.match(r"\s*(Script completed|\{\"output\":\"Success)", txt): return "success", None
    return "unknown", None

def parse_codex(path):
    meta = {"source_format": "codex-rollout-jsonl", "agent": "codex", "session_id": None, "cwd": None,
            "agent_version": None, "git_branch": None, "started": None, "ended": None, "models": set(),
            "user_turns": 0, "originator": None, "thread_source": None}
    events, pending, procs = [], {}, {}
    stats = {"codemode_scripts": 0, "codemode_inner_calls": 0, "codemode_unresolved": 0, "stdin_polls_folded": 0}
    for line in open(path, encoding="utf-8", errors="replace"):
        try: o = json.loads(line)
        except Exception: continue
        if not isinstance(o, dict): continue
        ts, typ, p = o.get("timestamp"), o.get("type"), o.get("payload") or {}
        if ts: meta["started"] = meta["started"] or ts; meta["ended"] = ts
        if not isinstance(p, dict): continue
        if typ == "session_meta":
            meta["session_id"] = meta["session_id"] or p.get("id"); meta["cwd"] = meta["cwd"] or p.get("cwd")
            meta["agent_version"] = meta["agent_version"] or p.get("cli_version"); meta["originator"] = p.get("originator")
            src = p.get("source"); meta["thread_source"] = src if isinstance(src, str) else "subagent"
            g = p.get("git") or {}
            if isinstance(g, dict) and g.get("branch"): meta["git_branch"] = g["branch"]
            continue
        if typ == "turn_context":
            if p.get("model"): meta["models"].add(p["model"])
            meta["cwd"] = meta["cwd"] or p.get("cwd"); continue
        pt = p.get("type")
        if typ != "response_item": continue
        if pt == "message" and p.get("role") == "user":
            t = text_of(p.get("content"))
            if t and not t.lstrip().startswith("<"): meta["user_turns"] += 1
            continue
        if pt == "web_search_call":
            a = p.get("action") or {}
            events.append(new_event(ts, "web_search", "network", target=str(a.get("query") or a.get("url") or "")[:300]))
            continue
        if pt in ("function_call", "custom_tool_call"):
            name, cid = p.get("name", ""), p.get("call_id")
            if pt == "function_call":
                try: args = json.loads(p.get("arguments") or "{}")
                except Exception: args = {"raw": p.get("arguments")}
            else:
                args = {"input": p.get("input")}
            if not isinstance(args, dict): args = {"raw": args}
            evs = []
            if name in ("exec_command", "shell", "local_shell"):
                cmd = args.get("cmd") or args.get("command")
                if isinstance(cmd, list): cmd = " ".join(map(str, cmd))
                evs.append(new_event(ts, name, "command", command=cmd or "", workdir=args.get("workdir")))
            elif name == "write_stdin":
                chars = args.get("chars") or ""
                if not chars:
                    pending[cid] = ("poll", args.get("session_id")); stats["stdin_polls_folded"] += 1; continue
                evs.append(new_event(ts, name, "command", command=chars, stdin_to=args.get("session_id")))
            elif name == "apply_patch":
                for op, fp, d in parse_apply_patch(args.get("input") or args.get("patch") or ""):
                    evs.append(new_event(ts, name, "file_change", path=fp, op=op, diff=d, diff_source="agent_patch"))
                if not evs: evs.append(new_event(ts, name, "file_change", path="", op="unknown", diff="", diff_source="unparsed"))
            elif name == "exec":
                stats["codemode_scripts"] += 1
                script = args.get("input") or ""
                inner, unres = codemode_calls(script)
                stats["codemode_inner_calls"] += len(inner); stats["codemode_unresolved"] += unres
                for tool, pl in inner:
                    if tool == "exec_command":
                        evs.append(new_event(ts, "exec>exec_command", "command", command=pl["cmd"] if pl["cmd"] is not None else "",
                                             workdir=pl.get("workdir"), via="code_mode", statically_resolved=pl["cmd"] is not None))
                    elif tool == "apply_patch":
                        parts = parse_apply_patch(pl["input"]) if pl["input"] else []
                        for op, fp, d in parts:
                            evs.append(new_event(ts, "exec>apply_patch", "file_change", path=fp, op=op, diff=d,
                                                 diff_source="agent_patch", via="code_mode", statically_resolved=True))
                        if not parts:
                            evs.append(new_event(ts, "exec>apply_patch", "file_change", path="", op="unknown", diff="",
                                                 diff_source="unresolved", via="code_mode", statically_resolved=False))
                if not inner:
                    evs.append(new_event(ts, "exec", "other", target=script[:300], via="code_mode", statically_resolved=False))
            elif name == "wait":
                pending[cid] = ("wait", None); continue
            elif CODEX_DELEGATE.search(name):
                evs.append(new_event(ts, name, "delegation", target=canon(args)[:300]))
            elif name in CODEX_READ:
                evs.append(new_event(ts, name, "read", target=str(args.get("path") or "")))
            elif CODEX_NET.match(name) or p.get("namespace") == "web":
                evs.append(new_event(ts, name, "network", target=canon(args)[:300]))
            else:
                evs.append(new_event(ts, name, "other", target=canon(args)[:300]))
            events.extend(evs); pending[cid] = ("events", evs)
            continue
        if pt in ("function_call_output", "custom_tool_call_output"):
            entry = pending.get(p.get("call_id"))
            if not entry: continue
            txt = text_of(p.get("output"))
            if isinstance(p.get("output"), str):
                try:
                    j = json.loads(p["output"])
                    if isinstance(j, dict) and "output" in j:
                        md = j.get("metadata") or {}
                        txt = ("Exit code: %s\n" % md["exit_code"] if "exit_code" in md else "") + str(j["output"])
                except Exception: pass
            status, code = codex_outcome(txt)
            sid = re.search(r"Process running with session ID (\d+)", txt or "")
            kind, val = entry
            if kind == "poll":  # fold a polling read into the command that owns the process
                owner = procs.get(str(val))
                if owner is not None and status != "unknown": set_outcome(owner, status, code, txt)
                continue
            if kind == "wait": continue
            for ev in val:
                if ev.get("via") == "code_mode":
                    # A script's success says nothing about each inner call. An outcome is attributed only when
                    # the script made exactly one inner call and the output names one unambiguous result.
                    # either the tool's own text, or the script printing the structured result object
                    codes = re.findall(r"Process exited with code (-?\d+)|\"exit_code\"\s*:\s*(-?\d+)", txt or "")
                    codes = [a or b for a, b in codes]
                    if len(val) == 1 and len(codes) == 1:
                        c = int(codes[0]); set_outcome(ev, "success" if c == 0 else "failure", c, txt)
                    elif len(val) == 1 and status == "failure": set_outcome(ev, status, code, txt)
                    elif len(val) == 1 and ev["kind"] == "file_change" and "Success. Updated the following files" in (txt or ""):
                        set_outcome(ev, "success", None, txt)
                    else: ev["outcome"]["output_excerpt"] = (txt or "")[:EXCERPT]
                else:
                    set_outcome(ev, status, code, txt)
                if sid and ev["kind"] == "command": procs[sid.group(1)] = ev
    meta["models"] = sorted(meta["models"])
    return meta, [finalize(e, meta["cwd"]) for e in events], stats

# ----------------------------------------------------------- dispatch -------
def detect_format(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for _, line in zip(range(50), f):
            try: o = json.loads(line)
            except Exception: continue
            if isinstance(o, dict) and o.get("type") in ("session_meta", "response_item", "turn_context") and "payload" in o:
                return "codex-rollout-jsonl"
            if isinstance(o, dict) and ("sessionId" in o or o.get("type") in ("user", "assistant", "summary")):
                return "claude-code-jsonl"
    return "claude-code-jsonl"

_SEEN = set()  # secret values matched anywhere in the session being parsed

def propagate(o, vals):
    """Second redaction pass: a value once recognised as a secret is redacted wherever it reappears,
    e.g. a token first seen in an Authorization header and later assigned to a bare shell variable."""
    if isinstance(o, str):
        for v in vals:
            if v in o: o = o.replace(v, REDACTED)
        return o
    if isinstance(o, list): return [propagate(x, vals) for x in o]
    if isinstance(o, dict): return {k: propagate(v, vals) for k, v in o.items()}
    return o

def parse(path):
    _SEEN.clear()
    fmt = detect_format(path)
    meta, events, stats = parse_codex(path) if fmt == "codex-rollout-jsonl" else parse_claude_code(path)
    vals = sorted(_SEEN, key=len, reverse=True)
    stats = dict(stats, propagated_redactions=0)
    if vals:
        for i, ev in enumerate(events):
            body = {k: v for k, v in ev.items() if k != "risk_flags"}
            new = propagate(body, vals)
            if new != body:
                stats["propagated_redactions"] += 1
                new["risk_flags"] = dedupe(ev["risk_flags"] + [_flag("R5", "secret_exposure", "high")])
                events[i] = new
        meta = propagate(meta, vals)
    _SEEN.clear()
    return meta, events, stats

# ------------------------------------------------------------- record -------
def build(meta, events):
    meta = redact_obj(meta)
    prev = GENESIS
    for i, ev in enumerate(events):
        ev["seq"] = i
        ev["prev_hash"] = prev
        if ev["kind"] == "file_change":
            ev["added"], ev["removed"] = diff_counts(ev.get("diff", ""))
        body = {k: v for k, v in ev.items() if k != "hash"}
        ev["hash"] = prev = sha(prev + canon(body))
    kinds = {}
    for e in events: kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    summary = {
        "events": len(events), "by_kind": kinds,
        "files_touched": len({e["path"] for e in events if e["kind"] == "file_change" and e.get("path")}),
        "lines_added": sum(e.get("added", 0) for e in events),
        "lines_removed": sum(e.get("removed", 0) for e in events),
        "failures": sum(e["outcome"]["status"] == "failure" for e in events),
        "unknown_outcomes": sum(e["outcome"]["status"] == "unknown" for e in events),
        "risk_flags": sum(len(e["risk_flags"]) for e in events),
        "high_risk_events": sum(any(f["severity"] == "high" for f in e["risk_flags"]) for e in events),
    }
    rec = {"schema": SCHEMA_VERSION, "session": meta, "summary": summary, "events": events, "chain_head": prev}
    rec["record_digest"] = sha(canon({k: v for k, v in rec.items() if k != "record_digest"}))
    return rec

# --------------------------------------------------------------- render -----
CSS = """body{font:14px/1.45 -apple-system,Segoe UI,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1d1d1f}
h1{font-size:20px}h2{font-size:16px;margin-top:22px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}
.ev{border:1px solid #ddd;border-radius:6px;margin:10px 0;padding:8px}.failure{border-left:5px solid #c62828}.success{border-left:5px solid #2e7d32}
.unknown{border-left:5px solid #9e9e9e}.flag{display:inline-block;background:#fdecea;color:#b71c1c;border-radius:4px;padding:1px 6px;margin-right:4px;font-size:12px}
.flag.medium{background:#fff4e5;color:#8a4b00}.flag.low{background:#eef3fb;color:#1a4d8f}pre{background:#f6f8fa;padding:6px;overflow-x:auto;white-space:pre-wrap;font-size:12px}
.add{color:#1b5e20}.del{color:#b71c1c}.h{color:#777;font-size:11px;word-break:break-all}.tag{font-size:11px;color:#555;background:#eee;border-radius:3px;padding:0 4px}"""

def render_diff(d):
    out = []
    for l in d.splitlines():
        cls = "add" if l.startswith("+") and not l.startswith("+++") else "del" if l.startswith("-") and not l.startswith("---") else ""
        out.append('<span class="%s">%s</span>' % (cls, html.escape(l)))
    return "<pre>" + "\n".join(out) + "</pre>"

def to_html(rec):
    s, m = rec["summary"], rec["session"]
    rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (html.escape(k), html.escape(str(v))) for k, v in list(m.items()) + list(s.items()))
    flagged = [e for e in rec["events"] if e["risk_flags"]]
    failed = [e for e in rec["events"] if e["outcome"]["status"] == "failure"]
    def idx(lst):
        return " ".join('<a href="#e%d">#%d</a>' % (e["seq"], e["seq"]) for e in lst[:500]) or "none"
    evs = []
    for e in rec["events"]:
        flags = "".join('<span class="flag %s">%s %s</span>' % (f["severity"], f["rule"], f["name"]) for f in e["risk_flags"])
        via = ' <span class="tag">via %s%s</span>' % (html.escape(e["via"]), "" if e.get("statically_resolved", True) else ", unresolved") if e.get("via") else ""
        if e["kind"] == "command": body = "<pre>$ %s</pre>" % html.escape(e.get("command", ""))
        elif e["kind"] == "file_change": body = "<div>%s %s (+%d/-%d) <span class='tag'>%s</span></div>%s" % (
            html.escape(e.get("op", "")), html.escape(e.get("path", "")), e.get("added", 0), e.get("removed", 0), html.escape(e.get("diff_source", "")), render_diff(e.get("diff", "")))
        else: body = "<div>%s</div>" % html.escape(str(e.get("target", "")))
        out = e["outcome"]
        outp = "<details><summary>output (%s, exit=%s)</summary><pre>%s</pre></details>" % (out["status"], out["exit_code"], html.escape(out["output_excerpt"])) if out["output_excerpt"] else ""
        evs.append('<div class="ev %s" id="e%d"><b>#%d %s</b> · %s · %s%s %s%s%s<div class="h">prev %s<br>hash %s</div></div>' % (
            out["status"], e["seq"], e["seq"], html.escape(e["kind"]), html.escape(e["tool"]), html.escape(str(e["ts"])), via, flags, body, outp, e["prev_hash"], e["hash"]))
    data = canon(rec).replace("</", "<\\/")
    return ("<!doctype html><html><head><meta charset='utf-8'><meta name='s2a-schema' content='%s'>"
            "<meta name='s2a-record-digest' content='%s'><title>S2A audit %s</title><style>%s</style></head><body>"
            "<h1>Session-to-Audit report</h1><p class='h'>Integrity: run <code>s2a.py verify</code> on this file. "
            "Without a valid signature this report proves integrity, not authorship.</p><table>%s<tr><th>chain_head</th><td class='h'>%s</td></tr>"
            "<tr><th>record_digest</th><td class='h'>%s</td></tr></table>"
            "<h2>Risk-flagged events (%d)</h2><p>%s</p><h2>Failed events (%d)</h2><p>%s</p>"
            "<h2>Timeline</h2>%s<script type='application/json' id='s2a-record'>%s</script></body></html>") % (
            SCHEMA_VERSION, rec["record_digest"], html.escape(str(m["session_id"])), CSS, rows, rec["chain_head"], rec["record_digest"],
            len(flagged), idx(flagged), len(failed), idx(failed), "".join(evs), data)

# --------------------------------------------------------------- verify -----
RECORD_RX = re.compile(r"<script type='application/json' id='s2a-record'>(.*?)</script>", re.S)
SIG_RX = re.compile(r"<script type='application/s2a-signature' id='s2a-signature' data-identity='([^']*)'>(.*?)</script>", re.S)

def extract(path):
    t = open(path, encoding="utf-8").read()
    m = RECORD_RX.search(t)
    if not m: raise ValueError("no embedded S2A record")
    return json.loads(m.group(1).replace("<\\/", "</")), t

def verify_record(rec):
    prev = GENESIS
    for i, ev in enumerate(rec["events"]):
        if ev.get("seq") != i or ev.get("prev_hash") != prev: return False, "chain broken at event %d" % i
        body = {k: v for k, v in ev.items() if k != "hash"}
        if sha(prev + canon(body)) != ev.get("hash"): return False, "hash mismatch at event %d" % i
        prev = ev["hash"]
    if prev != rec.get("chain_head"): return False, "chain head mismatch"
    if sha(canon({k: v for k, v in rec.items() if k != "record_digest"})) != rec.get("record_digest"):
        return False, "record digest mismatch"
    return True, "ok"

def _ssh(args, data):
    return subprocess.run(["ssh-keygen", "-Y"] + args, input=data.encode(), capture_output=True)

def verify_signature(text, digest, signers, identity):
    m = SIG_RX.search(text)
    if not m: return False, "no signature present"
    if identity and m.group(1) != identity: return False, "signature identity mismatch"
    with tempfile.NamedTemporaryFile("w", suffix=".sig", delete=False) as f: f.write(m.group(2).strip() + "\n"); sig = f.name
    try:
        r = _ssh(["verify", "-f", signers, "-I", m.group(1), "-n", SIG_NAMESPACE, "-s", sig], digest)
    finally: os.unlink(sig)
    return (r.returncode == 0), ("signature ok (%s)" % m.group(1) if r.returncode == 0 else "signature invalid")

def verify(path, signers=None, identity=None):
    rec, text = extract(path)
    ok, why = verify_record(rec)
    if not ok: return ok, why
    if ("<meta name='s2a-record-digest' content='%s'>" % rec["record_digest"]) not in text: return False, "meta digest mismatch"
    if signers: return verify_signature(text, rec["record_digest"], signers, identity)
    return True, "ok (integrity only; unsigned or signature not checked)"

def sign(path, key, identity):
    rec, text = extract(path)
    ok, why = verify_record(rec)
    if not ok: raise SystemExit("refusing to sign an artifact that fails verification: " + why)
    r = _ssh(["sign", "-f", key, "-n", SIG_NAMESPACE], rec["record_digest"])
    if r.returncode != 0: raise SystemExit(r.stderr.decode())
    text = SIG_RX.sub("", text)
    tag = "<script type='application/s2a-signature' id='s2a-signature' data-identity='%s'>%s</script>" % (html.escape(identity, quote=True), r.stdout.decode().strip())
    open(path, "w", encoding="utf-8").write(text.replace("</body></html>", tag + "</body></html>"))

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a: sys.exit(__doc__)
    if a[0] == "convert":
        meta, evs, _ = parse(a[1]); rec = build(meta, evs)
        open(a[2], "w", encoding="utf-8").write(to_html(rec)); print(json.dumps(rec["summary"]))
    elif a[0] == "verify":
        signers = a[a.index("--signers") + 1] if "--signers" in a else None
        ident = a[a.index("--identity") + 1] if "--identity" in a else None
        ok, why = verify(a[1], signers, ident); print(why); sys.exit(0 if ok else 1)
    elif a[0] == "sign":
        sign(a[1], a[2], a[3]); print("signed")
    else:
        sys.exit(__doc__)
