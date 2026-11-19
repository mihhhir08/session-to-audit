# Session-to-Audit (S2A)

**A schema and single-file HTML artifact for verifiable AI coding sessions: diffs, commands, failures and risk flags.**

AI coding agents run shell commands, edit files, install packages and push code. Code review only sees the final diff. The evidence of what the agent actually did lives in vendor-specific session logs that can be hundreds of megabytes and that nobody reads.

S2A turns a coding-agent session into one portable HTML file that:

- **a human can read** in any browser, offline, with no tooling: every command, every diff, every failure, every risk flag, in order
- **a machine can verify**: the file embeds a canonical, SHA-256 hash-chained JSON record, so any edited, deleted or reordered event is detected
- **is safe to share**: common secret patterns are redacted before hashing, and the file contains no executable script

This repository is the reference implementation for the paper *"Session-to-Audit HTML as a Standard Artifact: A Schema for Verifiable AI Coding Sessions (Diffs, Commands, Failures, Risk Flags)"* by Mihirsinh Chavda (preprint forthcoming).

## Quick start

Requires Python 3.9+ and nothing else (standard library only).

```bash
# convert a session log into an audit artifact
python3 s2a.py convert examples/demo_session.jsonl demo.html

# verify an artifact has not been modified (exit code 0 = ok, 1 = tampered)
python3 s2a.py verify demo.html
```

Open `demo.html` in a browser. `examples/demo_session.html` is a pre-built copy. The demo session is **fictional** and was written by hand to exercise every part of the schema.

Claude Code stores session logs as JSON Lines files under `~/.claude/projects/<project>/<session-id>.jsonl`.

## What goes into an artifact

| Field | Content |
|---|---|
| `schema` | Version identifier (`s2a/0.1`) |
| `session` | Session id, working directory, agent version, git branch, models, start/end time, user turns |
| `summary` | Counts of events, commands, file changes, files touched, lines added/removed, failures, risk flags, high-risk events |
| `events[]` | Ordered, typed, hash-chained events |
| `chain_head`, `record_digest` | Final chain hash and SHA-256 digest of the canonical record |

**Event kinds:** `command` (shell command), `file_change` (path + unified diff), `read` (file or search), `network` (URL or web query), `other`.
Each event has an `outcome`: `success`, `failure` (tool error or non-zero exit code) or `unknown`, plus the exit code and a short redacted output excerpt.

Model reasoning and chat text are deliberately left out. S2A records what the agent **did**, not what it **said**.

## Risk flags (v0.1)

Deterministic rules that point a reviewer's attention. They are heuristics, not verdicts.

| ID | Name | Severity | Example trigger |
|---|---|---|---|
| R1 | destructive_fs | high | `rm -rf`, `find -delete` |
| R2 | vcs_history_rewrite | high | `git push --force`, `git reset --hard` |
| R3 | remote_code_exec | high | `curl ... \| sh` |
| R4 | privilege_escalation | high | `sudo`, `chmod 777` |
| R5 | secret_exposure | high | API-key / private-key patterns |
| R6 | network_egress | medium | `curl -X POST`, `scp` |
| R7 | dependency_install | medium | `npm install`, `pip install` |
| R8 | publish_or_deploy | medium | `git push`, `npm publish` |
| R9 | out_of_workspace_write | medium | file written outside the session directory |
| R10 | sensitive_file_write | high | `.env`, SSH keys, `.npmrc` |
| R11 | manifest_change | low | `package.json`, lockfiles |

## Integrity model

With canonical JSON serialization `C` (sorted keys, compact, UTF-8) and genesis `h_-1 = 0^256`:

```
h_i = SHA-256( h_{i-1} || C(event_i without its hash) )
```

The verifier recomputes every link, the chain head and the record digest, and checks the digest against the `<meta name="s2a-record-digest">` tag.

**Important:** an unsigned hash chain detects accidental corruption and naive edits. Someone with write access to the file can regenerate a consistent chain. For authenticity, anchor the 32-byte `record_digest` somewhere the agent cannot rewrite, such as a commit trailer, a CI log, a trusted timestamp or a signed attestation. Anchoring is not part of v0.1.

## Pilot evaluation

`evaluate.py` reproduces the paper's pilot numbers on your own sessions. It prints **aggregate statistics only**, never session content.

```bash
python3 evaluate.py /tmp/s2a_out                        # all sessions in ~/.claude/projects
python3 evaluate.py /tmp/s2a_out ~/.claude/projects foo  # skip project folders containing "foo"
```

Pilot results from the paper (12 of the author's Claude Code sessions, Sep to Nov 2026, Apple M2): `results/pilot_results.json`.

| Metric | Result |
|---|---|
| Tool events | 5,608 |
| Typed into audit categories | 86.5% |
| Artifact size vs raw log (median) | 5.5% |
| Conversion time (median / max) | 46 ms / 1.09 s (245 MB log) |
| Verification time (median) | 5.9 ms |
| Tampering trials detected | 200 / 200 |
| Failed tool calls surfaced | 141 |
| High-severity risk events | 128 |

Raw session logs are not published because they contain private project content.

## Limitations

- One adapter so far (Claude Code). Other agents need their own adapter that emits the same event structure.
- Risk-flag precision and recall have not been measured yet. For example, `rm -rf node_modules` triggers R1 even though it is usually harmless.
- Whole-file writes are recorded as additions, so lines removed is undercounted when a file is overwritten.
- Redaction is pattern-based and can miss secrets in unknown formats.

## Roadmap

- Labeled precision/recall for every risk rule
- Adapters for more coding agents, plus a conformance test suite
- Signed attestations over `record_digest`
- A `ui_action` event kind for browser-automation tools

## Citation

```
M. Chavda, "Session-to-Audit HTML as a Standard Artifact: A Schema for Verifiable
AI Coding Sessions (Diffs, Commands, Failures, Risk Flags)," preprint, 2026.
```

## License

MIT
