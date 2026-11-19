# Session-to-Audit (S2A)

**Verifiable, shareable audit records for AI coding-agent sessions: diffs, commands, failures and risk flags.**

AI coding agents run shell commands, edit files, install packages and push code. A pull request shows the final diff. It does not show the failed commands, the overwritten files, the writes outside the repository or the credentials that passed through the session. That evidence lives in vendor-specific session logs that can reach hundreds of megabytes and that nobody reads.

S2A turns a coding-agent session into one portable HTML file that:

- **a person can read** in any browser, offline, with no special tools: every command, diff, failure and risk flag, in order
- **a machine can verify**: the file embeds a canonical, SHA-256 hash-chained JSON record, so an edited, deleted, inserted or reordered event is detected
- **can be signed**: the record digest can carry an OpenSSH (SSHSIG) signature, which stops someone who rewrites the file and recomputes the chain
- **is safer to share**: credentials are redacted before hashing, so a published artifact verifies without containing them, and the file contains no executable script

This repository is the reference implementation for the paper *"Session-to-Audit: Verifiable, Shareable Audit Records for AI Coding-Agent Sessions (Diffs, Commands, Failures, Risk Flags)"* by Mihirsinh Chavda (preprint forthcoming).

## Quick start

Requires Python 3.9+ and nothing else (standard library only). Signing needs `ssh-keygen` (OpenSSH 8.0+).

```bash
# convert a session log into an audit artifact (the source format is auto-detected)
python3 s2a.py convert examples/demo_session.jsonl demo.html

# verify integrity (exit code 0 = ok, 1 = modified)
python3 s2a.py verify demo.html

# sign the record digest with an SSH key, then verify integrity and signature
python3 s2a.py sign demo.html ~/.ssh/id_ed25519 you@example.com
python3 s2a.py verify demo.html --signers allowed_signers --identity you@example.com
```

Open `demo.html` in a browser. `examples/demo_session.html` is a pre-built copy. The demo session is **fictional** and was written by hand to exercise the schema; it contains no real project data.

### Supported agents

| Agent | Log location | Source format |
|---|---|---|
| Claude Code | `~/.claude/projects/<project>/<session-id>.jsonl` | `claude-code-jsonl` |
| OpenAI Codex | `~/.codex/sessions/**/rollout-*.jsonl` | `codex-rollout-jsonl` |

Codex "code mode" runs actions inside model-written scripts. S2A recovers the inner calls statically and marks them `via: code_mode`. Their outcome stays `unknown` unless the log makes it unambiguous, because a script-level status says nothing reliable about each inner call.

## The record

| Field | Content |
|---|---|
| `schema` | Version identifier (`s2a/0.2`) |
| `session` | Source format, agent and version, session id, working directory, branch, models, start/end time, user turns |
| `summary` | Counts by kind, files touched, lines added/removed, failures, unknown outcomes, risk flags, high-risk events |
| `events[]` | Ordered, typed, hash-chained events, each with its risk flags (rule ID, name, severity) |
| `chain_head`, `record_digest` | Final chain hash; SHA-256 of the canonical record |

**Event kinds:** `command`, `file_change` (path, operation, unified diff, line counts and a `diff_source` saying where the diff came from), `read`, `network`, `delegation` (sub-agents and spawned tasks), `other`.

Each event has an `outcome` with a status of `success`, `failure` or `unknown`, the exit code when available, and a redacted output excerpt of at most 600 characters. `unknown` is a first-class value: an adapter reports success only when the log supports it.

Model reasoning and user prompts are left out by design. S2A records what the agent **did**, not what it **said**. Full field-level details are in [`docs/schema.md`](docs/schema.md).

## Risk flags

Deterministic rules that point a reviewer's attention. They are pointers, not verdicts.

| ID | Name | Severity | Example trigger |
|---|---|---|---|
| R1 | destructive_fs | high | `rm -rf`, `find -delete`, `dd if=` |
| R2 | vcs_history_rewrite | high | `git push --force`, `git reset --hard` |
| R3 | remote_code_exec | high | `curl ... \| sh` |
| R4 | privilege_escalation | high | `sudo`, `chmod 777` |
| R5 | secret_exposure | high | credential pattern in any recorded field |
| R6 | network_egress | medium | `curl -X POST`, `scp` |
| R7 | dependency_install | medium | `npm install`, `npx pkg` |
| R8 | publish_or_deploy | medium | `git push`; deploy and pull-request tools |
| R9 | out_of_workspace_write | medium | file written outside the session directory |
| R10 | sensitive_file_write | high | `.env*`, SSH keys, `.npmrc` |
| R11 | manifest_change | low | package manifests, lockfiles |

## Integrity and authenticity

With canonical JSON `C` (sorted keys, compact, UTF-8), all hashes hex-encoded and genesis `h_-1` = 64 zero characters:

```
h_i = SHA-256( h_{i-1} || C(event_i without its hash) )
```

The verifier recomputes every link, the chain head and the record digest, and checks the digest against the `<meta name="s2a-record-digest">` tag.

An unsigned chain only catches accidental corruption and naive edits: anyone with write access can recompute it. `s2a.py sign` signs the `record_digest` with `ssh-keygen -Y sign` under the namespace `s2a` and embeds the signature in a non-executable element. `verify --signers` then checks it against an `allowed_signers` file. The digest works just as well with Sigstore or an in-toto attestation.

## Redaction

Every string field passes through a redactor before hashing. Twelve pattern families: private-key blocks, AWS access key IDs, GitHub classic and fine-grained tokens, Anthropic, OpenAI, Stripe, Slack and Google API keys, JWTs, bearer headers, credentials in URLs, and values assigned to credential-named keys. A second pass propagates: a value recognized as a credential anywhere in the session is redacted wherever it reappears. Redaction is pattern-based, so a credential in an unknown format can still get through. Review an artifact before you publish it.

## Reproducing the evaluation

All scripts print or write **aggregate statistics only**, never session content.

```bash
# corpus statistics, outcome determinacy, tampering trials, real-log redaction check
python3 evaluate.py /tmp/s2a_out --corpus CC='~/.claude/projects/**/*.jsonl' --corpus CX='~/.codex/sessions/**/rollout-*.jsonl'

# seeded redaction conformance test (synthetic credentials only)
python3 redaction_test.py 20

# conversion and verification timing
python3 bench.py /tmp/bench.json CC='~/.claude/projects/**/*.jsonl'

# compare against the v0.1 implementation
python3 compare_v01.py path/to/v0.1/s2a.py '~/.claude/projects/**/*.jsonl'
```

`NAME=GLOB[:EXCLUDE]` skips paths containing `EXCLUDE`.

## Results from the paper

97 real sessions from one developer (13,651 tool events, 853 MB of logs) in three settings: Claude Code (CC, 12 sessions), Codex (CX, 52) and Claude Agent SDK agents run by a desktop multi-agent assistant (OR, 33). Aggregates are in [`results/v0.2_results.json`](results/v0.2_results.json).

| Metric | Result |
|---|---|
| Events typed into audit kinds | 86.6% (CC), 93.9% (CX) |
| Artifact size vs raw log, logs over 50 KB (median) | 3.0% to 6.9% |
| Conversion of a 245 MB log | about 1.8 s |
| Naive tampering trials detected | 2,280 / 2,280 |
| Adaptive forgeries (chain recomputed) rejected by signature | 304 / 304 |
| Seeded synthetic credentials leaked | 0 / 2,260 |
| Provider-format credentials in the real logs left in artifacts | 0 / 6 |
| Claude Code file edits whose line counts changed when using the agent's structured patch | 21.2% |
| Codex actions run in code mode | 57.3% |
| Code-mode outcomes that could not be attributed | 93.4% (vs 18.5% for direct calls) |

The risk rules were assessed on 335 sampled events labeled by two LLM annotators and an LLM adjudicator (no human labels). The rules are mostly right about **what** an action is (category precision 0.71, weighted by how often each rule fires) but poor at deciding what deserves attention (0.27 review-worthy). The rubric is in [`docs/annotation_rubric.md`](docs/annotation_rubric.md). Per-item texts are not released.

`results/pilot_results.json` holds the earlier v0.1 pilot (Claude Code only) and is kept for reference.

Raw session logs and per-item annotation texts are not published because they contain private project content and paths.

## Limitations

- All sessions come from one developer, so the rates may not generalize.
- Risk-flag labels come from LLM annotators, not human experts, and there is no reviewer study yet.
- Codex code-mode outcomes are mostly unknown. That is a property of the logs, which S2A reports rather than guesses around.
- When an agent log has no structured patch, the diff is reconstructed from tool input (`diff_source: reconstructed_from_input`), which treats a whole-file write as pure addition. Check `diff_source` before trusting line counts.
- Redaction is pattern-based.

## Citation

```
M. Chavda, "Session-to-Audit: Verifiable, Shareable Audit Records for AI Coding-Agent
Sessions (Diffs, Commands, Failures, Risk Flags)," preprint, 2026.
```

## License

MIT
