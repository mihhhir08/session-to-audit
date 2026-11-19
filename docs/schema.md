# S2A record schema (s2a/0.2)

This is the field-level reference for the record embedded in every S2A artifact. The artifact embeds it as canonical JSON (sorted keys, compact separators, UTF-8) in a non-executable `<script type="application/json">` element. `examples/demo_session.html` shows a complete record.

## Top level

| Field | Type | Content |
|---|---|---|
| `schema` | string | `"s2a/0.2"` |
| `session` | object | See below |
| `summary` | object | See below |
| `events` | array | Ordered events, see below |
| `chain_head` | hex string | Hash of the last event (genesis value if there are no events) |
| `record_digest` | hex string | SHA-256 of the canonical record without `record_digest`; mirrored in `<meta name="s2a-record-digest">` |

## `session`

`source_format` (`claude-code-jsonl` or `codex-rollout-jsonl`), `agent`, `agent_version`, `session_id`, `cwd`, `git_branch`, `models` (list), `started`, `ended` (ISO 8601), `user_turns` (count). All strings are redacted.

## `summary`

`events`, `by_kind` (count per kind), `files_touched`, `lines_added`, `lines_removed`, `failures`, `unknown_outcomes`, `risk_flags` (total flags), `high_risk_events` (events with at least one high-severity flag).

## Events

Common fields on every event:

| Field | Content |
|---|---|
| `seq` | 0-based position |
| `ts` | Timestamp from the source log |
| `tool` | Originating tool name |
| `kind` | `command`, `file_change`, `read`, `network`, `delegation` or `other` |
| `outcome` | `{status, exit_code, output_excerpt}`; `status` is `success`, `failure` or `unknown`; `output_excerpt` holds at most 600 redacted characters |
| `risk_flags` | List of `{rule, name, severity}` |
| `prev_hash`, `hash` | Chain links (see below) |
| `via`, `statically_resolved` | Present on Codex code-mode inner calls: `via: "code_mode"` and whether arguments were resolved statically |

Kind-specific payloads:

| Kind | Fields |
|---|---|
| `command` | `command`; `description` (Claude Code) or `workdir` (Codex) when available |
| `file_change` | `path`, `op` (`create`, `update`, `delete`, `move`, unresolved `edit`/`write`, or `unknown`), `diff` (unified), `added`, `removed`, `diff_source` |
| `read` | `target` (path or search pattern) |
| `network` | `target` (URL or query) |
| `delegation` | `target`: sub-agent or spawned task description (truncated) |
| `other` | `target`: canonical tool input, truncated to 300 characters and redacted |

`diff_source` is one of `agent_patch` (the agent's own structured patch or patch envelope), `reconstructed_from_input`, `unresolved` (a code-mode patch whose arguments could not be resolved statically) or `unparsed` (a patch call S2A could not parse).

## Hash chain

```
h_-1 = "0" * 64
event_i.prev_hash = h_{i-1}
h_i = SHA-256( h_{i-1} || C(event_i without "hash") )     # hex strings concatenated, UTF-8
chain_head = h_{n-1}
```

`C` is canonical JSON. A verifier recomputes every link, `chain_head` and `record_digest`, and compares the digest with the meta tag. `s2a.py verify` is the reference verifier.

## Signature

`s2a.py sign` runs `ssh-keygen -Y sign -n s2a` over `record_digest` and embeds the armored signature in `<script type="application/s2a-signature" data-identity="...">`. `s2a.py verify --signers <allowed_signers> --identity <id>` checks integrity first, then the signature.
