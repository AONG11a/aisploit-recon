# Task prompt — continue AISploit-Recon (paste into a coding agent)

> Copy everything in the fenced block below into a fresh AI coding session that
> has read/write access to this repository. It is self-contained.

```
You are continuing work on AISploit-Recon, an AUTHORIZED black-box scanner for
LLM security weaknesses (prompt injection, jailbreak, system-prompt / data
leakage) in web apps. Python 3.11+. You have full read/write access to the repo.

STEP 0 — READ FIRST (do not skip):
- AI_HANDOFF.md ............ current status, what's done, backlog, gotchas
- docs/DESIGN.md ........... the design spec you will implement (D1–D9, each has
  problem → approach → concrete changes with file anchors → acceptance → rollback)
- docs/ARCHITECTURE.md, README.md ...... how the pieces fit
- docs/SECURITY_REVIEW.md, docs/AUTHORIZATION.md, docs/PAYLOAD_AUTHORING.md

ALREADY DONE (do NOT redo): D9 (SSRF/private-range guard), D8 (signature
normalization + re:/word: indicators), D7 (Thai/locale refusal packs), plus lint
(UP017) and DL-001 tightening. Verify they pass, then build on them.

YOUR TASK — implement the remaining designs from docs/DESIGN.md, IN THIS ORDER,
one at a time, each fully finished (code + mock + tests + green suite) before the
next:
  1. D1  Baseline-diff detection            (P0 — kills a false-positive class)
  2. D4  Repeat-and-confirm                  (P0 — determinism)
  3. D5  Repro artifact + request manifest   (P0/P1 — also persists severity/score)
  4. D3  Streaming transport (SSE/NDJSON)    (P1 — streaming targets silently
                                              return zero findings today)
  5. D2  Multi-turn probes                   (P1 — biggest capability gap)
  6. D6  Auth capture command (aisploit login)
Follow the concrete changes and acceptance criteria in docs/DESIGN.md exactly.

HARD CONSTRAINTS (non-negotiable):
- SAFETY: nothing may send a byte before ScopeGuard.assert_in_scope. Keep
  fail-closed scope, dry-run-by-default, and ship NO working jailbreak payloads.
- BACKWARD COMPATIBLE: new schema fields are OPTIONAL; existing single-`template`
  payloads and ALL existing tests must keep passing unchanged.
- ADDITIVE + FLAG-GATED: gate new behaviour behind config flags/defaults that
  preserve today's behaviour where the design says so. DB migrations are additive
  only (CREATE ... IF NOT EXISTS, nullable columns, guarded ALTER TABLE) so old
  evidence DBs keep working.
- DETECTION PHILOSOPHY: deterministic detectors first; a non-refusal is NEVER
  auto-escalated to VULNERABLE (INCONCLUSIVE instead).

DEFINITION OF DONE for EACH design (all required):
1. Implement the code per docs/DESIGN.md.
2. Extend the mock target (tests/fixtures/mock_ai_app/app.py) with the ground-
   truth toggle the design names: D1→ECHO mode, D4→INTERMITTENT mode, D3→a
   streaming SSE route, D2→a 2-turn CONVERSATION route.
3. Add unit AND integration tests for the acceptance criteria, INCLUDING negative
   paths (e.g. baseline echo target must NOT yield a high-confidence canary hit).
4. Everything green: `pytest -q`, `ruff check src tests`, `mypy src` (strict).
   Fix all failures — do not disable checks.
5. Update AI_HANDOFF.md: move the item to "Implemented", update the backlog, and
   append a dated change-log entry.
6. Commit with a conventional message, e.g.
   `feat(detection): D1 baseline-diff + ECHO mock + tests`.

VERIFY FOR REAL: actually run the test suite and paste the summary. Do not claim
tests pass without running them.

ENVIRONMENT:
- `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev,judge]"`
- `playwright install chromium` only for the Playwright transport / D6.
- If httpx picks up a SOCKS proxy from the env and integration tests hang, run
  with `NO_PROXY=127.0.0.1,localhost` or `pip install socksio`.

PER-DESIGN PITFALLS (read the design too):
- D1: establish ONE baseline per campaign (benign control message + a distinct
  CONTROL_ token) after transport.setup(); if the target reflects that token,
  penalise canary hits (INCONCLUSIVE or confidence ×0.4) with a note. Do not
  break existing canary tests (non-echo vuln target still VULNERABLE ≥0.95).
- D4: only re-probe when the first verdict is VULNERABLE and confirm_trials>1;
  respect the rate limiter; downgrade to INCONCLUSIVE if the policy (majority/
  any/all) isn't met; record per-trial outcomes. Default confirm_trials=1 must
  equal today's behaviour.
- D5: add ProbeResponse.request_manifest (method/url/headers/body/response_path),
  REDACT auth headers via utils.crypto.redact before persisting; add nullable
  evidence columns request_json/severity/score; render a copy-paste `curl` repro
  in the MD/HTML reports; golden-file + redaction tests.
- D3: add HttpConfig.stream + stream_format/stream_delta_path/done sentinel; use
  client.stream(), assemble `data:` JSON deltas until the sentinel; fall back to
  .json() when not streaming; cap max bytes. A streaming target must now produce
  the same findings as the non-stream route.
- D2: add optional Payload.turns (exactly one of template/turns); canary may sit
  in any turn; add Transport.send_conversation with a default that sends turns
  sequentially and returns the last response; evaluate detection on the final
  response. Existing single-`template` payloads must be byte-for-byte unchanged.
- D6: `aisploit login --target <url> --out auth/state.json` launches non-headless
  Playwright, waits for the operator, saves storage_state. Interactive: a smoke
  test that the command wires up is enough.

OPTIONAL (if time) — clear these from the AI_HANDOFF.md backlog:
- Wire the mutators into the scan flow (add Payload.mutators, apply AFTER canary
  substitution; never mutate the {canary} token) OR mark them experimental.
- Move ScopeGuard construction inside cli.py's try/except (clean expired-auth exit).
- Verify/pin config.settings.judge_model to a real model id.
- Make llm_judge JSON parsing defensive (float/bool inside the try).
- Validate at registry load that a `canary`-detection payload contains `{canary}`.
- Rewrite test_rate_limiter_enforces_ceiling to actually assert throttling.
- Make playwright a `[browser]` extra + lazy-import it in cli.py.
- Delete the duplicate root copies of ARCHITECTURE/IMPLEMENTATION_PLAN/SECURITY_REVIEW.

When done: summarise what changed, paste the `pytest`/`ruff`/`mypy` output, and
list the commits. Ask before any `git push`.
```
