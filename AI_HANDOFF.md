# AI Handoff — AISploit-Recon

A running handoff for the next session (AI or human). It records **verified
state**, **what changed**, the **open backlog**, and **how to pick up**. Keep it
short and current; append a dated entry each session.

---

## Snapshot

- **Version:** 1.0.0 · **Branch:** `main` · **Last update:** 2026-07-15 (session 5)
- **Overall:** solid, well-documented v1. Clean architecture (transport /
  detection / reporting are swappable). Safety posture (fail-closed scope,
  dry-run default, no bundled bypass kit) is sound.
- **Session 1:** full code review + claim verification + `docs/DESIGN.md` + this file.
- **Session 2:** implemented **D9, D8, D7** from `docs/DESIGN.md` (+ tests).
- **Session 3 / 3b:** implemented **D1** (baseline-diff) and **D4**
  (repeat-and-confirm); fixed pre-existing mypy/ruff debt.
- **Session 4:** finished the half-done **D2 (multi-turn probes)** WIP and — for
  the first time — **ran the real suite to green** (`pytest`/`ruff`/`mypy --strict`).
- **Session 5 (this one):** committed **D2** (`d25d389`); implemented **D3
  streaming** (SSE/NDJSON assembly) — streaming targets are now scanned instead
  of silently returning zero findings. 66 tests green, ruff + mypy --strict clean.

### Implemented so far (from docs/DESIGN.md)
- **D5 — Reproduction manifest + repro** ✅ (session 5, core) `ProbeResponse.request_manifest`
  captured by HTTP + Playwright drivers with auth **masked at capture**; flows
  `resp → Finding → report`. Report gains a `repro` (`curl` for HTTP, step-list
  for Playwright); evidence DB gains a `request_json` column (guarded
  `ALTER TABLE`). `severity`/`severity_score` were already persisted (backlog #9
  is DONE). Tests: 6 unit (`test_repro_manifest.py`) + 1 integration proving the
  auth token never reaches the manifest or report. D5b (export/diff/CI-gate) = P2, TODO.
- **D3 — Streaming transport (SSE/NDJSON)** ✅ (session 5) `HttpConfig.stream`
  (+ `stream_format`, `stream_delta_path`, `stream_done_sentinel`,
  `stream_max_chars`). `HttpDriver.send` → `_send_streaming`/`_assemble_stream`
  reads `text/event-stream` (or NDJSON), extracts each chunk's delta and
  concatenates to the full message; non-stream path unchanged. Closes the
  silent zero-findings-on-streaming-targets gap. Example
  `examples/transport.sse.json`. 2 integration tests vs the mock `/chat/stream`.
- **D2 — Multi-turn / conversational probes** ✅ (session 4) `Payload` now takes
  either `template` (single-shot) or `turns: list[str]` (multi-turn); a
  model-validator enforces exactly-one and ≥2 turns. `requires_canary`/`body_text`
  span both shapes. New `ConversationRequest` + `Transport.send_conversation`;
  shared fallback `send_turns_sequentially` replays turns via single-shot `send`
  (used by both HTTP + Playwright drivers). `HttpDriver` also does *native*
  multi-turn via `HttpConfig.conversation_endpoint` + `{turns}` placeholder.
  `Campaign` branches to multi-turn in plan/probe/confirm. Library:
  `multi_turn.yaml` (MT-001 canary, MT-002 persona→signature). Tests: 11 unit
  (`test_multi_turn.py`) + 4 integration. Also fixed a latent bug: `llm_judge`
  used `payload.template` (None for multi-turn) → now `payload.body_text`.
- **D4 — Repeat-and-confirm** ✅ `ScopeRule.confirm_trials` (default 1) +
  `confirm_policy` (majority|any|all). When a candidate VULNERABLE verdict
  appears and `confirm_trials > 1`, the campaign re-probes N-1 more times and
  applies the policy, downgrading to INCONCLUSIVE with per-trial reasoning if
  unsatisfied. Mock extended with `AISPLOIT_MOCK_INTERMITTENT=1` mode (fires
  ~1-in-3). 3 integration tests (majority→INCONCLUSIVE, any→VULNERABLE,
  default=1 unchanged).
- **D1 — Baseline-diff detection** ✅ `core/baseline.py` sends a benign control
  probe with a `CONTROL_<hex>` token after `transport.setup()`. If the target
  echoes it, canary hits are downgraded to INCONCLUSIVE (confidence x0.4) with a
  `baseline_delta` note. Flag `baseline_diff: true` on `ScopeRule` (default on).
  Mock extended with `AISPLOIT_MOCK_ECHO=1` mode. 7 unit + 2 integration tests.
- **D9 — SSRF / private-range destination guard** ✅ `core/scope_guard.py`
  now refuses loopback / RFC-1918 / link-local / multicast / reserved IPs,
  `localhost`, and cloud-metadata FQDNs (`metadata.google.internal`, …) unless
  `allow_private_destinations: true`. Uses the field you added to `ScopeRule`.
  Tests added (`tests/unit/test_scope_guard.py`). Logic verified 11/11.
- **D8 — Signature detector hardening** ✅ `detection/signature.py` now NFKC-
  normalizes, strips zero-width chars, collapses whitespace, casefolds; and
  supports `re:<pattern>` (regex) and `word:<term>` (whole-word) indicators
  alongside plain substrings. Tests added. Logic verified 9/9.
- **D7 — Thai/locale refusal packs** ✅ `detection/heuristic.py` refactored to
  locale packs; **Thai** refusals now recognised (default `("en","th")`).
  Patterns are NFKC-normalized so Thai combining-mark ordering matches. Tests
  added. Logic verified 6/6.

### Verification status (updated session 4 — RESOLVED)
The real suite now runs green. Session 4 stood up a genuine interpreter in the
sandbox (via `uv`, on a non-mounted path) and ran everything end-to-end:

- **`pytest`: 64 passed** (52 unit + 12 integration), incl. all new D2 tests and
  a backward-compat check that single-shot `PI-001` still fires.
- **`ruff check src tests`: clean.**
- **`mypy src` (`--strict`): clean, 36 files.**

Two environment gotchas worth knowing (neither is a code bug):
1. **httpx + SOCKS proxy.** The integration tests hit a local mock; if the shell
   exports `ALL_PROXY=socks5h://…`, httpx tries to route `127.0.0.1` through it
   and every integration test errors with a `socksio` ImportError. `no_proxy`
   was *not* honoured for `ALL_PROXY`. Fix: `unset *_PROXY` (or `pip install
   httpx[socks]`). Confirmed root cause, not a scanner bug.
2. **`test_rate_limiter_enforces_ceiling` blocks ~60s.** `RateLimiter(1)` refills
   1 token/60s, so the 2nd `acquire()` genuinely sleeps ~60s. It passes but makes
   the suite look hung at ~50/64. This is backlog #6 — rewrite it to use a small
   capacity with a fast refill and assert real throttling in <1s.

---

## Bug / defect backlog

**Done (by you, in parallel)**
- ✅ `ruff` UP017 in test files (`timezone.utc` → `datetime.UTC`) — applied.
- ✅ DL-001 over-broad `"@"` success indicator — tightened.
- ✅ `ScopeRule.allow_private_destinations` field added (D9 now enforces it).

**Should-fix (still open)**
1. ✅ **DONE (session 5).** ~~Mutators are dead code.~~ Wired: `Payload.mutators`
   field + a validator that rejects mutator+`{canary}` conflicts; `apply_mutators`
   runs in `Campaign.plan()`, `_probe_one`, and `_confirm`. Tests prove application
   in the planner and on the wire (`test_mutators_*`). Documented in
   `docs/PAYLOAD_AUTHORING.md`. (No weaponised mutated payload is shipped — by design.)
2. **Expired-auth CLI crash is ugly.** `cli.py:98` constructs `ScopeGuard(...)`
   *before* the `try/except` (starts ~`cli.py:120`); expired auth → raw
   traceback + exit 1 instead of "SCOPE VIOLATION" + exit 2. Move into the try.
3. **`judge_model` default looks invalid.** `config/settings.py` + `.env.example`
   set `claude-sonnet-4-6`; verify against the current model list and pin a valid
   string, else `--judge` fails at the API.
4. **LLM-judge parsing is fragile.** `detection/llm_judge.py` runs
   `float(confidence)` / `bool(compromised)` *outside* the try/except: non-numeric
   `confidence` raises uncaught; `bool("false")` is `True`. Parse defensively.
5. **No load-time check that a `canary` payload contains `{canary}`.** Missing
   placeholder → runtime `ERROR`. Validate in `PayloadRegistry._load_file` / a
   `Payload` model validator (fail loud on load).

**Nice-to-fix / robustness**
6. **`test_rate_limiter_enforces_ceiling` asserts nothing meaningful**
   (`elapsed >= 0`). Rewrite to assert a burst-exhausted bucket blocks.
7. **Playwright driver only catches `PwTimeout`**; other errors escape as campaign
   errors instead of a graceful `ProbeResponse(error=…)` like the HTTP driver.
8. **Duplicate docs.** `ARCHITECTURE.md` / `IMPLEMENTATION_PLAN.md` /
   `SECURITY_REVIEW.md` exist identically at repo root *and* `docs/`. Delete the
   root copies.
9. ✅ **DONE.** ~~Evidence DB omits severity/score~~ — now persisted, plus a
   `request_json` manifest column (D5). Originally: recomputed at
   report time; blocks severity-based purge/diff. (Covered by DESIGN D5.)
10. **`playwright` is a hard core dep + imported at CLI top** (`cli.py`); HTTP-only
    users must install the browser stack to run `--help`. `[browser]` extra +
    lazy import (mirrors `[judge]`).

**Security review tracks:** F-1 (evidence at rest), F-2 (creds/keyring), F-3
(SSRF — **now implemented as D9**), F-4 (judge egress consent), F-5 (markdown
fence-breakout).

---

## Forward design (what to build next)

See **`docs/DESIGN.md`**. Remaining, priority order:

- **P0 credibility:** D1 baseline-diff · D4 repeat-and-confirm · D5 repro +
  request manifest.
- **P1 reach:** D3 streaming (SSE/NDJSON) · D6 auth capture · D2 multi-turn probes.
- **P2 adoption:** D5b platform export / run-diff / CI-gate · import adapters.

Biggest single capability gap: **multi-turn probes (D2)** — schema is single-shot.
Biggest silent-failure risk: **streaming targets (D3)** return zero findings today.

## Next actions (top of stack)

0. **Commit the D2 work** (staged, not committed — see git-lock note). Suggested:
   `git add -A && git commit -m "feat(detection): D2 multi-turn probes + native/ sequential conversation transport + tests"`
1. Implement **D5 repro/manifest** (also closes backlog #9, severity in DB) — now
   the top remaining P0 credibility item.
2. Wire or quarantine the **mutators** (backlog #1) — still dead code.
3. Rewrite **`test_rate_limiter_enforces_ceiling`** (backlog #6) so the suite
   isn't 60s-bound; then stand up CI (plan E1) now that the suite is green.
4. Implement **D3 streaming (SSE/NDJSON)** — the mock already has a `/chat/stream`
   route and `AISPLOIT_MOCK_STREAM`; biggest silent-failure risk on real targets.
5. Consider MT-002 (persona→signature) coverage: only MT-001 (canary) has an
   integration test; add a signature-detection multi-turn assertion.

---

## Environment & repro notes

- **Python ≥3.11 required** (`datetime.UTC`). `python -m venv .venv && pip install
  -e ".[dev,judge]"`; then `pytest`, `ruff check src tests`, `mypy src`.
- **Integration tests + restricted networks:** if `httpx` picks up a SOCKS proxy
  from the env, install `socksio` or run with `NO_PROXY=127.0.0.1,localhost`
  (environment artifact, not a code bug).
- **Sandbox mount caveat (session 2):** the agent sandbox did not reflect in-place
  file edits in its bash view, so `pytest`-in-sandbox ran stale copies. Canonical
  files (what you see in the repo) are correct; verification was done via
  standalone logic scripts. Always run the real suite locally.
- **`playwright install chromium`** only needed for the Playwright transport.
- **Stale git lock:** if git refuses to commit, remove `.git/index.lock` first
  (`del .git\index.lock` on Windows).

---

## Change log

- **2026-07-15 (session 5, cont.)** — Confirmed + tested **mutator wiring**
  (backlog #1, already wired in the D2 refactor): added planner + on-the-wire
  tests and `PAYLOAD_AUTHORING.md` docs. No weaponised payloads shipped. 74 tests
  green (ex-60s rate-limiter), ruff + mypy --strict clean.

- **2026-07-15 (session 5, cont.)** — Implemented **D5 core** (repro manifest):
  drivers capture a redacted request manifest (auth masked at source); reports
  render a `curl`/step-list repro; evidence DB persists `request_json`. Redaction
  proven by test (token never leaks). 73 tests green, ruff + mypy --strict clean.

- **2026-07-15 (session 5)** — Post-D2 roadmap. **Committed D2** (`d25d389`).
  Implemented **D3 streaming**: `HttpDriver` now assembles SSE/NDJSON deltas so
  streaming chat APIs are scanned instead of silently yielding zero findings
  (biggest false-negative risk). 66 tests (was 64), ruff + mypy --strict clean.

- **2026-07-15 (session 4)** — Finished the uncommitted **D2 (multi-turn)** WIP.
  Closed the gaps that blocked it: (a) `PlaywrightDriver` didn't implement
  `send_conversation`, so it no longer satisfied the `Transport` protocol
  (mypy `arg-type` error at `cli.py`); added it. (b) Replaced the
  monkey-patched `ConversationMixin` with a shared `send_turns_sequentially`
  helper (removed a `type: ignore`). (c) Fixed a `no-any-return` in
  `_build_conversation_body` (typed `cast`). (d) `llm_judge` used
  `payload.template` (None for multi-turn) → `payload.body_text`. (e) Tidied a
  stale `ConversationMixin` doc-comment. **First green run of the real suite:**
  64 pytest passed, ruff clean, mypy --strict clean. Not committed (git mount is
  read-restricted this session; a stale `.git/index.lock` is present and could
  not be unlinked from the sandbox — remove it before committing).
- **2026-07-14 (session 3)** — Fixed pre-existing mypy/ruff errors that session 2
  never caught (playwright type annotations, pipeline `assert_never`, scheduler
  `BaseException` narrowing, CLI return types, llm_judge block iteration,
  logging cast, generator sort key, ssrf set comprehension). All 37 existing
  tests green under real `pytest` + `ruff` + `mypy` (strict). Implemented **D1**
  (baseline-diff detection): `core/baseline.py` + `CanaryDetector.detect(baseline=)`
  + `DetectionPipeline.evaluate(baseline=)` + `Campaign._establish_baseline()`.
  Echoing targets now downgrade canary hits to INCONCLUSIVE (confidence x0.4).
  Mock extended with `AISPLOIT_MOCK_ECHO` mode + SSE/conversation routes (D3/D2
  prep). 7 new unit tests + 2 integration tests. 46 tests total, all green.
- **2026-07-14 (session 3b)** — Implemented **D4** (repeat-and-confirm):
  `ScopeRule.confirm_trials` + `confirm_policy` + `Campaign._confirm()` method
  re-probes VULNERABLE candidates, applies majority/any/all policy, downgrades
  to INCONCLUSIVE with reproduction rate reasoning. Mock extended with
  `AISPLOIT_MOCK_INTERMITTENT=1` mode. 3 integration tests. 49 tests total.
- **2026-07-14 (session 2)** — Implemented **D9** (SSRF/private-range guard,
  `core/scope_guard.py`), **D8** (signature normalization + `re:`/`word:`
  indicators, `detection/signature.py`), **D7** (Thai/locale refusal packs,
  `detection/heuristic.py`). Added unit tests for each
  (`tests/unit/test_scope_guard.py`, `tests/unit/test_detectors.py`). Verified
  each via standalone logic scripts (D9 11/11, D8 9/9, D7 6/6); full `pytest`
  pending a real 3.11+ env. No behavioural change to existing detectors for
  existing payloads.
- **2026-07-14 (session 1)** — Review pass. Verified 25/25 tests + ruff(src).
  Logged defects + 5 tracked security findings. Added `docs/DESIGN.md` and this
  handoff. No source changes.
