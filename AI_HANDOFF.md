# AI Handoff — AISploit-Recon

A running handoff for the next session (AI or human). It records **verified
state**, **what changed**, the **open backlog**, and **how to pick up**. Keep it
short and current; append a dated entry each session.

---

## Snapshot

- **Version:** 1.0.0 · **Branch:** `main` · **Last update:** 2026-07-14 (session 2)
- **Overall:** solid, well-documented v1. Clean architecture (transport /
  detection / reporting are swappable). Safety posture (fail-closed scope,
  dry-run default, no bundled bypass kit) is sound.
- **Session 1:** full code review + claim verification + `docs/DESIGN.md` + this file.
- **Session 2:** implemented **D9, D8, D7** from `docs/DESIGN.md` (+ tests).
  Verified by standalone logic scripts (see caveat); full `pytest` still to be
  run locally.

### Implemented so far (from docs/DESIGN.md)
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

### Verification caveat (important)
The review/impl sandbox could **not** run the real `pytest` suite reliably: its
mounted-filesystem view did not reflect in-place file edits, so imports/tests ran
against stale copies. Each change above was instead verified with **standalone
logic scripts** that replicate the exact algorithm (no dependency on the mount).
**Action for next session / you:** run the real suite locally to confirm:
`pytest -q` (Python ≥3.11). All new code is plain stdlib + existing deps.

---

## Bug / defect backlog

**Done (by you, in parallel)**
- ✅ `ruff` UP017 in test files (`timezone.utc` → `datetime.UTC`) — applied.
- ✅ DL-001 over-broad `"@"` success indicator — tightened.
- ✅ `ScopeRule.allow_private_destinations` field added (D9 now enforces it).

**Should-fix (still open)**
1. **Mutators are dead code.** `payloads/mutators.py` is implemented + property-
   tested but never used in a scan: no `mutators` field on `Payload` and
   `scheduler._probe_one` never calls `apply_mutators`. Wire in (add schema
   field, apply after canary substitution — guard against mutating a `{canary}`
   token) or mark explicitly experimental.
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
9. **Evidence DB omits severity/score** (`evidence/store.py`) — recomputed at
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

1. **Run `pytest` locally** to confirm D9/D8/D7 (sandbox couldn't — see caveat).
2. Implement **D1 baseline-diff** + mock `ECHO` mode (kills a false-positive class).
3. Implement **D4 repeat-and-confirm** + mock `INTERMITTENT` mode.
4. Implement **D5 repro/manifest** (also closes backlog #9, severity in DB).
5. Wire or quarantine the **mutators** (backlog #1); then stand up CI (plan E1).

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
