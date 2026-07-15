# AISploit-Recon — Design: Credibility, Reach & Workflow

Status: **proposed** · Author: review pass 2026-07-14 · Supersedes nothing
(complements `IMPLEMENTATION_PLAN.md`, references `SECURITY_REVIEW.md` findings).

This document turns the review's recommendations into concrete, buildable
designs. It is organised around the three levers that actually move the tool
from "solid v1 scaffold" to "reached-for in real engagements":

1. **Credibility of findings** — fewer false positives, provable results.
2. **Reach** — works against the targets people actually have (streaming,
   authenticated, multi-turn, RAG).
3. **Workflow fit** — output a triager or a CI pipeline can consume directly.

Each design states: *problem → approach → concrete changes (with file anchors)
→ acceptance → risk/rollback*. All changes are additive and flag-gated unless
noted. Payload/DB/schema changes are backward-compatible (new optional fields,
`CREATE ... IF NOT EXISTS`, nullable columns).

---

## Guiding constraints (unchanged)

- **Fail-closed authorization stays first.** No design may send bytes before
  `ScopeGuard.assert_in_scope` (`core/scope_guard.py`). New transports/turns
  call the guard on every distinct destination.
- **Deterministic-first.** New detectors must degrade to a defined verdict, not
  silently skip. Non-refusal never auto-escalates to VULNERABLE.
- **No shipped weaponised payloads.** Coverage grows via import adapters with
  provenance, not a bundled bypass kit.
- **Data-as-config.** Behaviour is driven by YAML/JSON schema fields, not engine
  edits, wherever practical.

---

## Priority & sequencing

```
P0  D1 Baseline-diff ─┬─► D4 Repeat-and-confirm ─► D5 Repro+Export
                      │
P0  D9 SSRF guard ────┘        (safety gate, from SECURITY_REVIEW F-3)

P1  D3 Streaming transport ─► D6 Auth capture ─► D2 Multi-turn probes
P1  D7 Thai/locale refusals   D8 Signature hardening   (parallel, cheap)
P2  D5b Platform export, run-diff, CI-gate            (workflow adoption)
```

Rationale: **D1 + D4** buy the biggest credibility gain for the least code and
unlock honest precision numbers. **D9** is a cheap, high-value safety control.
**D3 → D2** is the reach path (most real targets stream and need auth; multi-turn
is the largest capability gap but depends on transport work first).

---

## D1 — Baseline-diff detection  (P0, credibility)

**Problem.** The canary detector (`detection/canary.py`) assumes a reflected
marker means instructions were followed. A target that *echoes all input*
(some RAG/search UIs, "you said: …" confirmations) reflects the canary
regardless — a false positive, the exact class that gets reports rejected.

**Approach.** Characterise the target once per campaign with a benign control
probe carrying a *control canary*. If the control canary comes back, the target
reflects input indiscriminately; canary hits are then penalised, not trusted.

**Concrete changes.**
- New `core/baseline.py`: `Baseline(reflects_input: bool, control_digest: str,
  control_excerpt: str)`.
- `Campaign` (`core/scheduler.py`): add `async def _establish_baseline()` run
  after `transport.setup()` and before probes. It sends one neutral message
  (e.g. `"Please reply with a one-sentence greeting."`) plus a distinct
  `CONTROL_<hex>` token, and sets `reflects_input = CONTROL_… in response`.
- Thread `baseline` into `DetectionPipeline.evaluate(...)` and into
  `CanaryDetector.detect(response, canary, baseline)`.
- `detection/types.py`: add optional `baseline_delta: str = ""` and let
  `CanaryDetector` return `INCONCLUSIVE` (or confidence ×0.4) with a note when
  `baseline.reflects_input` is true.

**Acceptance.**
- Extend the mock (`tests/fixtures/mock_ai_app/app.py`) with an
  `AISPLOIT_MOCK_ECHO=1` mode that echoes any input. In echo mode, PI-001 must
  **not** be reported as high-confidence VULNERABLE.
- Non-echo vulnerable mode: PI-001 unchanged (still VULNERABLE ≥0.95).

**Risk/rollback.** One extra request per campaign (negligible vs. rate limits).
Flag `baseline_diff: true` (default on); disable to restore current behaviour.

---

## D4 — Repeat-and-confirm  (P0, credibility)

**Problem.** LLM targets are non-deterministic; a single VULNERABLE hit can be a
fluke, and a single miss can hide a real issue. Reports need reproducible signal.

**Approach.** On a candidate VULNERABLE verdict, re-probe N times and apply a
confirmation policy before finalising.

**Concrete changes.**
- `ScopeRule` / campaign config: `confirm_trials: int = 1` (opt-in; e.g. 3),
  `confirm_policy: "majority" | "any" | "all" = "majority"`.
- `Campaign._probe_one`: when the first verdict is VULNERABLE and
  `confirm_trials > 1`, run the probe `confirm_trials-1` more times (respecting
  the rate limiter), collect verdicts, and:
  - keep VULNERABLE only if policy is satisfied; otherwise downgrade to
    INCONCLUSIVE with reasoning `"1/3 trials reproduced"`.
- Persist per-trial outcomes (see D5 request/response manifest) so the report
  shows reproduction rate.

**Acceptance.** A mock mode that fires intermittently (e.g. 1-in-3) yields
INCONCLUSIVE under `majority`, VULNERABLE under `any`. Deterministic mock
unchanged.

**Risk/rollback.** More requests when enabled; bounded by `confirm_trials` and
rate limiter. Default `1` = today's behaviour.

---

## D5 — Reproduction artifact + request manifest  (P0→P1, workflow)

**Status: ✅ DONE (session 5)** — core manifest + repro. `ProbeResponse.request_manifest`
is populated (auth masked at capture) by both drivers; flows to `Finding`; the
report renders a `curl` (HTTP) or step-list (Playwright) `repro`; evidence DB
gained a `request_json` column (guarded migration). `severity`/`severity_score`
were already persisted (backlog #9). **D5b** (export/diff/CI-gate) remains P2.

**Problem.** A finding today carries evidence text and a response digest but not
the *exact request*. Triagers want a one-command repro. `EvidenceStore`
(`evidence/store.py`) has no request columns, so nothing can reconstruct the
probe later.

**Approach.** Capture a redacted request manifest per finding and render a
copy-paste repro (curl for HTTP; step list for Playwright).

**Concrete changes.**
- `transport/base.py`: add `ProbeResponse.request_manifest: dict | None`
  (method, url, headers-with-auth-masked, body, response_path) populated by each
  driver in `send()`.
- `evidence/models.py` + `store.py`: add nullable `request_json TEXT`,
  `severity TEXT`, `score REAL` columns (`CREATE TABLE IF NOT EXISTS` +
  `ALTER TABLE ADD COLUMN` guarded for old DBs).
- `reporting/generator.py` `_finding_dict`: add `repro` (a `curl` string built
  from the manifest, auth headers shown as `Bearer <REDACTED>`), and include
  `severity`/`score` already computed by `score_finding`.
- Templates: add a "Reproduce" block to `report.md.j2` / `report.html.j2`.

**Acceptance.** Golden-file test: a finding renders a curl that, run against the
mock, reproduces the response (verified in an integration test). Redaction test:
auth header never appears in the manifest or repro.

**Risk.** Request bodies may contain the payload (fine) but never target
secrets. Reuse `utils/crypto.redact` on the manifest before persisting.

### D5b — Platform export, run-diff, CI-gate  (P2, adoption)

**Status: ✅ DONE (session 6).** `reporting/export.py` + three CLI commands.
`export_finding` → hackerone/huntr/markdown from a stored finding; `diff_runs`
→ new/resolved/unchanged between two runs; `ci_gate` → pass/fail vs severity
threshold. CLI: `aisploit export`, `aisploit diff`, `aisploit scan --fail-on
<level>`. EvidenceStore gained `fetch_finding` / `fetch_run`. 14 unit tests
(`test_export_diff.py`).
- `aisploit export --finding <id> --format hackerone|huntr|markdown` reads the
  store and fills a per-platform template (maps to `IMPLEMENTATION_PLAN` D1).
- `aisploit diff <runA> <runB>` lists new/resolved findings by `payload_id +
  target` (D2 in the plan).
- `aisploit scan … --fail-on high` returns non-zero when a new ≥HIGH appears,
  for CI gating on the SARIF already produced (E4). Report-only mode first.

---

## D9 — SSRF / private-range destination guard  (P0, safety — SECURITY_REVIEW F-3)

**Problem.** `ScopeGuard` validates host *shape and membership* but not
*destination sensitivity*. A copied scope listing `127.0.0.1`,
`169.254.169.254`, `metadata.google.internal`, `[::1]`, or an RFC-1918 host is
allowed. High blast radius.

**Approach.** Resolve the host and refuse private/link-local/loopback/metadata
destinations unless the operator explicitly opts in (legitimate internal
engagements exist — and the integration tests target `127.0.0.1`, so the
override must be first-class).

**Concrete changes.**
- `ScopeRule`: `block_private_ranges: bool = True`, `allow_private_hosts:
  list[str] = []`.
- `core/scope_guard.py`: after host-pattern match, resolve via
  `socket.getaddrinfo`; reject if any resolved IP is loopback/link-local/private/
  ULA/multicast (use `ipaddress`), or if the host is a known metadata FQDN,
  unless the host is in `allow_private_hosts`. Emit `scope.block reason=private`.
- Tests set `allow_private_hosts: ["127.0.0.1"]` for the mock harness.

**Acceptance (negative-path).** Guard blocks `169.254.169.254`, `127.0.0.1`,
`10.0.0.5`, `metadata.google.internal`; allows a public host; override permits
`127.0.0.1`. DNS-rebinding note: resolve-and-pin the IP, and have drivers
connect to the pinned IP where feasible (documented limitation otherwise).

**Risk/rollback.** Default-on changes behaviour for localhost targets → mitigated
by the override and updated test scopes. Flag off = current behaviour.

---

## D3 — Streaming transport (SSE / NDJSON)  (P1, reach)

**Status: ✅ DONE (session 5).** `HttpConfig` gained `stream`/`stream_format`
(`sse`|`ndjson`)/`stream_delta_path`/`stream_done_sentinel`/`stream_max_chars`;
`HttpDriver.send` branches to `_send_streaming` which assembles deltas via
`aiter_lines`. Example `examples/transport.sse.json`. Acceptance met: the mock
`/chat/stream` route is assembled and `PI-001` fires (vulnerable) / stays quiet
(secure) — `tests/integration/test_scanner_vs_mock.py`.

**Problem.** `HttpDriver.send` (`transport/http_driver.py`) calls `resp.json()`.
Against a `text/event-stream` chat API it raises → caught → `ProbeResponse.error`
→ probe dropped. Net effect: **a streaming target silently yields zero
findings**, which reads as "secure". Most modern chat APIs stream.

**Approach.** Add a streaming mode that assembles the full message from deltas.

**Concrete changes.**
- `HttpConfig`: `stream: bool = False`, `stream_format: "sse" | "ndjson" =
  "sse"`, `stream_delta_path: str = "choices.0.delta.content"`,
  `stream_done_sentinel: str = "[DONE]"`.
- `HttpDriver.send`: when `stream` (or response `content-type` is
  `text/event-stream`), use `client.stream(...)`, iterate lines, parse each
  `data:` JSON chunk, extract the delta via `stream_delta_path`, concatenate
  until the sentinel/stream end; return the assembled text.
- Example config `examples/transport.sse.json`.

**Acceptance.** A streaming route added to the mock (emits token-by-token SSE)
is scanned and assembled identically to the non-stream route; PI-001 fires.

**Risk.** Partial reads / hung streams → bound by `timeout_s` and a max-bytes
cap. Non-stream path unchanged when `stream=false`.

---

## D6 — Interactive auth capture (`aisploit login`)  (P1, reach)

**Status: ✅ DONE (session 6).** `core/auth.py`: `AuthCapture` launches
Playwright non-headless, navigates to the target, captures `storage_state`.
`save_auth_state` persists to file (chmod 600) or OS keyring (`--keyring`);
`load_auth_state` reads back. CLI: `aisploit login --target <url> --out
auth/state.json [--keyring <name>]`. Interactive only (documented; not for
headless CI — inject tokens via transport config there). 8 unit tests
(`test_auth_capture.py`): file save/load, chmod 600 permissions, keyring
fallback, error paths.

**Problem.** Playwright/HTTP auth requires a hand-crafted `storage_state` /
`auth_headers`. High friction; discourages real use. (Ties to F-2 keyring.)

**Approach.** A guided command that opens a real browser, lets the operator log
in, and saves the session.

**Concrete changes.**
- `aisploit login --target <url> --out auth/state.json [--keyring <name>]`:
  launches Playwright non-headless, waits for the operator to authenticate and
  press Enter, then `context.storage_state(path=...)`.
- Follow-up (F-2): if `--keyring` given, store via the `keyring` lib instead of
  a plaintext file; transports load from keyring first, file with a
  plaintext-at-rest warning otherwise.
- `.gitignore` already covers `auth/` and `*.json` patterns — keep.

**Acceptance.** One command produces a reusable state; a subsequent authenticated
scan uses it. Secret never logged.

**Risk.** Interactive only; document that it is not for headless CI (use tokens
there).

---

## D2 — Multi-turn / conversational probes  (P1, biggest capability gap)

**Status: ✅ DONE (session 4).** Implemented as specified below, with one
refinement: instead of a `ConversationMixin`, the sequential fallback is a
shared helper `transport.base.send_turns_sequentially(send, req)` used by both
the HTTP and Playwright drivers (no monkey-patching; passes mypy strict). The
`HttpDriver` also supports a *native* multi-turn endpoint via
`HttpConfig.conversation_endpoint` (+ `{turns}` body placeholder). Payloads:
`payloads/library/multi_turn.yaml` (MT-001 canary, MT-002 persona/signature).
Acceptance met by `tests/integration/test_scanner_vs_mock.py` (multi-turn fires
in vulnerable mode, quiet in secure mode, sequential fallback works, single-shot
unchanged) + `tests/unit/test_multi_turn.py` (schema). Full suite green
(64 tests), ruff + mypy --strict clean.

**Problem.** The `Payload` schema (`payloads/models.py`) is single-shot: one
`template`, one request, one response. Real injections often need setup turns
(establish a persona/context, then exploit). No amount of single-shot payloads
covers this.

**Approach.** Make a payload optionally a *sequence of turns*; detect on the
final (or aggregated) response. Fully backward-compatible.

**Concrete changes.**
- `Payload`: add `turns: list[str] | None = None`. Validation: exactly one of
  `template` / `turns` is set; `requires_canary` scans all turns; the canary is
  substituted in whichever turn(s) contain `{canary}`.
- `transport/base.py`: add `ConversationRequest(turns: list[str], metadata)` and
  `Transport.send_conversation(req) -> ProbeResponse` (default mixin: for
  single-turn Transports, send turns sequentially and return the last response).
  - HTTP stateless APIs: accumulate a `messages` array — extend
    `body_template` to support a `{history}` array injection, or a
    `conversation_template`. Design detail resolved in implementation; keep the
    single-message path as the default.
  - Playwright: type/submit each turn on the same page, wait-for-stable between
    turns, capture the final answer + a screenshot.
- `Campaign._probe_one`: branch on `payload.turns`; evaluate detection against
  the final turn's response (canary/ signature unchanged).
- Detection unaffected: it still scores one final `response` string.

**Acceptance.** A mock conversation route where turn 1 "primes" and turn 2
exploits: a 2-turn PI payload fires only when both turns are sent in order;
sending only turn 2 does not. Existing single-`template` payloads: byte-identical
behaviour.

**Risk.** Larger blast radius per payload (more requests) → counts against rate
limiter; document. Rollback: `turns` is optional; omit to keep single-shot.

---

## D7 — Locale refusal packs (Thai first)  (P1, cheap, correctness)

**Problem.** `RefusalClassifier` (`detection/heuristic.py`) patterns are
English-only. A Thai refusal ("ขอโทษครับ ไม่สามารถช่วยเรื่องนี้ได้") matches
nothing → returns INCONCLUSIVE → the pipeline may escalate a *correctly-refusing*
Thai target. False-positive risk on exactly the operator's home locale.

**Approach.** Loadable locale packs; select per engagement.

**Concrete changes.**
- `detection/refusals/en.yaml`, `th.yaml`, … each a list of regex/phrases.
  Thai seeds: `ขอโทษ`, `ขออภัย`, `ไม่สามารถ`, `ไม่สามารถช่วย`, `ทำไม่ได้`,
  `ไม่สามารถให้ข้อมูล`, `ขัดต่อนโยบาย`.
- `RefusalClassifier(locales=["en","th"])` compiles the union; config
  `refusal_locales: [en, th]` on `ScopeConfig` or settings.
- Normalise before matching (NFKC) so width/variant forms match.

**Acceptance.** Thai refusal → NOT_VULNERABLE; Thai non-refusal → INCONCLUSIVE.
English behaviour unchanged.

**Risk.** None material; additive data files.

---

## D8 — Signature detector hardening  (P1, cheap)

**Problem.** `SignatureDetector` (`detection/signature.py`) does case-folded
substring `in` only. It both misses (spacing/unicode/zero-width evasions) and
over-matches (substring inside an unrelated word).

**Approach.** Normalise inputs and support richer indicators without breaking
existing YAML.

**Concrete changes.**
- Normalise response + indicators: NFKC, strip zero-width, collapse whitespace,
  lowercase.
- Indicator syntax: plain string = normalised substring; `re:<pattern>` =
  regex; optional `word:<term>` = word-boundary match.
- Keep the mixed-signal (success + refusal) → INCONCLUSIVE logic as-is.
- Revisit weak indicators surfaced in review, e.g. DL-001's `"@"` (too broad in
  the judge-off fallback) — tighten to `re:[\w.+-]+@[\w.-]+\.\w{2,}` or drop.

**Acceptance.** Zero-width-injected "You␏␏are" still matches "You are";
`"class"` no longer matches indicator `"as"`; DL-001 fallback stops firing on a
lone `@`.

**Risk.** Indicator semantics change slightly → covered by unit tests per
indicator form; existing plain-string indicators keep working.

---

## Cross-cutting: import adapters for coverage  (P2, ties to plan B6)

Rather than authoring payloads by hand, ship a one-way importer:
`aisploit import garak|pyrit <path>` maps upstream probes into the `Payload`
schema, namespaces IDs (`GARAK-…`), records provenance in `references`, and
writes them `enabled: false` for review. This grows coverage while keeping the
"no bundled bypass kit" stance — the operator opts each probe in.

---

## Testing strategy (applies to every design)

- **Unit** per new detector/guard/parser, including negative paths (each safety
  control has a test proving it *blocks*).
- **Property (Hypothesis)** for the SSRF IP classifier, SSE assembler, and
  multi-turn canary substitution.
- **Integration vs. mock** with new ground-truth toggles: `ECHO`, `STREAM`,
  `INTERMITTENT`, a 2-turn `CONVERSATION` route. Assert precision/recall, not
  just "runs".
- **Golden-file** for repro/export renderers; **SARIF** stays schema-valid.
- **Regression:** `aisploit diff` catches behavioural drift between runs.

## Migration & rollback (global)

Every item is flag-gated and additive. DB migrations are additive nullable
columns via `IF NOT EXISTS` / guarded `ALTER TABLE`, so existing evidence DBs
keep working. Rollback = disable the flag / revert the module; no data loss.
