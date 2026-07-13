# AISploit-Recon — Architecture

Status: v1.0 · Audience: engineers/reviewers · Companion docs: `SECURITY_REVIEW.md`, `IMPLEMENTATION_PLAN.md`

---

## 1. System overview

AISploit-Recon is an **authorized black-box scanner** that probes an AI feature
in a web app for LLM-specific weaknesses (prompt injection, jailbreak, system
prompt / data leakage), then produces reproducible, submission-ready findings.

It is deliberately the inverse of the legacy *PentestGPT* design: there, an LLM
sat in the critical decision path, making runs non-deterministic and evidence
hard to reproduce. Here, **deterministic payload + detector logic is the spine**,
and an LLM is only an optional, off-by-default scoring layer. Reproducibility is
a hard requirement because the output is evidence attached to a bug report.

### Design goals (ranked)

1. **Safety/authorization** — never test out of scope; fail closed.
2. **Reproducibility** — every finding carries a re-runnable PoC + digest.
3. **Precision over recall** — a false positive costs researcher credibility;
   the pipeline prefers "inconclusive" to a wrong "vulnerable".
4. **Extensibility** — payloads are data; detectors and transports are pluggable.
5. **Operational courtesy** — rate-limited, concurrency-capped, polite by default.

### Non-goals

- Not a curated weaponised-bypass distribution (see `jailbreak.yaml`).
- Not a defensive runtime guardrail; it is a testing tool.
- Not a fuzzer for non-AI web surface (use ZAP/Burp for that).

---

## 2. High-level architecture

```
                          ┌──────────────────────────────┐
                          │            CLI (Typer)        │
                          │  scan · payloads · dry-run    │
                          └───────────────┬──────────────┘
                                          │
                          ┌───────────────▼──────────────┐
                          │      Orchestrator / Campaign  │
      ┌───────────────────┤  (async, concurrency-capped)  ├───────────────┐
      │                   └───────┬───────────────┬───────┘               │
      │                           │               │                       │
┌─────▼──────┐          ┌─────────▼──────┐  ┌──────▼───────┐     ┌─────────▼────────┐
│ ScopeGuard │  (gate)  │  RateLimiter   │  │  Payload     │     │  Detection       │
│ fail-closed│◄─────────┤  token bucket  │  │  Registry    │     │  Pipeline        │
└────────────┘          └────────────────┘  │  (YAML)      │     │  canary▸sig▸     │
                                             └──────┬───────┘     │  refusal▸judge?  │
                                                    │             └────────┬─────────┘
                          ┌─────────────────────────▼──────────┐          │
                          │  Transport (Protocol)              │          │
                          │  ┌──────────────┐  ┌────────────┐  │          │
                          │  │ Playwright   │  │ HTTP/API   │  │──► target │
                          │  │ (UI, HAR,    │  │ (httpx)    │  │          │
                          │  │  screenshots)│  │            │  │          │
                          │  └──────────────┘  └────────────┘  │          │
                          └────────────────────────────────────┘          │
                                          │                                │
                          ┌───────────────▼────────────────────────────────▼──┐
                          │   Evidence Store (SQLite + artifacts, 0600)        │
                          └───────────────────────────┬────────────────────────┘
                                                      │
                          ┌───────────────────────────▼────────────────────────┐
                          │   Report Generator → JSON · Markdown · HTML · SARIF │
                          └─────────────────────────────────────────────────────┘
```

Control flow for a live scan: CLI loads scope + transport config → constructs
`ScopeGuard`, `PayloadRegistry`, `RateLimiter`, `DetectionPipeline`, transport →
`Campaign.run()` asserts scope (fail-closed) → for each payload: rate-limit →
inject canary → send via transport → evaluate via pipeline → keep actionable
findings → persist to evidence store → render reports.

---

## 3. Component responsibilities & module map

| Module | Responsibility | Key invariant |
|---|---|---|
| `config/scope.py` | Authorization + scope models | Rejects dangerously broad host globs at validation |
| `config/settings.py` | Env/secret loading | Secrets only from env, never YAML/code |
| `core/scope_guard.py` | **Enforcement** of scope | Deny-by-default; raises before any I/O |
| `core/session.py` | Token-bucket rate limiter | Never exceeds `max_per_minute` |
| `core/scheduler.py` | Async campaign runner | Asserts scope before setup; canary flows to detector |
| `core/models.py` | `Finding`, `CampaignResult` | Findings carry digest for tamper-evidence |
| `payloads/models.py` | `Payload` schema | `{canary}` presence drives injection |
| `payloads/registry.py` | Load/validate YAML | Unique IDs; malformed file is fatal |
| `payloads/mutators.py` | Generic encoding transforms | Pure, composable, property-tested |
| `transport/base.py` | `Transport` Protocol + DTOs | DIP boundary: engine depends on abstraction |
| `transport/http_driver.py` | API probing (httpx) | Configurable request/response shape |
| `transport/playwright_driver.py` | UI probing | Waits for streamed response to stabilise |
| `detection/types.py` | `Verdict`, `DetectionResult` | Immutable results (frozen) |
| `detection/canary.py` | Deterministic marker detector | ~0 false positives |
| `detection/signature.py` | Keyword matcher | Weighs success vs refusal |
| `detection/heuristic.py` | Refusal classifier | Non-refusal ⇒ INCONCLUSIVE, not VULNERABLE |
| `detection/llm_judge.py` | Optional semantic scorer | Off by default; graceful fallback |
| `detection/pipeline.py` | Route payload→detector | Cheap→expensive; fallback labelled |
| `evidence/store.py` | SQLite persistence | Parameterised SQL; 0600 file perms |
| `reporting/severity.py` | CVSS-inspired scoring | Confidence dampens severity |
| `reporting/generator.py` | Multi-format reports | Autoescaped HTML; consent artifact embedded |
| `cli.py` | UX + safety flow | Dry-run default; `--live` required to send |

---

## 4. Key design decisions (with rationale)

### 4.1 Deterministic detection first, LLM last

The **canary detector** embeds a random 64-bit marker in a payload; if it is
reflected verbatim, the injected instruction ran. This gives near-zero false
positives and a reproducible PoC. Signature and refusal detectors handle cases
without a natural marker. The LLM judge — the only non-deterministic component —
is opt-in and, if unavailable, the pipeline degrades to signature matching at
reduced confidence and *labels* the degradation rather than hiding it.

**Trade-off:** deterministic detectors can't catch purely semantic compromises
(subtle data leakage). That's exactly what the optional judge is for; the
operator accepts the third-party-exfiltration trade-off consciously.

### 4.2 Fail-closed scope guard as a first-class component

Authorization isn't a config comment; it's an enforced gate that runs before any
network activity and before transport setup. Deny-by-default plus validation-time
rejection of broad globs (`*`, `*.com`) turns a class of catastrophic operator
mistakes into a startup error. It also emits a consent artifact into reports.

**Alternative considered:** a soft warning. Rejected — a warning you can ignore
is not a control.

### 4.3 Transport as a Protocol (Dependency Inversion)

The orchestrator depends on the `Transport` abstraction, not on Playwright or
httpx. This lets us test the whole pipeline against an in-process mock via the
HTTP driver (fast, deterministic) while still supporting real UI probing.

**Trade-off:** two drivers to maintain. Worth it: UI-path defences only trigger
on the genuine request path, so UI probing is not optional for thoroughness.

### 4.4 Payloads as data (YAML)

Keeps the engine stable while the library evolves, enables VCS review of test
changes, and lets you import vetted payloads from public research into one schema.

### 4.5 Async with concurrency cap + token bucket

Probes are I/O-bound; asyncio overlaps them. The token bucket enforces the scope's
rate ceiling, and a semaphore caps concurrency. Together they keep the scanner a
good citizen and keep results uncorrupted by target-side rate limiting.

---

## 5. Data flow (sequence, live scan)

```
CLI
 │  load scope.yaml, transport.json, settings(.env)
 ▼
Campaign.run(payloads)
 │  ScopeGuard.assert_in_scope(target)        ── raises ScopeViolation → exit 2
 │  transport.setup()                          (browser/context or httpx client)
 │
 ├─ for each enabled payload (bounded by semaphore):
 │     RateLimiter.acquire()                   (blocks to honour rate ceiling)
 │     inject canary if template has {canary}
 │     transport.send(ProbeRequest)  ──────────► target AI feature
 │                              ◄────────────── ProbeResponse (+screenshot/HAR)
 │     DetectionPipeline.evaluate(payload, resp, canary)
 │         canary | signature | refusal | judge?
 │     keep if VULNERABLE or INCONCLUSIVE
 │
 ▼  transport.teardown()  (flush HAR, close browser/client)
EvidenceStore.record_finding(...)             (SQLite, 0600, digest)
ReportGenerator.write_all(...)                (JSON/MD/HTML/SARIF, redacted)
```

---

## 6. Data model

**Persisted (SQLite `findings`):** run_id, payload_id, target_url, verdict,
confidence, detector, canary, evidence_snippet (≤2000 chars), raw_response_digest
(SHA-256), screenshot_path, latency_ms, created_at. Indexed on run_id and verdict.

**Report JSON (source of truth):** run metadata + authorization consent block +
summary counts + findings sorted by score, each with severity, confidence,
detector, evidence (redacted by default), digest, references.

**Artifacts:** `evidence/<payload_id>.png`, `evidence/session.har`. The digest
ties a report line to an immutable artifact for tamper-evidence.

---

## 7. Deployment & operations

- **Local CLI** for interactive research (primary mode).
- **Container** (`docker/Dockerfile`) on the Playwright base image; runs as a
  non-root `scanner` user. Suitable for CI.
- **CI gate (future, see plan):** run against a staging AI feature; fail the
  build on new HIGH/CRITICAL via the SARIF output imported into code scanning.

**Configuration surface:** `scope.yaml` (authorization), `transport.*.json`
(how to reach the feature), `.env` (secrets, judge toggle). Secrets never live in
the first two.

**Observability:** structured (JSON) logs via structlog with stable event keys
(`scope.allow`, `scope.block`, `probe.transport_error`, `campaign.done`). These
form an audit trail of what was tested, when, and whether anything was blocked.

---

## 8. Scaling & performance characteristics

- Bottleneck is the **target**, not the scanner — deliberately, via rate limits.
- Playwright is the heavy path (a browser context per campaign, a page per probe);
  the HTTP driver is used wherever an API exists.
- Memory is bounded by concurrency (`max_concurrent`) × response size; findings
  accrue in memory then flush to SQLite.
- Horizontal scaling (many targets) is embarrassingly parallel at the process
  level; within a target, politeness caps throughput on purpose.

---

## 9. Failure modes & resilience

| Failure | Behaviour |
|---|---|
| Out-of-scope target | `ScopeViolation` before any I/O; exit code 2 |
| Expired authorization | Guard refuses at construction |
| Target 429 / timeout | Probe returns error, campaign continues, counted in `errors` |
| Judge unavailable | Pipeline falls back to signature at reduced confidence, labelled |
| Malformed payload YAML | Registry raises; run aborts (fail loud) |
| Streamed response read early | `_wait_for_stable_response` prevents partial reads |
| Target injects HTML into evidence | HTML report autoescapes; no XSS in the viewer |

---

## 10. Extension points

- **New detector:** implement the `detect(...)` shape, return a `DetectionResult`,
  wire it into `DetectionPipeline` (a future plugin/entry-point registry is in the
  plan).
- **New transport:** implement the `Transport` Protocol.
- **New payloads:** drop a YAML file in `payloads/library/` (unique IDs, schema-valid).
- **New judge backend:** implement `JudgeBackend.score()` (e.g. a local model) to
  avoid third-party exfiltration.

---

## 11. Known architectural limitations (tracked)

1. Detectors are English-first; multilingual targets need locale-specific refusal
   patterns.
2. No automated evidence-retention purge job yet (`retention_days` is declared,
   enforcement is future work).
3. Detector plugin system is a manual `if/elif` today; fine at this size, refactor
   to a registry as detectors grow.
4. No baseline-diff step yet (send a benign message, diff against payload response)
   — a precision improvement queued in the plan.

See `SECURITY_REVIEW.md` for the security-specific findings and `IMPLEMENTATION_PLAN.md`
for how these are sequenced.
