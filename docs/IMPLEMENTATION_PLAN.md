# AISploit-Recon — Implementation Plan

A real, sequenced plan grounded in the current codebase. It records **what is
already built and validated**, then breaks the remaining work into tasks no
larger than ~1 day, each with dependencies, acceptance criteria, and a rollback.
Security items map to findings in `SECURITY_REVIEW.md` (F-x).

Estimation legend: **XS** ≤2h · **S** ~half day · **M** ~1 day · (nothing larger
— anything bigger is split).

---

## 0. Current state (done & validated)

The core engine exists, imports cleanly, and passes **25/25 tests** (unit +
integration) including a property-based test that already caught and fixed a real
bug (leetspeak `maketrans` length mismatch). Validated end-to-end against the
in-repo intentionally-vulnerable mock: 9 probes → 5 true-positive findings, HTML
autoescape confirmed, report redaction confirmed, SARIF 2.1.0 valid, evidence DB
created `0600`.

| Area | Status |
|---|---|
| Packaging (`pyproject`, scripts, tooling cfg) | ✅ |
| Scope models + **fail-closed guard** (+ tests) | ✅ |
| Detection: canary / signature / refusal + pipeline (+ tests) | ✅ |
| Optional LLM judge with graceful fallback | ✅ (backend pluggable) |
| Transport: HTTP driver + Playwright driver | ✅ (HTTP tested vs mock) |
| Async scheduler + token-bucket rate limiter | ✅ |
| Payload registry + YAML library (9 payloads, 5 files) | ✅ |
| Mutators (+ property tests) | ✅ |
| Evidence store (SQLite, 0600, digests) | ✅ |
| Severity scoring (+ tests) | ✅ |
| Reports: JSON/Markdown/HTML/SARIF + consent artifact | ✅ |
| CLI (`scan`, `payloads`, dry-run default) | ✅ |
| Mock vulnerable target + integration harness | ✅ |
| Docs: README, ARCHITECTURE, SECURITY_REVIEW | ✅ |
| Dockerfile (non-root) | ✅ |

What remains is **hardening, breadth, and productionisation** — below.

---

## 1. Roadmap phases

```
Phase A  Harden safety (security findings)        ← do first
Phase B  Detection precision & breadth
Phase C  Transport robustness
Phase D  Reporting & workflow integration
Phase E  Productionisation (CI, supply chain, packaging)
Phase F  Extensibility & scale
```

---

## Phase A — Harden safety (from SECURITY_REVIEW)

Priority: **P0/P1**. These reduce blast radius and misuse risk. Dependencies:
none beyond current code.

| ID | Task | Est | Prio | Finding | Acceptance |
|----|------|-----|------|---------|-----------|
| A1 | `block_private_ranges` destination guard: resolve host, refuse loopback/link-local/RFC-1918/metadata FQDNs unless overridden | M | P0 | F-3 | Test: guard blocks `169.254.169.254`, `127.0.0.1`, `10.x`, `metadata.google.internal`; allows public host; override flag works |
| A2 | Explicit CLI warning when `--judge` will egress target data; require an interactive confirm or `--judge-i-accept-egress` | XS | P1 | F-4 | Running `--judge` without the accept flag prints warning and aborts; with it, proceeds |
| A3 | `aisploit evidence purge --older-than <days>` honouring `evidence_retention_days` | S | P1 | F-1 | Rows and artifacts older than N are deleted; dry-run lists them first |
| A4 | Keyring-backed credential loading for `storage_state`/tokens (fallback to file with a warning) | M | P1 | F-2 | Token retrievable from OS keyring; file path still works but logs a plaintext-at-rest warning |
| A5 | Markdown evidence fence-breakout fix + regression test | XS | P2 | F-5 | Response containing ```` ``` ```` renders without breaking the report; test asserts structure |
| A6 | Evidence dir `chmod 700`; optional at-rest encryption (age/Fernet) behind a flag | M | P2 | F-1 | Dir is 700; with `--encrypt-evidence`, DB is unreadable without key |

**Testing strategy (Phase A):** unit tests per control; a negative-path suite that
asserts each guard *blocks*. **Validation:** manual run against the mock with a
scope pointing at `127.0.0.1` must now require the override (proving A1).
**Rollback:** each control is additive and flag-gated; disable the flag / revert
the module. No schema change except A3/A6 (additive).

---

## Phase B — Detection precision & breadth

Priority: **P1**. Precision is the product's credibility. Dependencies: A (so new
detectors inherit the safety posture).

| ID | Task | Est | Prio | Acceptance |
|----|------|-----|------|-----------|
| B1 | **Baseline-diff** step: send a benign control message, diff normal vs payload response before scoring | M | P1 | Findings include a `baseline_delta`; a target that always echoes text no longer yields false canary hits |
| B2 | Local-model `JudgeBackend` (e.g. an on-box model) to avoid third-party egress | M | P1 | Judge runs fully offline; parity test vs hosted on a fixture set |
| B3 | Finding **deduplication/clustering** (same root cause across payloads → one issue) | S | P2 | N payloads hitting one behaviour collapse to a single reported issue with evidence list |
| B4 | Multilingual refusal patterns (Thai + others) as loadable locale packs | S | P2 | Thai refusal (“ขอโทษครับ ไม่สามารถ…”) classified as NOT_VULNERABLE |
| B5 | Confidence **calibration harness**: measure precision/recall on a labelled corpus, tune thresholds | M | P2 | Report prints precision/recall; thresholds documented with the number behind them |
| B6 | Expand payload libraries from vetted public research (Garak/PyRIT import adapter) | M | P2 | Import script maps upstream probes into our schema; IDs namespaced; provenance in `references` |

**Testing:** extend the mock with more vuln toggles for ground truth; add a
labelled fixture corpus for B5. **Validation:** precision must not regress vs the
current baseline. **Rollback:** detectors are pipeline-routed; drop-in/out.

---

## Phase C — Transport robustness

Priority: **P1/P2**. Dependencies: none.

| ID | Task | Est | Prio | Acceptance |
|----|------|-----|------|-----------|
| C1 | Playwright **auth capture** helper (`aisploit login`) that saves `storage_state` interactively | S | P1 | One command produces a reusable, keyring-stored session state |
| C2 | Backoff + jitter on 429/challenge; auto-pause campaign, resume | S | P1 | Sustained 429 triggers exponential backoff; campaign completes without banning |
| C3 | Robust response extraction for streaming UIs (mutation-observer strategy) | M | P2 | Stable capture on a token-streaming fixture; no partial reads |
| C4 | SSE/WebSocket transport driver for streaming chat APIs | M | P2 | Probes a WS/SSE endpoint; response assembled correctly |
| C5 | Indirect-injection **delivery harness** (host a poisoned page/doc for RAG targets, in-scope only) | M | P2 | II-00x payload delivered via ingested content; canary detection end-to-end |

**Testing:** fixtures that emulate streaming, 429s, and a RAG ingest path.
**Validation:** run against the mock extended with a streaming route. **Rollback:**
new drivers implement the `Transport` Protocol; selectable via config.

---

## Phase D — Reporting & workflow integration

Priority: **P2**. Dependencies: B3 (dedup improves report quality).

| ID | Task | Est | Prio | Acceptance |
|----|------|-----|------|-----------|
| D1 | Bug-bounty submission template per platform (HackerOne/huntr) auto-filled from a finding | S | P2 | `aisploit export --finding <id> --format hackerone` yields a paste-ready report |
| D2 | Diff two runs (regression view): what’s new/fixed since last scan | S | P2 | `aisploit diff runA runB` lists new/resolved findings |
| D3 | HTML report: collapsible evidence, filter by severity, embed screenshots inline | S | P3 | Reviewer can filter/expand; screenshots inline as data URIs (size-capped) |
| D4 | Attach authorization proof + digests as a signed manifest | S | P3 | Manifest hash-chains artifacts; tamper of any artifact is detectable |

**Testing:** golden-file tests for exporters; schema validation for SARIF stays
green. **Rollback:** reporting is a pure function of `CampaignResult`; revert
templates/exporters freely.

---

## Phase E — Productionisation

Priority: **P1 for CI/supply-chain**, P2 rest. Dependencies: Phase A.

| ID | Task | Est | Prio | Acceptance |
|----|------|-----|------|-----------|
| E1 | CI pipeline: ruff + mypy(strict) + pytest + coverage gate on PR | S | P1 | PR fails on lint/type/test/coverage regression |
| E2 | Supply chain: lockfile with hashes, `pip-audit`, Dependabot, SBOM | S | P1 | CI fails on known-vuln dep; SBOM artifact published |
| E3 | Container scan (Trivy) + publish signed image | S | P2 | Image scanned; signature verifiable |
| E4 | “CI-gate” mode: scan a staging AI feature, fail build on new HIGH/CRITICAL via SARIF | M | P2 | Demo pipeline blocks a regression seeded in the mock |
| E5 | PyPI packaging + versioned release + changelog | S | P2 | `pip install aisploit-recon` works from a tagged release |

**Testing:** the CI itself is the test; E4 validated by seeding a regression in
the mock and asserting a red build. **Rollback:** CI config is versioned; E4 gate
can run in report-only mode first.

---

## Phase F — Extensibility & scale

Priority: **P3**. Dependencies: B, C.

| ID | Task | Est | Prio | Acceptance |
|----|------|-----|------|-----------|
| F1 | Detector **plugin registry** via entry points (replace if/elif routing) | M | P3 | A third-party package can register a detector without editing core |
| F2 | Multi-target campaign runner (parallel across targets, shared report index) | M | P3 | Scans N targets; per-target reports + an index |
| F3 | Resumable campaigns (checkpoint progress to the store) | S | P3 | Interrupted run resumes without re-probing completed payloads |
| F4 | Optional TUI dashboard (Rich Live) with real-time findings | S | P3 | Live table updates as findings arrive |

---

## 2. Dependency graph (critical path)

```
A1,A2,A3 (safety) ──► B1 (baseline-diff) ──► B5 (calibration) ──► E4 (CI gate)
        │                     │
        └► A4 (keyring) ──► C1 (auth capture)
B3 (dedup) ──► D1,D2 (exporters/diff)
E1,E2 (CI/supply-chain) run in parallel from the start of Phase E
```

The credibility-critical path is **A1 → B1 → B5**: lock down destinations, remove
a false-positive class with baseline diffing, then prove precision with numbers.

---

## 3. Milestones

- **M1 — “Safe to point at anything” (Phase A):** destination guard, judge egress
  consent, evidence purge, keyring. *Exit:* all Phase-A acceptance tests green.
- **M2 — “Trustworthy findings” (Phase B core: B1, B5):** baseline diffing +
  measured precision/recall printed in reports. *Exit:* precision ≥ target on the
  labelled corpus with no regression.
- **M3 — “Fits a real workflow” (C1, C2, D1, D2):** interactive auth, backoff,
  platform export, run-diff. *Exit:* a full authorized engagement runs end-to-end
  and produces a submittable report.
- **M4 — “Production/CI” (Phase E):** gated CI, supply-chain checks, published
  artifact. *Exit:* red build on a seeded regression; signed release.

---

## 4. Global testing & validation strategy

- **Unit:** every detector, guard, limiter, mutator, scorer (current + new).
- **Property-based (Hypothesis):** mutators, canary uniqueness, config validators.
- **Integration:** scanner vs mock with expanding ground-truth toggles; assert
  precision/recall, not just "runs".
- **Contract:** SARIF validates against schema; report JSON validates against an
  internal schema.
- **Negative/abuse:** every safety control has a test proving it *blocks*
  (out-of-scope host, private-range target, expired auth, egress without consent).
- **Regression:** golden-file report tests; run-diff catches behavioural drift.

## 5. Deployment & rollback (global)

- Local CLI and container are the delivery vehicles; both are stateless per run
  (state lives in the evidence dir/DB).
- Every phase is additive and flag-gated; rollback = revert the module / disable
  the flag. The only migrations are additive SQLite columns (A3/A6/F3) — guarded
  with `CREATE ... IF NOT EXISTS` and nullable columns so old DBs keep working.

## 6. Monitoring & maintenance (operational)

- Structured logs already emit scope decisions and campaign outcomes; ship them to
  a file/collector during real engagements as an audit trail.
- **Maintenance cadence:** payloads and refusal patterns rot as models change —
  schedule a monthly refresh from upstream research (B6) and a precision re-check
  (B5). Keep dependencies patched via E2.

## 7. Risks to the plan

| Risk | Mitigation |
|---|---|
| Detection precision drifts as target models change | B5 calibration + monthly refresh cadence |
| Playwright brittleness on modern SPA chat UIs | C3 mutation-observer strategy; HTTP driver preferred where an API exists |
| Scope misconfiguration by operator | A1 destination guard + existing validation + dry-run default |
| Third-party judge egress in regulated contexts | B2 local judge + A2 explicit consent |
| Supply-chain compromise | E2 pin+audit+SBOM; non-root container |
