# AISploit-Recon — Security Code Review

Reviewer perspective: Senior Security Architect / DevSecOps
Scope of review: the toolkit's own source (not the targets it scans)
Method: threat model → trust boundaries → per-finding analysis → residual risk

A scanner is itself a high-value, high-privilege piece of software: it holds
session credentials, sends attacker-shaped traffic, and stores data a target
leaked. This review treats the tool as the asset and asks the questions a
Principal/Security reviewer would: *what does it hold, who can reach it, what
happens when a dependency or a target turns hostile?*

---

## 1. Threat model

### Assets
- Operator's **session credentials** for the target (Playwright `storage_state`,
  HTTP `auth_headers`).
- **Authorization scope** (defines legal boundary of activity).
- **Evidence** (may contain a target's leaked secrets/PII).
- **The operator's machine / CI runner** executing the tool.

### Actors / entry points
- **Operator** (trusted, but fallible — typos, over-broad scope).
- **Target application** (semi-trusted → treat all responses as *untrusted input*).
- **Third-party LLM judge** (untrusted sink if enabled).
- **Dependency supply chain** (Playwright, httpx, pydantic, etc.).
- **Payload YAML / scope YAML** (operator-authored, but parsed → parser risk).

### Trust boundaries
1. Operator → tool (CLI args, config files). *Trusted-ish.*
2. Tool → target (outbound probes). *We are the client.*
3. **Target → tool (responses).** *Critical inbound boundary — untrusted data.*
4. Tool → third-party judge (optional outbound of target data). *Exfil boundary.*
5. Tool → disk (evidence, DB, credentials). *At-rest boundary.*

The most important boundary is **#3**: target responses flow into detectors,
into SQLite, and into rendered reports. Anything there must be treated as
adversarial (log injection, HTML/script injection, fence-breakout).

---

## 2. Findings

Severity uses likelihood × impact in the tool's context. Status is one of
**Remediated** (fixed in this codebase), **Mitigated** (controlled by design),
or **Tracked** (accepted for now, queued in the plan).

### F-1 · Sensitive data at rest in evidence store — **Medium** — Remediated (partial)
**What.** The SQLite DB and `evidence/` artifacts can contain a target's leaked
secrets/PII (that's often the whole point of a data-leakage finding).
**Root cause.** Findings are persisted so results are reproducible/auditable.
**Risk/impact.** If the operator's disk or a CI artifact store is compromised,
someone else's production secret leaks a second time — now from *your* box.
**Remediation applied.** `EvidenceStore` sets the DB file to `0600` on creation
(owner-only), best-effort/cross-platform. Reports **redact** high-confidence
secret shapes by default (`utils.crypto.redact`). Evidence dir is `.gitignore`d.
**Residual risk.** No encryption-at-rest; redaction is heuristic (can miss novel
secret formats); the *raw* value is intentionally retained in the DB for PoC
fidelity. **Recommendation (tracked):** optional at-rest encryption; `evidence
purge` command honouring `evidence_retention_days`; `chmod 700` on the dir.

### F-2 · Session credentials stored in plaintext config files — **Medium** — Mitigated
**What.** `storage_state` (cookies/localStorage) and `auth_headers` (bearer
tokens) are read from files referenced by the transport config.
**Risk/impact.** Plaintext session tokens on disk → account impersonation on the
target if leaked; accidental commit is the classic failure.
**Mitigation.** Secrets are pulled from env for the judge; auth material is
`.gitignore`d (`auth/`, `*.json` patterns documented); never logged.
**Residual risk.** Still plaintext at rest. **Recommendation (tracked):** load
`storage_state`/tokens from the OS keyring (`keyring` lib) or a secret manager;
support short-lived tokens; document rotation.

### F-3 · No guard against link-local / cloud-metadata targets (SSRF-style) — **Medium** — Tracked
**What.** `ScopeGuard` allows whatever hosts the operator lists. Nothing blocks
`169.254.169.254`, `metadata.google.internal`, `localhost`, RFC-1918 ranges, or
`[::1]` if an operator (or a copied scope file) includes them.
**Root cause.** The guard validates *shape* (no bare-TLD wildcard) and membership,
not *destination sensitivity*.
**Risk/impact.** A careless or malicious scope could aim the tool at an internal
metadata endpoint or an unintended internal service. Lower likelihood because the
operator authors scope, but the blast radius is high.
**Mitigation today.** Non-http schemes are rejected; hosts must be explicitly
listed; broad globs are rejected at validation.
**Recommendation (tracked, high priority).** Add an optional (default-on)
`block_private_ranges` control that resolves the host and refuses link-local,
loopback, RFC-1918, and known metadata FQDNs unless explicitly overridden for
legitimate internal engagements.

### F-4 · Target data exfiltration via LLM judge — **Medium** — Mitigated (by design)
**What.** With `--judge`, the target's response is sent to a third-party model
for scoring.
**Risk/impact.** A target's sensitive response leaves the operator's trust domain.
**Mitigation.** Off by default; requires **both** `AISPLOIT_JUDGE_ENABLED=true`
and an API key; the judge module documents the trade-off; a `JudgeBackend`
Protocol allows a **local model** to avoid third-party egress entirely.
**Residual risk.** Operator must understand the implication. **Recommendation:**
CLI should print an explicit one-line warning when `--judge` sends data out
(quick win), and prefer a local backend for regulated engagements.

### F-5 · Untrusted target output rendered into reports — **Low** — Mitigated / partial
**What.** Target responses are embedded in HTML and Markdown reports.
**Analysis.** HTML report uses Jinja2 `select_autoescape(["html","xml"])`, so a
response containing `<script>` is escaped — **no stored XSS** in the HTML viewer
(verified). The **Markdown** template wraps evidence in a ```` ``` ```` fence; a
response containing triple backticks could break out of the fence (cosmetic
corruption, not code execution).
**Risk/impact.** Low: report formatting glitch; the JSON source of truth is
unaffected.
**Recommendation (tracked).** Escape/normalise backticks in Markdown evidence, or
switch to indented code blocks; add a test asserting fence integrity.

### F-6 · Log injection via target content — **Low** — Mitigated
**What.** Could a hostile response forge log lines? **Analysis.** We log *metadata*
(payload IDs, target URL, counts, error strings) — not raw response bodies — and
structlog emits JSON, so newlines in any logged value are encoded, not literal.
No untrusted multi-line content reaches the log renderer as structure.
**Residual risk.** `error` strings from transports are logged; they originate from
our client libraries, not target-controlled bodies. Acceptable.

### F-7 · Parser / deserialisation safety — **Info** — Mitigated
**What.** Both scope and payload YAML are loaded. **Analysis.** Exclusively via
`yaml.safe_load` (no `load`/`FullLoader`), so no arbitrary object construction.
Pydantic then validates structure. JSON transport configs use `json.loads`. No
`pickle`, `eval`, `exec`, or `subprocess` on untrusted input anywhere in the
codebase.

### F-8 · SQL injection in the tool itself — **Info** — Mitigated
**What.** All DB writes use parameterised queries; no f-string/`%`-formatted SQL.
The schema is static. The tool cannot be SQL-injected via target content or IDs.

### F-9 · TLS/transport verification — **Low** — Mitigated
**What.** Outbound probes use httpx (Playwright uses Chromium). httpx verifies
certificates by default; no `verify=False` anywhere.
**Residual risk.** No certificate pinning (rarely needed for this use case).
**Recommendation (tracked, low):** allow an operator-supplied CA bundle for
targets behind an internal PKI.

### F-10 · Rate limiter correctness under concurrency — **Info** — Note
**What.** `RateLimiter.acquire()` holds an `asyncio.Lock` while sleeping, which
serialises acquisition. **Analysis.** This is *correct* for a shared token bucket
(prevents over-issuing tokens) and keeps us under the target's ceiling; effective
concurrency is still bounded by the semaphore between acquisitions. Documented so
a future maintainer doesn't "optimise" it into a rate-limit bypass.

### F-11 · Screenshot evidence over-capture — **Low** — Tracked
**What.** Playwright captures `full_page` screenshots; a target UI showing other
users' data would capture it.
**Recommendation (tracked):** offer element-scoped screenshots and a redaction
pass over images (or store only on VULNERABLE verdicts).

---

## 3. Findings summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| F-1 | Sensitive data at rest in evidence store | Medium | Remediated (partial) |
| F-2 | Plaintext session credentials in config | Medium | Mitigated |
| F-3 | No private/metadata destination guard (SSRF-style) | Medium | Tracked (high prio) |
| F-4 | Target data exfil via LLM judge | Medium | Mitigated (by design) |
| F-5 | Untrusted output in reports | Low | Mitigated (HTML) / partial (MD) |
| F-6 | Log injection | Low | Mitigated |
| F-7 | Deserialisation safety | Info | Mitigated |
| F-8 | SQLi in the tool | Info | Mitigated |
| F-9 | TLS verification | Low | Mitigated |
| F-10 | Rate-limiter concurrency | Info | Note |
| F-11 | Screenshot over-capture | Low | Tracked |

**Net posture:** no Critical/High in the tool. The two items most worth doing
next are **F-3** (destination guard — cheap, meaningfully reduces blast radius)
and completing **F-1/F-2** (at-rest encryption + keyring). None block v1.0 for its
intended single-operator, in-scope use.

---

## 4. Controls that are working (positive assurance)

- **Fail-closed authorization** enforced before any I/O; validated by unit tests
  (out-of-scope host, non-http scheme, denied path, expired auth all blocked).
- **Broad-glob rejection** at config-validation time (`*`, `*.com` refused).
- **Deterministic, low-false-positive detection**; non-refusal never auto-escalates
  to "vulnerable".
- **`safe_load` + Pydantic** everywhere; no dynamic code execution.
- **Parameterised SQL**, static schema.
- **Autoescaped HTML** reports (no stored XSS from target content — verified).
- **Redaction-by-default** in reports; **0600** evidence DB.
- **Least privilege** container (non-root `scanner` user).
- **Structured audit logging** of scope decisions and campaign outcomes.

---

## 5. Recommendations, prioritised

**Do next (high value / low cost)**
1. F-3: `block_private_ranges` destination guard (resolve + refuse link-local /
   loopback / RFC-1918 / metadata FQDNs unless explicitly overridden).
2. F-4: explicit CLI warning line when `--judge` will egress target data.
3. F-1: `aisploit evidence purge --older-than` honouring `retention_days`.

**Do soon**
4. F-2: keyring-backed credential loading; document token rotation.
5. F-5: fix Markdown fence-breakout + regression test.
6. F-1: optional at-rest encryption for the evidence DB/artifacts.

**Nice to have**
7. F-11: element-scoped screenshots + image redaction; capture only on hits.
8. F-9: operator-supplied CA bundle for internal-PKI targets.
9. Supply chain: pin dependencies with hashes (`pip-tools`/`uv` lockfile),
   enable `pip-audit`/Dependabot, and add SBOM generation to CI.

---

## 6. Abuse-resistance note

Beyond code security, the *design* resists misuse: authorization is enforced not
suggested, the default action is a dry run, rate limits are polite by default,
reports embed a consent artifact, and the project intentionally ships **no**
working jailbreak/bypass library. These choices align the tool with the norms of
Garak/PyRIT-class research tooling and with bug-bounty program expectations.
