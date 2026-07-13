# AISploit-Recon

Authorized black-box scanner for **LLM security weaknesses** — prompt injection,
jailbreak, system-prompt / data leakage — in web applications that expose AI
features (chatbots, AI search, RAG). Built for legitimate AI red-teaming and
bug-bounty work (HackerOne AI category, ProtectAI/huntr, and self-hosted apps).

> ⚠️ **Use only against targets you own or are explicitly authorized to test.**
> The engine enforces an authorization scope, fail-closed, before sending
> anything. See [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md).

## Why this design

- **Deterministic-first detection.** A canary-marker detector gives provable,
  reproducible findings — the opposite of the legacy "LLM-in-the-loop" approach
  whose non-determinism made evidence unreliable. The LLM judge is optional and
  off by default.
- **Scope guard is a feature, not a limit.** It protects you legally and
  operationally, and its output doubles as a consent artifact in reports.
- **Payloads are data (YAML), not code.** Extend the library — including from
  vetted public research — without touching the engine.
- **Evidence you can submit.** Screenshots, HAR, response digests, per-finding
  reproducibility, and SARIF for CI.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,judge]"        # core + dev + optional LLM judge
# pip install -e ".[browser]"        # add if using the Playwright transport
# playwright install chromium         # then install Chromium binaries
```

## Quickstart

```bash
# 1. Author your scope (authorization boundary).
cp examples/scope.example.yaml scope.yaml && $EDITOR scope.yaml

# 2. Configure how to reach the AI feature.
cp examples/transport.http.json transport.json && $EDITOR transport.json

# 3. DRY RUN first (default) — see exactly what would be sent, sends nothing.
aisploit scan https://chat.example.com/api/chat \
  --scope scope.yaml --transport http --transport-config transport.json

# 4. Go live once you're happy.
aisploit scan https://chat.example.com/api/chat \
  --scope scope.yaml --transport http --transport-config transport.json --live \
  --out ./reports
```

List built-in payloads:

```bash
aisploit payloads
```

## Architecture (one screen)

```
CLI ─► Orchestrator ─► [ Scope Guard ] ─► Scheduler (async, rate-limited)
                                              │
        Payload Registry ─────────────────────┤
                                              ▼
                        Transport (Playwright | HTTP) ─► target
                                              ▼
                        Detection Pipeline (canary ▸ signature ▸ refusal ▸ judge?)
                                              ▼
                        Evidence Store (SQLite + artifacts) ─► Report (JSON/MD/HTML/SARIF)
```

Full write-up: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
Security review: [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) ·
Roadmap: [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)

## Testing

```bash
pytest                     # unit + integration (uses the in-repo mock target)
mypy src                   # strict typing
ruff check src tests       # lint + security lint (bandit rules)
```

The test suite boots an **intentionally-vulnerable mock app** with known ground
truth and asserts the scanner fires in vulnerable mode and stays quiet in secure
mode — that's how precision is measured, not assumed.

## Operational commands

```bash
# List payloads
aisploit payloads

# Purge evidence older than the retention period (settings or --days override)
aisploit purge --days 30
```

## Safety controls

- **Scope guard** — fail-closed authorization gate; expired/broad scope stops the run
- **SSRF guard** — blocks cloud-metadata / loopback / RFC-1918 destinations unless
  `allow_private_destinations: true` is set in scope (metadata endpoints always blocked)
- **Rate limiter** — token-bucket throttled to the scope's declared ceiling
- **Evidence purge** — `aisploit purge` deletes old findings + screenshot artifacts
- **Canary-safe mutators** — payload mutators and canary placeholders are mutually
  exclusive (validated at load); a mutated canary token would corrupt detection

## What this tool deliberately does NOT ship

A curated library of working jailbreak/safety-bypass strings. The engine
supports them; you supply vetted payloads from public research. See the note in
`src/aisploit_recon/payloads/library/jailbreak.yaml`.

## License

MIT with a responsible-use rider. See [LICENSE](LICENSE).
