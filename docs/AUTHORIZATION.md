# Authorization & Responsible Use

This tool sends attacker-shaped traffic to a target. Doing that against a system
you are not authorized to test can be **illegal** (e.g. the US CFAA; Thailand's
Computer Crime Act B.E. 2550, sections 5–7 on unauthorized access) and will get a
bug-bounty report rejected or your account banned. The engine enforces an
authorization scope, fail-closed, to keep you on the right side of that line — but
the responsibility is ultimately yours.

## What counts as authorized

- **Your own systems** (self-hosted apps, staging you control).
- **In-scope bug-bounty targets** where the program's policy explicitly permits
  testing the AI feature and the technique. Read the scope; some programs exclude
  automated scanning or specific endpoints.
- **A written engagement** (pentest SOW) naming the target and window.

## What is NOT authorized

- Any host not listed in your `scope.yaml`.
- Endpoints excluded by the program even if the host is in scope.
- Techniques the program forbids (e.g. automated scanning, DoS-style volume).
- "It was probably fine" — if you can't point to written permission, stop.

## How the tool helps you stay compliant

1. **Fail-closed scope guard.** Every target is checked before any request; an
   out-of-scope host, a non-http scheme, a denied path, or expired authorization
   aborts with a `ScopeViolation`.
2. **Validation-time safety.** Dangerously broad host globs (`*`, `*.com`) are
   rejected when the scope is loaded, not at 3 a.m. mid-scan.
3. **Dry-run by default.** `scan` shows exactly what *would* be sent and sends
   nothing until you add `--live`.
4. **Rate limits & concurrency caps.** Defaults are gentle; respect the program's
   stated limits by setting `max_requests_per_minute` accordingly.
5. **Consent artifact in reports.** Your authorization (program, reference, who
   authorized, when) is embedded in every report so a triager can verify scope.

## Authoring a scope file

See `examples/scope.example.yaml`. At minimum:

```yaml
proof:
  program: "HackerOne:acme-corp"
  scope_reference: "https://hackerone.com/acme-corp/policy"
  authorized_by: "your-handle"
  authorized_at: "2026-07-14T00:00:00Z"
  expires_at: "2026-08-14T00:00:00Z"
rules:
  allowed_hosts: ["chat.acme.com"]     # explicit; never "*"
  allowed_paths: ["/api/chat*"]
  denied_paths: ["/admin/*"]
  max_requests_per_minute: 10
```

## Handling what you find

- Findings may contain a target's **real secrets or user data**. Treat the
  evidence directory as sensitive: it is created `0600`, `.gitignore`d, and reports
  redact high-confidence secrets by default. Don't paste raw secrets into public
  tickets; reference the digest and share redacted evidence.
- Follow the program's **disclosure policy**. Report through the proper channel;
  don't publish before coordinated disclosure.

## The tool's own limits (by design)

It ships **no** working jailbreak/safety-bypass library. The engine supports such
probes, but curating and sending them against an in-scope target — and owning that
choice — is your responsibility as a researcher. See
`src/aisploit_recon/payloads/library/jailbreak.yaml`.

If you're unsure whether something is in scope: **don't send it.** Ask the program.
