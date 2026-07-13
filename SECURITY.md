# Security Policy

## Authorized use only

AISploit-Recon is a security testing tool designed exclusively for use against
targets you own or have **explicit written authorization** to test. Unauthorized
scanning of third-party systems may be illegal in your jurisdiction.

## Safety controls

The tool implements multiple layers of protection to keep operators within
bounds:

- **Scope guard** — deny-by-default authorization gate; rejects expired, broad,
  or out-of-scope targets before any probe is sent.
- **SSRF guard** — blocks cloud-metadata endpoints (169.254.169.254, etc.),
  loopback, link-local, and RFC-1918 addresses. Override for internal testing
  via `allow_private_destinations: true`; metadata endpoints are always blocked.
- **Rate limiter** — token-bucket throttled to the engagement scope's declared
  request ceiling.
- **Evidence retention** — `aisploit purge` deletes old findings and associated
  artifacts per the configured retention window.

## Reporting a vulnerability in this tool

Found a security issue in AISploit-Recon itself? Please report it privately:

1. **Do NOT open a public GitHub issue.**
2. Email the maintainer or open a private vulnerability report via GitHub's
   "Report a vulnerability" feature (Security tab → Advisories).
3. Include: description, reproduction steps, and impact assessment.
4. You will receive a response within 72 hours.

## Responsible disclosure

This tool's payload library deliberately does **not** ship working jailbreak or
safety-bypass strings. Operators are expected to source, vet, and authorize
their own payloads from public research (OWASP, Garak, PyRIT, disclosed reports).
