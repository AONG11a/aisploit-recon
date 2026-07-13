"""Evidence integrity + light-touch redaction.

Two responsibilities:

1. ``content_digest`` — produce a stable SHA-256 over evidence so a report
   can prove an artifact wasn't altered after the fact. Bug-bounty triagers
   care about tamper-evidence; a hash chain gives them that cheaply.

2. ``redact`` — best-effort masking of obvious secrets (API keys, bearer
   tokens, emails) that a *target* might have leaked back to us. This is
   defence for the operator: we don't want to persist someone else's
   production secret in plaintext on disk. Redaction is opt-in per report;
   the raw copy (if kept) is stored access-controlled and hashed.
"""

from __future__ import annotations

import hashlib
import re

# Patterns are intentionally conservative — better to under-redact and rely on
# the operator, than to mangle evidence and destroy a valid PoC. These target
# high-confidence secret shapes only.
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(sk-[A-Za-z0-9]{16,})\b"), "sk-<REDACTED>"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"), "gh_<REDACTED>"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AKIA<REDACTED>"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*"), "Bearer <REDACTED>"),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "<REDACTED_EMAIL>",
    ),
]


def content_digest(data: str | bytes) -> str:
    """Return a hex SHA-256 digest, prefixed for self-documentation."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def redact(text: str) -> str:
    """Mask high-confidence secret shapes. Idempotent."""
    out = text
    for pattern, replacement in _REDACTION_PATTERNS:
        out = pattern.sub(replacement, out)
    return out
