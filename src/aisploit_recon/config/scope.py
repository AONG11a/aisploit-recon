"""Authorization & scope models.

The scope config is the single most important safety control in this
project. It encodes *what you are allowed to test* and is enforced,
fail-closed, by ``core.scope_guard.ScopeGuard`` before any probe is sent.

Design rules baked into these models:
  * No implicit "test everything" — hosts must be listed explicitly.
  * Dangerously broad glob patterns (``*``, ``*.com``) are rejected at
    validation time, not left to bite you at runtime.
  * Authorization carries provenance (who authorized, when, reference)
    so it can be embedded into reports as a consent artifact.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator, model_validator


class AuthorizationProof(BaseModel):
    """Evidence that testing this target is permitted.

    This is not merely bookkeeping: it is emitted into every report so a
    triager (or your future self) can verify the engagement was in-scope.
    """

    program: str = Field(..., description="e.g. 'HackerOne:acme-corp' or 'internal:staging'")
    scope_reference: str = Field(..., description="URL/text pointing at the authoritative scope")
    authorized_by: str = Field(..., description="Person/handle who granted authorization")
    authorized_at: datetime
    expires_at: datetime | None = Field(
        default=None, description="If set, guard refuses to run past this time"
    )
    notes: str = ""

    @field_validator("authorized_at", "expires_at")
    @classmethod
    def _ensure_tz_aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            # Treat naive timestamps as UTC rather than guessing local time.
            return v.replace(tzinfo=UTC)
        return v


_DANGEROUS_HOST_PATTERNS = {"*", "*.*", "**"}


class ScopeRule(BaseModel):
    """Concrete allow/deny rules and rate constraints for an engagement."""

    allowed_hosts: list[str] = Field(
        ..., min_length=1, description="Glob patterns, e.g. ['chat.acme.com', '*.staging.acme.com']"
    )
    allowed_paths: list[str] = Field(default_factory=lambda: ["*"])
    denied_paths: list[str] = Field(default_factory=list)

    # Politeness / blast-radius controls. Defaults are deliberately gentle.
    max_requests_per_minute: int = Field(default=10, ge=1, le=600)
    max_concurrent: int = Field(default=2, ge=1, le=20)

    # Optional UTC testing window, e.g. (0, 6) => only 00:00-06:00 UTC.
    allowed_hours_utc: tuple[int, int] | None = None

    # SSRF guard: when False (default), probes to loopback / RFC-1918 /
    # metadata endpoints are blocked. Set True only for authorized internal
    # testing against private-network staging instances.
    allow_private_destinations: bool = False

    @field_validator("allowed_hosts")
    @classmethod
    def _reject_broad_hosts(cls, hosts: list[str]) -> list[str]:
        for h in hosts:
            host = h.strip().lower()
            if not host:
                raise ValueError("Empty host pattern is not allowed")
            if host in _DANGEROUS_HOST_PATTERNS:
                raise ValueError(f"Host pattern {h!r} is dangerously broad")
            # Reject a bare-TLD wildcard like '*.com' / '*.io' (one dot only).
            if host.startswith("*.") and host.count(".") == 1:
                raise ValueError(
                    f"Host pattern {h!r} matches an entire TLD; narrow it down"
                )
        return hosts

    @field_validator("allowed_hours_utc")
    @classmethod
    def _validate_window(cls, v: tuple[int, int] | None) -> tuple[int, int] | None:
        if v is None:
            return v
        start, end = v
        if not (0 <= start < 24 and 0 <= end <= 24):
            raise ValueError("allowed_hours_utc must be within 0..24")
        if start >= end:
            raise ValueError("allowed_hours_utc start must be < end (no wrap-around)")
        return v


class ScopeConfig(BaseModel):
    """Top-level engagement scope: proof + rules + safety toggles."""

    proof: AuthorizationProof
    rules: ScopeRule
    dry_run_first: bool = Field(
        default=True,
        description="When true, the CLI forces a dry-run preview before live probes",
    )

    @model_validator(mode="after")
    def _warn_on_prod_looking_hosts(self) -> ScopeConfig:
        # Not fatal — a bug-bounty scope legitimately includes prod hosts — but
        # we surface a structured hint elsewhere. Kept as a hook for the guard.
        return self
