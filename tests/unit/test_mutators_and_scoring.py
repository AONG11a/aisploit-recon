"""Property-based and unit tests for mutators, rate limiting, and scoring."""

from __future__ import annotations

import base64
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from aisploit_recon.core.models import Finding
from aisploit_recon.core.session import RateLimiter
from aisploit_recon.detection.types import DetectionResult, Verdict
from aisploit_recon.payloads.models import DetectionStrategy, Payload, PayloadCategory
from aisploit_recon.payloads.mutators import MUTATORS, apply_mutators
from aisploit_recon.reporting.severity import Severity, score_finding


@given(st.text())
def test_mutators_never_crash(text: str) -> None:
    for name in MUTATORS:
        apply_mutators(text, [name])  # must not raise


@given(st.text())
def test_base64_roundtrips(text: str) -> None:
    encoded = apply_mutators(text, ["base64"])
    assert base64.b64decode(encoded).decode("utf-8") == text


def test_unknown_mutator_raises() -> None:
    with pytest.raises(ValueError):
        apply_mutators("x", ["does-not-exist"])


def _finding(sev_base: float, conf: float, verdict: Verdict) -> Finding:
    payload = Payload(
        id="T-1",
        category=PayloadCategory.PROMPT_INJECTION,
        name="t",
        template="{canary}",
        detection=DetectionStrategy.CANARY,
        severity_base=sev_base,
    )
    result = DetectionResult(verdict=verdict, confidence=conf, detector="canary")
    return Finding(payload=payload, result=result)


def test_low_confidence_reduces_severity() -> None:
    high_conf = score_finding(_finding(8.0, 1.0, Verdict.VULNERABLE))[1]
    low_conf = score_finding(_finding(8.0, 0.2, Verdict.VULNERABLE))[1]
    assert high_conf > low_conf


def test_inconclusive_is_dampened() -> None:
    vuln = score_finding(_finding(8.0, 0.9, Verdict.VULNERABLE))[1]
    inconc = score_finding(_finding(8.0, 0.9, Verdict.INCONCLUSIVE))[1]
    assert inconc < vuln


def test_critical_bucketing() -> None:
    sev, _ = score_finding(_finding(10.0, 1.0, Verdict.VULNERABLE))
    assert sev is Severity.CRITICAL


async def test_rate_limiter_enforces_ceiling() -> None:
    """Draining the bucket forces the next acquire to wait for a refill, which
    proves the limiter actually throttles (not just that time passes). Uses a
    fast refill (10 tokens/s) so the wait is ~0.1s, not the 60s a capacity-1
    limiter would take — keeps the suite/CI quick (was backlog #6)."""
    limiter = RateLimiter(max_per_minute=600)  # 10 tokens/s, capacity 600
    for _ in range(600):
        await limiter.acquire()  # drain the initially-full bucket (instant)

    start = time.monotonic()
    await limiter.acquire()  # bucket empty -> must wait ~1/10s for a refill
    elapsed = time.monotonic() - start

    assert elapsed >= 0.05, f"Rate limiter did not throttle; elapsed={elapsed:.3f}s"
    assert elapsed < 5.0, f"Rate limiter blocked far too long; elapsed={elapsed:.3f}s"
