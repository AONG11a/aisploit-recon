"""Tests for D1: baseline-diff detection.

Verifies that a canary hit against an echoing target is downgraded to
INCONCLUSIVE (false-positive suppression) while a canary hit against a
non-echoing vulnerable target remains VULNERABLE at high confidence.
"""

from __future__ import annotations

from aisploit_recon.core.baseline import Baseline, build_baseline, generate_control_token
from aisploit_recon.detection.canary import CanaryDetector
from aisploit_recon.detection.types import Verdict


def test_generate_control_token_format() -> None:
    token = generate_control_token()
    assert token.startswith("CONTROL_")
    assert token.endswith("_END")
    # Two calls produce different tokens.
    assert generate_control_token() != token


def test_build_baseline_detected() -> None:
    token = generate_control_token()
    response = f"Hello! Here is your code: {token}. Thanks!"
    baseline = build_baseline(response, token)
    assert baseline.reflects_input is True
    assert token in baseline.control_excerpt
    assert baseline.control_digest.startswith("sha256:")


def test_build_baseline_not_detected() -> None:
    token = generate_control_token()
    response = "Hello! I don't see any code in my message."
    baseline = build_baseline(response, token)
    assert baseline.reflects_input is False
    assert baseline.control_excerpt == ""


def test_canary_hit_on_echoing_target_is_inconclusive() -> None:
    """The key false-positive suppression test."""
    d = CanaryDetector()
    canary = CanaryDetector.generate_canary()
    baseline = Baseline(reflects_input=True, control_digest="sha256:abc", control_excerpt="...")
    res = d.detect(f"Sure! {canary}", canary, baseline=baseline)
    assert res.verdict is Verdict.INCONCLUSIVE
    assert res.confidence < 0.5
    assert res.baseline_delta != ""


def test_canary_hit_on_non_echoing_target_remains_vulnerable() -> None:
    """Non-echo vulnerable target must still be VULNERABLE at high confidence."""
    d = CanaryDetector()
    canary = CanaryDetector.generate_canary()
    baseline = Baseline(reflects_input=False, control_digest="sha256:abc", control_excerpt="")
    res = d.detect(f"Sure! {canary}", canary, baseline=baseline)
    assert res.verdict is Verdict.VULNERABLE
    assert res.confidence >= 0.95
    assert res.baseline_delta == ""


def test_canary_hit_without_baseline_remains_vulnerable() -> None:
    """When baseline_diff is disabled, behaviour is unchanged (backward compat)."""
    d = CanaryDetector()
    canary = CanaryDetector.generate_canary()
    res = d.detect(f"Sure! {canary}", canary, baseline=None)
    assert res.verdict is Verdict.VULNERABLE
    assert res.confidence >= 0.95


def test_canary_miss_on_echoing_target_is_still_not_vulnerable() -> None:
    d = CanaryDetector()
    canary = CanaryDetector.generate_canary()
    baseline = Baseline(reflects_input=True, control_digest="sha256:abc", control_excerpt="...")
    res = d.detect("I can't help with that.", canary, baseline=baseline)
    assert res.verdict is Verdict.NOT_VULNERABLE
