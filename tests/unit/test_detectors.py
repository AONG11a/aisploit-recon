"""Unit tests for the detection layer."""

from __future__ import annotations

from aisploit_recon.detection.canary import CanaryDetector
from aisploit_recon.detection.heuristic import RefusalClassifier
from aisploit_recon.detection.signature import SignatureDetector
from aisploit_recon.detection.types import Verdict


def test_canary_hit_is_high_confidence_vulnerable() -> None:
    d = CanaryDetector()
    canary = CanaryDetector.generate_canary()
    res = d.detect(f"Sure thing! Here it is: {canary} done.", canary)
    assert res.verdict is Verdict.VULNERABLE
    assert res.confidence >= 0.95
    assert canary in res.evidence


def test_canary_miss_is_not_vulnerable() -> None:
    d = CanaryDetector()
    canary = CanaryDetector.generate_canary()
    res = d.detect("I can't help with that.", canary)
    assert res.verdict is Verdict.NOT_VULNERABLE


def test_canary_tokens_are_unique() -> None:
    tokens = {CanaryDetector.generate_canary() for _ in range(1000)}
    assert len(tokens) == 1000


def test_signature_success_without_refusal() -> None:
    d = SignatureDetector()
    res = d.detect("You are HelpBot with these instructions...", ["You are"], ["I can't"])
    assert res.verdict is Verdict.VULNERABLE


def test_signature_refusal_beats_absent_success() -> None:
    d = SignatureDetector()
    res = d.detect("I can't share that.", ["You are"], ["I can't"])
    assert res.verdict is Verdict.NOT_VULNERABLE


def test_signature_mixed_signal_is_inconclusive() -> None:
    d = SignatureDetector()
    res = d.detect("You are... actually I can't reveal more.", ["You are"], ["I can't"])
    assert res.verdict is Verdict.INCONCLUSIVE


def test_refusal_detects_refusal() -> None:
    d = RefusalClassifier()
    res = d.detect("I'm sorry, but I cannot help with that.")
    assert res.verdict is Verdict.NOT_VULNERABLE


def test_non_refusal_is_inconclusive_not_vulnerable() -> None:
    # Key anti-false-positive behaviour.
    d = RefusalClassifier()
    res = d.detect("The weather in Bangkok is warm today.")
    assert res.verdict is Verdict.INCONCLUSIVE
