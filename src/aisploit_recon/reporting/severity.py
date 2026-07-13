"""Severity scoring.

Combines a payload's base severity with the detector's confidence, so a
low-confidence signal never masquerades as a critical finding. Inconclusive
verdicts are further dampened. Over-reporting severity erodes trust with
triagers faster than anything else, so this errs conservative.
"""

from __future__ import annotations

from enum import Enum

from aisploit_recon.core.models import Finding
from aisploit_recon.detection.types import Verdict


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def score_finding(finding: Finding) -> tuple[Severity, float]:
    base = finding.payload.severity_base
    conf = finding.result.confidence

    # Confidence acts as a multiplier in [0.5, 1.0]: even a max-confidence hit
    # keeps its base; a coin-flip halves it.
    adjusted = base * (0.5 + 0.5 * conf)

    if finding.result.verdict is Verdict.INCONCLUSIVE:
        adjusted *= 0.5

    return _bucket(adjusted), round(adjusted, 2)


def _bucket(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 1.0:
        return Severity.LOW
    return Severity.INFO
