"""Shared detection value objects.

Kept in their own module (not in ``pipeline``) so individual detectors can
import them without creating an import cycle with the pipeline that
orchestrates them. This is a deliberate fix over the naive layout where the
pipeline both *defines* the result type and *imports* the detectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass(frozen=True)
class DetectionResult:
    """Outcome of running one detector against one response.

    ``frozen`` because a result is a record of what happened; mutating it
    after the fact would undermine the evidence trail.
    """

    verdict: Verdict
    confidence: float  # 0.0-1.0
    detector: str
    evidence: str = ""  # the substring/segment that triggered the verdict
    reasoning: str = ""
    raw_response: str = ""
    signals: tuple[str, ...] = field(default_factory=tuple)

    def with_confidence(self, confidence: float, reasoning: str | None = None) -> DetectionResult:
        """Return a copy with adjusted confidence (frozen-friendly)."""
        return DetectionResult(
            verdict=self.verdict,
            confidence=max(0.0, min(1.0, confidence)),
            detector=self.detector,
            evidence=self.evidence,
            reasoning=reasoning if reasoning is not None else self.reasoning,
            raw_response=self.raw_response,
            signals=self.signals,
        )
