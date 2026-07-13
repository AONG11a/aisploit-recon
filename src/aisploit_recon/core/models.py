"""Core domain models produced by a campaign run."""

from __future__ import annotations

from dataclasses import dataclass, field

from aisploit_recon.detection.types import DetectionResult
from aisploit_recon.payloads.models import Payload


@dataclass
class Finding:
    payload: Payload
    result: DetectionResult
    canary: str | None = None
    target_url: str = ""
    latency_ms: float = 0.0
    screenshot_path: str | None = None
    evidence_digest: str | None = None  # SHA-256 of the raw response


@dataclass
class CampaignResult:
    target_url: str = ""
    findings: list[Finding] = field(default_factory=list)
    total_probes: int = 0
    errors: int = 0

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.result.verdict.value == "vulnerable")

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for f in self.findings if f.result.verdict.value == "inconclusive")
