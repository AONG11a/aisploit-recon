"""Evidence records persisted to SQLite for reproducibility & audit."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EvidenceRecord:
    run_id: str
    payload_id: str
    target_url: str
    verdict: str
    confidence: float
    detector: str
    canary: str | None
    evidence_snippet: str
    raw_response_digest: str
    screenshot_path: str | None
    latency_ms: float
    created_at: str  # ISO-8601 UTC
    request_json: str | None = None  # D5: redacted request manifest (JSON)
