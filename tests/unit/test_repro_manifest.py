"""D5: request-manifest capture, redaction, curl repro, and evidence persistence."""

from __future__ import annotations

import json
from pathlib import Path

from aisploit_recon.core.models import Finding
from aisploit_recon.detection.types import DetectionResult, Verdict
from aisploit_recon.evidence.store import EvidenceStore
from aisploit_recon.payloads.models import DetectionStrategy, Payload, PayloadCategory
from aisploit_recon.reporting.generator import _curl_repro, _repro
from aisploit_recon.transport.http_driver import HttpConfig, HttpDriver, _mask_headers

_SECRET = "Bearer sk-SUPERSECRETTOKENvalue1234567890"  # noqa: S105 (test fixture)


def test_mask_headers_masks_auth() -> None:
    masked = _mask_headers({"Authorization": _SECRET, "X-Trace": "abc"})
    assert masked["Authorization"] == "<REDACTED>"
    assert masked["X-Trace"] == "abc"


def test_http_manifest_never_contains_secret() -> None:
    driver = HttpDriver(
        HttpConfig(body_template={"message": "{payload}"}, response_path="response"),
        storage_headers={"Authorization": _SECRET},
    )
    manifest = driver._request_manifest("http://t/chat", {"message": "hi {canary}"})
    blob = json.dumps(manifest)
    assert "SUPERSECRET" not in blob
    assert manifest["headers"]["Authorization"] == "<REDACTED>"
    assert manifest["transport"] == "http"


def test_curl_repro_shape() -> None:
    manifest = {
        "transport": "http",
        "method": "POST",
        "url": "http://t/chat",
        "headers": {"Authorization": "<REDACTED>"},
        "body": {"message": "hello"},
        "response_path": "response",
        "stream": False,
    }
    curl = _curl_repro(manifest)
    assert curl.startswith("curl ")
    assert "-X POST" in curl
    assert "http://t/chat" in curl
    assert "--data" in curl and "hello" in curl
    assert "<REDACTED>" in curl


def test_curl_repro_streaming_adds_no_buffer() -> None:
    manifest = {
        "transport": "http",
        "method": "POST",
        "url": "http://t/s",
        "headers": {},
        "body": {"m": "x"},
        "response_path": "response",
        "stream": True,
    }
    assert "--no-buffer" in _curl_repro(manifest)


def test_repro_dispatch() -> None:
    assert _repro(None) is None
    assert _repro(
        {
            "transport": "playwright",
            "url": "http://t/",
            "input_selector": "#in",
            "submit_selector": "#go",
            "response_selector": "#out",
        }
    ).startswith("Playwright:")


def _finding_with_manifest() -> Finding:
    payload = Payload(
        id="PI-001",
        category=PayloadCategory.PROMPT_INJECTION,
        name="t",
        template="{canary}",
        detection=DetectionStrategy.CANARY,
        severity_base=8.0,
    )
    result = DetectionResult(verdict=Verdict.VULNERABLE, confidence=0.95, detector="canary")
    return Finding(
        payload=payload,
        result=result,
        target_url="http://t/chat",
        request_manifest={
            "transport": "http",
            "method": "POST",
            "url": "http://t/chat",
            "headers": {},
            "body": {"message": "x"},
            "response_path": "response",
            "stream": False,
        },
    )


def test_evidence_store_persists_manifest_and_severity(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "ev.db")
    store.record_finding("run-1", _finding_with_manifest())
    cur = store._conn.execute(
        "SELECT severity, severity_score, request_json FROM findings WHERE run_id=?",
        ("run-1",),
    )
    severity, score, request_json = cur.fetchone()
    assert severity and score is not None
    assert request_json is not None and json.loads(request_json)["transport"] == "http"
    store.close()
