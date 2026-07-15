"""D5b: export / diff / CI-gate logic."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisploit_recon.core.models import Finding
from aisploit_recon.detection.types import DetectionResult, Verdict
from aisploit_recon.evidence.store import EvidenceStore
from aisploit_recon.payloads.models import DetectionStrategy, Payload, PayloadCategory
from aisploit_recon.reporting.export import (
    ExportFormat,
    ci_gate,
    diff_runs,
    export_finding,
    parse_fail_on,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_payload(pid: str = "PI-001", sev: float = 8.0) -> Payload:
    return Payload(
        id=pid,
        category=PayloadCategory.PROMPT_INJECTION,
        name="Test Probe",
        template="{canary}",
        detection=DetectionStrategy.CANARY,
        severity_base=sev,
    )


def _make_finding(
    pid: str = "PI-001",
    verdict: Verdict = Verdict.VULNERABLE,
    confidence: float = 0.95,
    target: str = "http://target.local/chat",
    sev: float = 8.0,
) -> Finding:
    payload = _make_payload(pid, sev)
    result = DetectionResult(verdict=verdict, confidence=confidence, detector="canary")
    return Finding(payload=payload, result=result, target_url=target)


def _store_with_findings(tmp_path: Path, findings: list[Finding], run_id: str) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "test.db")
    for f in findings:
        store.record_finding(run_id, f)
    return store


# ---------------------------------------------------------------------------
# parse_fail_on
# ---------------------------------------------------------------------------


def test_parse_fail_on_levels() -> None:
    assert parse_fail_on("critical") == 5
    assert parse_fail_on("high") == 4
    assert parse_fail_on("medium") == 3
    assert parse_fail_on("low") == 2
    assert parse_fail_on("info") == 1


def test_parse_fail_on_case_insensitive() -> None:
    assert parse_fail_on("HIGH") == 4
    assert parse_fail_on("Critical") == 5


def test_parse_fail_on_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid --fail-on"):
        parse_fail_on("urgent")


# ---------------------------------------------------------------------------
# ci_gate
# ---------------------------------------------------------------------------


def test_ci_gate_passes_when_no_severe_findings(tmp_path: Path) -> None:
    """A run with only LOW findings passes a 'high' gate."""
    f = _make_finding(verdict=Verdict.VULNERABLE, confidence=0.3, sev=2.0)
    store = _store_with_findings(tmp_path, [f], "run-1")
    passed, triggers = ci_gate(store, "run-1", parse_fail_on("high"))
    assert passed is True
    assert triggers == []
    store.close()


def test_ci_gate_fails_on_high_severity(tmp_path: Path) -> None:
    """A HIGH finding fails a 'high' gate."""
    f = _make_finding(verdict=Verdict.VULNERABLE, confidence=0.95, sev=8.0)
    store = _store_with_findings(tmp_path, [f], "run-1")
    passed, triggers = ci_gate(store, "run-1", parse_fail_on("high"))
    assert passed is False
    assert len(triggers) == 1
    assert triggers[0]["payload_id"] == "PI-001"
    store.close()


def test_ci_gate_empty_run_passes(tmp_path: Path) -> None:
    """A run with no findings passes any gate."""
    store = _store_with_findings(tmp_path, [], "run-1")
    passed, triggers = ci_gate(store, "run-1", parse_fail_on("critical"))
    assert passed is True
    assert triggers == []
    store.close()


def test_ci_gate_critical_only(tmp_path: Path) -> None:
    """A HIGH finding passes a 'critical' gate (threshold too high)."""
    f = _make_finding(verdict=Verdict.VULNERABLE, confidence=0.85, sev=7.5)
    store = _store_with_findings(tmp_path, [f], "run-1")
    passed, _triggers = ci_gate(store, "run-1", parse_fail_on("critical"))
    assert passed is True
    store.close()


# ---------------------------------------------------------------------------
# diff_runs
# ---------------------------------------------------------------------------


def test_diff_new_finding(tmp_path: Path) -> None:
    """Run B has a finding not in run A → new."""
    f1 = _make_finding(pid="PI-001", target="http://t/chat")
    f2 = _make_finding(pid="PI-002", target="http://t/chat")
    store = EvidenceStore(tmp_path / "diff.db")
    store.record_finding("runA", f1)
    store.record_finding("runB", f1)  # unchanged
    store.record_finding("runB", f2)  # new

    result = diff_runs(store, "runA", "runB")
    assert len(result.new_findings) == 1
    assert result.new_findings[0]["payload_id"] == "PI-002"
    assert len(result.unchanged_findings) == 1
    assert len(result.resolved_findings) == 0
    store.close()


def test_diff_resolved_finding(tmp_path: Path) -> None:
    """Run A has a finding missing from run B → resolved."""
    f1 = _make_finding(pid="PI-001")
    f2 = _make_finding(pid="PI-002")
    store = EvidenceStore(tmp_path / "diff2.db")
    store.record_finding("runA", f1)
    store.record_finding("runA", f2)
    store.record_finding("runB", f1)  # PI-002 resolved

    result = diff_runs(store, "runA", "runB")
    assert len(result.resolved_findings) == 1
    assert result.resolved_findings[0]["payload_id"] == "PI-002"
    assert len(result.new_findings) == 0
    store.close()


def test_diff_no_changes(tmp_path: Path) -> None:
    """Identical runs → no changes."""
    f1 = _make_finding(pid="PI-001")
    store = EvidenceStore(tmp_path / "diff3.db")
    store.record_finding("runA", f1)
    store.record_finding("runB", f1)

    result = diff_runs(store, "runA", "runB")
    assert result.has_changes is False
    assert len(result.unchanged_findings) == 1
    store.close()


# ---------------------------------------------------------------------------
# export_finding
# ---------------------------------------------------------------------------


def test_export_markdown(tmp_path: Path) -> None:
    """Markdown export contains key fields."""
    f = _make_finding()
    store = _store_with_findings(tmp_path, [f], "run-1")
    report = export_finding(store, "run-1", "PI-001", ExportFormat.MARKDOWN)
    assert "PI-001" in report
    assert "canary" in report.lower() or "evidence" in report.lower()
    store.close()


def test_export_hackerone(tmp_path: Path) -> None:
    """HackerOne export has Summary, Steps, Impact sections."""
    f = _make_finding()
    store = _store_with_findings(tmp_path, [f], "run-1")
    report = export_finding(store, "run-1", "PI-001", ExportFormat.HACKERONE)
    assert "## Summary" in report
    assert "## Steps to Reproduce" in report
    assert "## Impact" in report
    assert "## Evidence" in report
    store.close()


def test_export_huntr(tmp_path: Path) -> None:
    """huntr export has Description, PoC, Severity."""
    f = _make_finding()
    store = _store_with_findings(tmp_path, [f], "run-1")
    report = export_finding(store, "run-1", "PI-001", ExportFormat.HUNTR)
    assert "## Description" in report
    assert "## Proof of Concept" in report
    assert "## Severity" in report
    store.close()


def test_export_not_found_raises(tmp_path: Path) -> None:
    """Exporting a non-existent finding raises KeyError."""
    store = EvidenceStore(tmp_path / "empty.db")
    with pytest.raises(KeyError):
        export_finding(store, "no-such-run", "no-such-payload", ExportFormat.MARKDOWN)
    store.close()
