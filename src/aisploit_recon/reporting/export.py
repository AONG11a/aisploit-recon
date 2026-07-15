"""D5b: Platform export, run-diff, and CI-gate logic.

Three capabilities for workflow adoption:

1. **Export** — render a finding as a paste-ready bug-bounty submission
   (HackerOne, huntr) or plain Markdown.
2. **Diff** — compare two runs and report new / resolved / unchanged findings.
3. **CI-gate** — evaluate findings against a severity threshold and decide
   whether the run passes (exit 0) or fails (exit non-zero).

All three read from the EvidenceStore so they work on any past run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from aisploit_recon.evidence.store import EvidenceStore


class ExportFormat(str, Enum):
    HACKERONE = "hackerone"
    HUNTR = "huntr"
    MARKDOWN = "markdown"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_finding(
    store: EvidenceStore,
    run_id: str,
    payload_id: str,
    fmt: ExportFormat,
) -> str:
    """Export a single finding from the store in the requested format.

    The finding is identified by ``run_id`` + ``payload_id`` (the natural key
    used by the diff logic). Returns a formatted string ready to paste.
    """
    row = store.fetch_finding(run_id, payload_id)
    if row is None:
        raise KeyError(
            f"No finding found for run_id={run_id!r}, payload_id={payload_id!r}"
        )

    severity = str(row.get("severity", "unknown"))
    conf_raw = row.get("confidence", 0.0)
    confidence = float(conf_raw) if isinstance(conf_raw, (int, float)) else 0.0
    evidence = str(row.get("evidence_snippet", ""))
    target = str(row.get("target_url", ""))
    detector = str(row.get("detector", ""))
    canary = str(row.get("canary") or "")
    name = str(row.get("name", payload_id))

    if fmt is ExportFormat.HACKERONE:
        return _format_hackerone(
            payload_id, name, severity, confidence,
            target, evidence, detector, canary,
        )
    if fmt is ExportFormat.HUNTR:
        return _format_huntr(
            payload_id, name, severity, confidence,
            target, evidence, detector, canary,
        )
    # markdown
    return _format_markdown(
        payload_id, name, severity, confidence,
        target, evidence, detector, canary,
    )


def _common_header(
    title: str,
    payload_id: str,
    severity: str,
    confidence: float,
    target: str,
) -> list[str]:
    return [
        f"# {title}",
        f"**Payload ID:** {payload_id}",
        f"**Severity:** {severity}",
        f"**Confidence:** {confidence:.1%}",
        f"**Target:** {target}",
        "",
    ]


def _format_hackerone(
    payload_id: str,
    name: str,
    severity: str,
    confidence: float,
    target: str,
    evidence: str,
    detector: str,
    canary: str,
) -> str:
    """HackerOne report format: Summary → Impact → Steps to Reproduce."""
    lines = _common_header(name, payload_id, severity, confidence, target)
    lines += [
        "## Summary",
        f"The target exhibited a `{detector}` signal indicating a potential "
        f"LLM security weakness. The probe `{payload_id}` triggered with "
        f"{confidence:.0%} confidence.",
        "",
        "## Steps to Reproduce",
        f"1. Send the probe payload `{payload_id}` to `{target}`.",
        f"2. Observe the response for `{detector}` indicators.",
        "",
    ]
    if canary:
        lines += [f"**Canary token:** `{canary}`", ""]
    lines += [
        "## Evidence",
        "```",
        evidence[:4000],
        "```",
        "",
        "## Impact",
        "An attacker could exploit this weakness to manipulate the model's "
        "behavior, potentially extracting sensitive data or bypassing safety "
        "guardrails.",
    ]
    return "\n".join(lines)


def _format_huntr(
    payload_id: str,
    name: str,
    severity: str,
    confidence: float,
    target: str,
    evidence: str,
    detector: str,
    canary: str,
) -> str:
    """huntr.dev report format: concise, structured for API submission."""
    lines = _common_header(name, payload_id, severity, confidence, target)
    lines += [
        "## Description",
        f"Probe `{payload_id}` detected a `{detector}` signal at `{target}`.",
        "",
        "## Proof of Concept",
        f"Canary: `{canary}`" if canary else "N/A",
        "",
        "```",
        evidence[:4000],
        "```",
        "",
        "## Severity",
        f"Rated **{severity}** based on payload base score and detector "
        f"confidence ({confidence:.0%}).",
    ]
    return "\n".join(lines)


def _format_markdown(
    payload_id: str,
    name: str,
    severity: str,
    confidence: float,
    target: str,
    evidence: str,
    detector: str,
    canary: str,
) -> str:
    """Plain Markdown export — the raw finding for reference."""
    lines = _common_header(name, payload_id, severity, confidence, target)
    lines += [
        f"**Detector:** {detector}",
        f"**Canary:** `{canary}`" if canary else "",
        "",
        "## Evidence",
        "```",
        evidence[:4000],
        "```",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    """Result of comparing two runs."""
    new_findings: list[dict[str, str]] = field(default_factory=list)
    resolved_findings: list[dict[str, str]] = field(default_factory=list)
    unchanged_findings: list[dict[str, str]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.resolved_findings)


def diff_runs(
    store: EvidenceStore,
    run_a: str,
    run_b: str,
) -> DiffResult:
    """Diff findings between two runs.

    A finding is identified by the tuple ``(payload_id, target_url)``.
    - **New:** in run_b but not run_a.
    - **Resolved:** in run_a but not run_b.
    - **Unchanged:** in both.
    """
    rows_a = store.fetch_run(run_a)
    rows_b = store.fetch_run(run_b)

    key_a = {_finding_key(r) for r in rows_a}
    key_b = {_finding_key(r) for r in rows_b}

    def _info(r: dict[str, object]) -> dict[str, str]:
        return {
            "payload_id": str(r["payload_id"]),
            "target_url": str(r["target_url"]),
            "verdict": str(r["verdict"]),
        }

    result = DiffResult()
    for r in rows_b:
        key = _finding_key(r)
        if key not in key_a:
            result.new_findings.append(_info(r))
        else:
            result.unchanged_findings.append(_info(r))
    for r in rows_a:
        key = _finding_key(r)
        if key not in key_b:
            result.resolved_findings.append(_info(r))
    return result


def _finding_key(row: dict[str, object]) -> tuple[str, str]:
    """Natural key for comparing findings across runs."""
    return (str(row["payload_id"]), str(row["target_url"]))


# ---------------------------------------------------------------------------
# CI-gate
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def parse_fail_on(spec: str) -> int:
    """Parse a ``--fail-on`` severity spec into a numeric threshold.

    Examples: ``high`` → fail on HIGH+CRITICAL; ``critical`` → CRITICAL only;
    ``medium`` → MEDIUM+HIGH+CRITICAL.

    Returns the minimum ``_SEVERITY_ORDER`` value that triggers a failure.
    """
    level = spec.strip().lower()
    if level not in _SEVERITY_ORDER:
        raise ValueError(
            f"Invalid --fail-on value {spec!r}. "
            f"Use one of: {', '.join(_SEVERITY_ORDER)}"
        )
    return _SEVERITY_ORDER[level]


def ci_gate(
    store: EvidenceStore,
    run_id: str,
    fail_threshold: int,
) -> tuple[bool, list[dict[str, str]]]:
    """Evaluate a run against a CI severity gate.

    Returns ``(passed, triggering_findings)``. ``passed`` is True when no
    finding meets or exceeds the threshold; the triggering list contains the
    findings that caused the gate to fail (empty when passed).
    """
    rows = store.fetch_run(run_id)
    triggering: list[dict[str, str]] = []
    for r in rows:
        sev = str(r.get("severity", "info")).lower()
        if _SEVERITY_ORDER.get(sev, 0) >= fail_threshold:
            triggering.append(
                {"payload_id": str(r["payload_id"]),
                 "target_url": str(r["target_url"]),
                 "severity": sev,
                 "verdict": str(r["verdict"])}
            )
    return (len(triggering) == 0), triggering
