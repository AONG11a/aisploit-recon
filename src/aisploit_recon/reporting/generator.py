"""Report generation.

Turns a campaign result into artifacts for different consumers:
  * JSON     — machine-readable, the source of truth.
  * Markdown — paste into a bug-bounty submission.
  * HTML     — human-readable review with evidence.
  * SARIF    — import into GitHub code scanning / CI gates.

Every report embeds the authorization proof as a *consent artifact* so a
reviewer can see the engagement was in-scope. Optional redaction masks
high-confidence secrets the target may have leaked back to us.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aisploit_recon.config.scope import ScopeConfig
from aisploit_recon.core.models import CampaignResult, Finding
from aisploit_recon.reporting.severity import Severity, score_finding
from aisploit_recon.utils.crypto import redact

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _finding_dict(finding: Finding, redact_secrets: bool) -> dict[str, object]:
    severity, score = score_finding(finding)
    snippet = finding.result.evidence
    reasoning = finding.result.reasoning
    if redact_secrets:
        snippet = redact(snippet)
        reasoning = redact(reasoning)
    return {
        "payload_id": finding.payload.id,
        "name": finding.payload.name,
        "category": finding.payload.category.value,
        "verdict": finding.result.verdict.value,
        "severity": severity.value,
        "score": score,
        "confidence": round(finding.result.confidence, 3),
        "detector": finding.result.detector,
        "evidence": snippet,
        "reasoning": reasoning,
        "canary": finding.canary,
        "evidence_digest": finding.evidence_digest,
        "screenshot": finding.screenshot_path,
        "references": finding.payload.references,
        "latency_ms": round(finding.latency_ms, 1),
    }


class ReportGenerator:
    def __init__(self, scope: ScopeConfig, redact_secrets: bool = True) -> None:
        self._scope = scope
        self._redact = redact_secrets
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _base_payload(self, result: CampaignResult, run_id: str) -> dict[str, object]:
        findings = sorted(
            (_finding_dict(f, self._redact) for f in result.findings),
            key=lambda d: d["score"],  # type: ignore[arg-type]
            reverse=True,
        )
        return {
            "run_id": run_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "target": result.target_url,
            "authorization": {
                "program": self._scope.proof.program,
                "scope_reference": self._scope.proof.scope_reference,
                "authorized_by": self._scope.proof.authorized_by,
                "authorized_at": self._scope.proof.authorized_at.isoformat(),
            },
            "summary": {
                "total_probes": result.total_probes,
                "findings": len(result.findings),
                "vulnerable": result.vulnerable_count,
                "inconclusive": result.inconclusive_count,
                "errors": result.errors,
            },
            "findings": findings,
        }

    def to_json(self, result: CampaignResult, run_id: str) -> str:
        return json.dumps(self._base_payload(result, run_id), indent=2, ensure_ascii=False)

    def to_markdown(self, result: CampaignResult, run_id: str) -> str:
        return self._env.get_template("report.md.j2").render(**self._base_payload(result, run_id))

    def to_html(self, result: CampaignResult, run_id: str) -> str:
        return self._env.get_template("report.html.j2").render(**self._base_payload(result, run_id))

    def to_sarif(self, result: CampaignResult, run_id: str) -> str:
        """Minimal SARIF 2.1.0 so findings import into GitHub / CI dashboards."""
        rules: dict[str, dict[str, object]] = {}
        results: list[dict[str, object]] = []
        for f in result.findings:
            severity, score = score_finding(f)
            rules.setdefault(
                f.payload.id,
                {
                    "id": f.payload.id,
                    "name": f.payload.name,
                    "shortDescription": {"text": f.payload.name},
                    "fullDescription": {"text": f.payload.description or f.payload.name},
                    "helpUri": f.payload.references[0] if f.payload.references else "",
                    "properties": {"category": f.payload.category.value},
                },
            )
            results.append(
                {
                    "ruleId": f.payload.id,
                    "level": _sarif_level(severity),
                    "message": {"text": f.result.reasoning},
                    "properties": {
                        "score": score,
                        "confidence": round(f.result.confidence, 3),
                        "verdict": f.result.verdict.value,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": result.target_url}
                            }
                        }
                    ],
                }
            )
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "aisploit-recon",
                            "version": "1.0.0",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def write_all(self, result: CampaignResult, run_id: str, out_dir: Path) -> dict[str, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        outputs = {
            "json": out_dir / f"{run_id}.json",
            "markdown": out_dir / f"{run_id}.md",
            "html": out_dir / f"{run_id}.html",
            "sarif": out_dir / f"{run_id}.sarif",
        }
        outputs["json"].write_text(self.to_json(result, run_id), encoding="utf-8")
        outputs["markdown"].write_text(self.to_markdown(result, run_id), encoding="utf-8")
        outputs["html"].write_text(self.to_html(result, run_id), encoding="utf-8")
        outputs["sarif"].write_text(self.to_sarif(result, run_id), encoding="utf-8")
        return outputs


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }[severity]
