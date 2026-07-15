"""Evidence store (SQLite).

Persists one row per finding so results are auditable and reproducible across
runs. All writes use parameterised queries (never string-formatted SQL) — the
tool must not itself be injectable. The raw response is stored as a digest by
default; keeping the full plaintext is opt-in because it may contain a target's
leaked secrets.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aisploit_recon.core.models import Finding
from aisploit_recon.evidence.models import EvidenceRecord
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    payload_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    detector TEXT NOT NULL,
    canary TEXT,
    evidence_snippet TEXT,
    raw_response_digest TEXT NOT NULL,
    screenshot_path TEXT,
    severity TEXT,
    severity_score REAL,
    latency_ms REAL,
    request_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class EvidenceStore:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.executescript(_SCHEMA)
        self._ensure_columns()
        self._conn.commit()
        # The evidence DB may contain a target's leaked data. Restrict it to the
        # owner. No-op / best-effort on platforms without POSIX permissions.
        with contextlib.suppress(OSError):
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    def _ensure_columns(self) -> None:
        """Add columns introduced after a DB was first created (idempotent)."""
        cur = self._conn.execute("PRAGMA table_info(findings)")
        cols = {row[1] for row in cur.fetchall()}
        if "request_json" not in cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN request_json TEXT")

    def record_finding(self, run_id: str, finding: Finding) -> None:
        from aisploit_recon.reporting.severity import score_finding

        severity, score = score_finding(finding)
        request_json = (
            json.dumps(finding.request_manifest, ensure_ascii=False)
            if finding.request_manifest is not None else None
        )
        rec = EvidenceRecord(
            run_id=run_id,
            payload_id=finding.payload.id,
            target_url=finding.target_url,
            verdict=finding.result.verdict.value,
            confidence=finding.result.confidence,
            detector=finding.result.detector,
            canary=finding.canary,
            evidence_snippet=finding.result.evidence[:2000],
            raw_response_digest=finding.evidence_digest or "",
            screenshot_path=finding.screenshot_path,
            latency_ms=finding.latency_ms,
            request_json=request_json,
            created_at=datetime.now(UTC).isoformat(),
        )
        self._conn.execute(
            """
            INSERT INTO findings (
                run_id, payload_id, target_url, verdict, confidence, detector,
                canary, evidence_snippet, raw_response_digest, screenshot_path,
                severity, severity_score, latency_ms, request_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec.run_id, rec.payload_id, rec.target_url, rec.verdict,
                rec.confidence, rec.detector, rec.canary, rec.evidence_snippet,
                rec.raw_response_digest, rec.screenshot_path,
                severity.value, score, rec.latency_ms, rec.request_json,
                rec.created_at,
            ),
        )
        self._conn.commit()

    def purge_old(self, retention_days: int) -> int:
        """Delete findings older than ``retention_days``. Also attempts to
        delete associated screenshot files. Returns the number of rows deleted.
        """
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()

        # Collect screenshot paths before deleting (for file cleanup).
        cursor = self._conn.execute(
            "SELECT screenshot_path FROM findings "
            "WHERE created_at < ? AND screenshot_path IS NOT NULL",
            (cutoff,),
        )
        for (path,) in cursor.fetchall():
            with contextlib.suppress(OSError):
                Path(path).unlink(missing_ok=True)

        cursor = self._conn.execute(
            "DELETE FROM findings WHERE created_at < ?",
            (cutoff,),
        )
        self._conn.commit()
        deleted = cursor.rowcount
        if deleted:
            log.info("evidence.purged", rows=deleted, retention_days=retention_days)
        return deleted

    def close(self) -> None:
        self._conn.close()
