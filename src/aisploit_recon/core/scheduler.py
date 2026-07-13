"""Campaign scheduler.

Runs a set of payloads against one target: scope-gated, rate-limited, and
concurrency-capped, using asyncio so I/O-bound probes overlap without
overwhelming the target. Canary injection happens here so the same random
token flows into both the payload and the detector.

A ``dry_run`` mode renders exactly what *would* be sent without sending it —
the default first step, so you can eyeball the campaign before it touches a
live system.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from aisploit_recon.core.models import CampaignResult, Finding
from aisploit_recon.core.scope_guard import ScopeGuard
from aisploit_recon.core.session import RateLimiter
from aisploit_recon.detection.canary import CanaryDetector
from aisploit_recon.detection.pipeline import DetectionPipeline
from aisploit_recon.detection.types import Verdict
from aisploit_recon.payloads.models import Payload, PayloadCategory
from aisploit_recon.payloads.mutators import apply_mutators
from aisploit_recon.transport.base import ProbeRequest, Transport
from aisploit_recon.utils.crypto import content_digest
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class PlannedProbe:
    payload_id: str
    rendered_text: str
    canary: str | None


class Campaign:
    def __init__(
        self,
        target_url: str,
        transport: Transport,
        pipeline: DetectionPipeline,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter,
        max_concurrent: int = 2,
    ) -> None:
        self._target = target_url
        self._transport = transport
        self._pipeline = pipeline
        self._guard = scope_guard
        self._limiter = rate_limiter
        self._sem = asyncio.Semaphore(max_concurrent)

    def plan(self, payloads: list[Payload]) -> list[PlannedProbe]:
        """Render probes without sending. Used by --dry-run.

        Scope is still asserted so a dry-run also validates authorization.
        """
        self._guard.assert_in_scope(self._target)
        planned: list[PlannedProbe] = []
        for p in payloads:
            if not p.enabled:
                continue
            canary = CanaryDetector.generate_canary() if p.requires_canary else None
            text = p.template.replace("{canary}", canary) if canary else p.template
            if p.mutators:
                text = apply_mutators(text, p.mutators)
            planned.append(PlannedProbe(p.id, text, canary))
        return planned

    async def run(self, payloads: list[Payload]) -> CampaignResult:
        # Fail-closed authorization BEFORE any setup or network activity.
        self._guard.assert_in_scope(self._target)

        await self._transport.setup()
        result = CampaignResult(target_url=self._target)

        # Warn if indirect-injection payloads are present — they are meant to
        # be delivered via retrieved content (RAG), not sent as direct user
        # messages. Without a proper delivery harness, II probes degenerate
        # into direct injection tests, which is not what they measure.
        if any(p.category is PayloadCategory.INDIRECT_INJECTION for p in payloads if p.enabled):
            log.warning(
                "campaign.indirect_injection_caveat",
                note=(
                    "Indirect-injection payloads are being sent as direct user "
                    "messages. Without a RAG/delivery harness, these test direct "
                    "injection, not the indirect path. Interpret results accordingly."
                ),
            )

        try:
            tasks = [self._probe_one(p) for p in payloads if p.enabled]
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                result.total_probes += 1
                if isinstance(outcome, Exception):
                    result.errors += 1
                    log.error("probe.exception", error=str(outcome))
                elif outcome is not None:
                    result.findings.append(outcome)
        finally:
            await self._transport.teardown()

        log.info(
            "campaign.done",
            target=self._target,
            probes=result.total_probes,
            findings=len(result.findings),
            vulnerable=result.vulnerable_count,
            errors=result.errors,
        )
        return result

    async def _probe_one(self, payload: Payload) -> Finding | None:
        async with self._sem:
            await self._limiter.acquire()

            canary = CanaryDetector.generate_canary() if payload.requires_canary else None
            text = payload.template.replace("{canary}", canary) if canary else payload.template
            if payload.mutators:
                text = apply_mutators(text, payload.mutators)

            resp = await self._transport.send(
                ProbeRequest(
                    target_url=self._target,
                    payload_text=text,
                    metadata={"payload_id": payload.id},
                )
            )
            if not resp.ok:
                log.warning("probe.transport_error", payload=payload.id, error=resp.error)
                return None

            result = self._pipeline.evaluate(payload, resp.text, canary)

            # Keep only actionable outcomes; drop clean NOT_VULNERABLE to reduce noise.
            if result.verdict in (Verdict.VULNERABLE, Verdict.INCONCLUSIVE):
                return Finding(
                    payload=payload,
                    result=result,
                    canary=canary,
                    target_url=self._target,
                    latency_ms=resp.latency_ms,
                    screenshot_path=resp.screenshot_path,
                    evidence_digest=content_digest(resp.text),
                )
            return None
