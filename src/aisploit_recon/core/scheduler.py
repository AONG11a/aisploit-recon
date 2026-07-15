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

from aisploit_recon.core.baseline import Baseline, build_baseline, generate_control_token
from aisploit_recon.core.models import CampaignResult, Finding
from aisploit_recon.core.scope_guard import ScopeGuard
from aisploit_recon.core.session import RateLimiter
from aisploit_recon.detection.canary import CanaryDetector
from aisploit_recon.detection.pipeline import DetectionPipeline
from aisploit_recon.detection.types import DetectionResult, Verdict
from aisploit_recon.payloads.models import Payload, PayloadCategory
from aisploit_recon.payloads.mutators import apply_mutators
from aisploit_recon.transport.base import (
    ConversationRequest,
    ProbeRequest,
    ProbeResponse,
    Transport,
)
from aisploit_recon.utils.crypto import content_digest
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)

# The benign control message for baseline characterisation. Deliberately
# neutral — it should not trigger any vulnerability behaviour on its own.
_CONTROL_MESSAGE = "Please reply with a one-sentence greeting."


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
        baseline_diff: bool = True,
        confirm_trials: int = 1,
        confirm_policy: str = "majority",
    ) -> None:
        self._target = target_url
        self._transport = transport
        self._pipeline = pipeline
        self._guard = scope_guard
        self._limiter = rate_limiter
        self._sem = asyncio.Semaphore(max_concurrent)
        self._baseline_diff = baseline_diff
        self._baseline: Baseline | None = None
        self._confirm_trials = confirm_trials
        self._confirm_policy = confirm_policy

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
            if p.is_multi_turn:
                text = self._render_turns(p, canary)
            else:
                text = p.template or ""
                if canary:
                    text = text.replace("{canary}", canary)
                if p.mutators:
                    text = apply_mutators(text, p.mutators)
            planned.append(PlannedProbe(p.id, text, canary))
        return planned

    @staticmethod
    def _render_turns(payload: Payload, canary: str | None) -> str:
        """Render a multi-turn payload's turns into a display string.

        For dry-run / logging: shows each turn with canary substituted.
        """
        turns = payload.turns or []
        if canary:
            turns = [t.replace("{canary}", canary) for t in turns]
        return " → ".join(turns)

    async def run(self, payloads: list[Payload]) -> CampaignResult:
        # Fail-closed authorization BEFORE any setup or network activity.
        self._guard.assert_in_scope(self._target)

        await self._transport.setup()
        result = CampaignResult(target_url=self._target)

        # D1: establish baseline characterisation once per campaign. If the
        # target reflects the control token, canary hits are penalised.
        if self._baseline_diff:
            try:
                self._baseline = await self._establish_baseline()
            except Exception as exc:
                log.warning("campaign.baseline_failed", error=str(exc))
                self._baseline = None

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
                if isinstance(outcome, BaseException):
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

    async def _establish_baseline(self) -> Baseline:
        """Send a benign control probe with a CONTROL_ token.

        If the target echoes the token, ``reflects_input`` will be True and
        canary hits are penalised. This is run after setup() and before any
        real probes, respecting the rate limiter.
        """
        async with self._sem:
            await self._limiter.acquire()
            control_token = generate_control_token()
            resp = await self._transport.send(
                ProbeRequest(
                    target_url=self._target,
                    payload_text=f"{_CONTROL_MESSAGE} Include this reference code: {control_token}",
                    metadata={"payload_id": "_baseline"},
                )
            )
            if not resp.ok:
                log.warning(
                    "campaign.baseline_transport_error",
                    error=resp.error,
                )
                return Baseline(
                    reflects_input=False,
                    control_digest="",
                    control_excerpt="",
                )
            baseline = build_baseline(resp.text, control_token)
            log.info(
                "campaign.baseline",
                reflects_input=baseline.reflects_input,
            )
            return baseline

    async def _probe_one(self, payload: Payload) -> Finding | None:
        async with self._sem:
            await self._limiter.acquire()

            canary = (
                CanaryDetector.generate_canary() if payload.requires_canary else None
            )

            if payload.is_multi_turn:
                resp = await self._send_multi_turn(payload, canary)
            else:
                text = payload.template or ""
                if canary:
                    text = text.replace("{canary}", canary)
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

            result = self._pipeline.evaluate(
                payload, resp.text, canary, baseline=self._baseline
            )

            # D4: repeat-and-confirm. If the first verdict is VULNERABLE and
            # confirm_trials > 1, re-probe N-1 more times and apply the policy.
            if (
                result.verdict is Verdict.VULNERABLE
                and self._confirm_trials > 1
            ):
                result = await self._confirm(
                    payload, canary, result
                )

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

    async def _send_multi_turn(
        self, payload: Payload, canary: str | None
    ) -> ProbeResponse:
        """D2: send a multi-turn conversation.

        Substitutes ``{canary}`` in any turn that contains it, then delegates
        to the transport's ``send_conversation``.
        """
        turns = list(payload.turns or [])
        if canary:
            turns = [t.replace("{canary}", canary) for t in turns]
        return await self._transport.send_conversation(
            ConversationRequest(
                target_url=self._target,
                turns=turns,
                metadata={"payload_id": payload.id},
            )
        )

    async def _confirm(
        self,
        payload: Payload,
        canary: str | None,
        first_result: DetectionResult,
    ) -> DetectionResult:
        """D4: re-probe confirm_trials-1 more times and apply the policy.

        Returns the final DetectionResult. If the policy is not satisfied,
        downgrades to INCONCLUSIVE with per-trial reasoning.
        """
        verdicts: list[Verdict] = [first_result.verdict]
        results: list[DetectionResult] = [first_result]

        for trial in range(self._confirm_trials - 1):
            await self._limiter.acquire()
            # Re-render and re-send the payload (single-shot or multi-turn).
            if payload.is_multi_turn:
                resp = await self._send_multi_turn(payload, canary)
            else:
                text = payload.template or ""
                if canary:
                    text = text.replace("{canary}", canary)
                if payload.mutators:
                    text = apply_mutators(text, payload.mutators)
                resp = await self._transport.send(
                    ProbeRequest(
                        target_url=self._target,
                        payload_text=text,
                        metadata={
                            "payload_id": payload.id,
                            "trial": str(trial + 2),
                        },
                    )
                )
            if not resp.ok:
                log.warning(
                    "probe.confirm_transport_error",
                    payload=payload.id,
                    trial=trial + 2,
                    error=resp.error,
                )
                verdicts.append(Verdict.ERROR)
                continue
            trial_result = self._pipeline.evaluate(
                payload, resp.text, canary, baseline=self._baseline
            )
            verdicts.append(trial_result.verdict)
            results.append(trial_result)

        vuln_count = sum(1 for v in verdicts if v is Verdict.VULNERABLE)
        total = len(verdicts)

        # Apply policy.
        if self._confirm_policy == "any":
            satisfied = vuln_count >= 1
        elif self._confirm_policy == "all":
            satisfied = vuln_count == total
        else:  # majority
            satisfied = vuln_count > total / 2

        if satisfied:
            log.info(
                "probe.confirmed",
                payload=payload.id,
                vuln=vuln_count,
                total=total,
                policy=self._confirm_policy,
            )
            return first_result

        log.info(
            "probe.downgraded",
            payload=payload.id,
            vuln=vuln_count,
            total=total,
            policy=self._confirm_policy,
        )
        return first_result.with_verdict(
            Verdict.INCONCLUSIVE,
            confidence=first_result.confidence * 0.5,
            reasoning=(
                f"Repeat-and-confirm: {vuln_count}/{total} trials reproduced "
                f"VULNERABLE under '{self._confirm_policy}' policy. "
                f"Downgraded to INCONCLUSIVE. Original: {first_result.reasoning}"
            ),
        )
