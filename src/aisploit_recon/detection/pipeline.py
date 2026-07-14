"""Detection pipeline.

Routes a (payload, response) pair to the appropriate detector based on the
payload's declared strategy. Philosophy: deterministic detectors first
(canary, signature, refusal); the expensive, non-deterministic LLM judge is
last and optional. When the judge is requested but unavailable, we fall back
to signature matching at reduced confidence and label the result so the
report reflects the uncertainty rather than hiding it.
"""

from __future__ import annotations

from typing import assert_never

from aisploit_recon.core.baseline import Baseline
from aisploit_recon.detection.canary import CanaryDetector
from aisploit_recon.detection.heuristic import RefusalClassifier
from aisploit_recon.detection.llm_judge import LLMJudge
from aisploit_recon.detection.signature import SignatureDetector
from aisploit_recon.detection.types import DetectionResult, Verdict
from aisploit_recon.payloads.models import DetectionStrategy, Payload
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)


class DetectionPipeline:
    def __init__(self, llm_judge: LLMJudge | None = None) -> None:
        self._canary = CanaryDetector()
        self._signature = SignatureDetector()
        self._refusal = RefusalClassifier()
        self._judge = llm_judge

    def evaluate(
        self,
        payload: Payload,
        response: str,
        canary_token: str | None = None,
        baseline: Baseline | None = None,
    ) -> DetectionResult:
        strategy = payload.detection

        if strategy is DetectionStrategy.CANARY:
            if not canary_token:
                return DetectionResult(
                    verdict=Verdict.ERROR,
                    confidence=0.0,
                    detector="canary",
                    reasoning="Canary strategy selected but no canary token supplied.",
                    raw_response=response,
                )
            return self._canary.detect(response, canary_token, baseline=baseline)

        if strategy is DetectionStrategy.SIGNATURE:
            return self._signature.detect(
                response, payload.success_indicators, payload.refusal_indicators
            )

        if strategy is DetectionStrategy.REFUSAL_CLASSIFIER:
            return self._refusal.detect(response, payload.refusal_indicators)

        if strategy is DetectionStrategy.LLM_JUDGE:
            if self._judge is None:
                log.warning("pipeline.judge_unavailable", payload_id=payload.id)
                fallback = self._signature.detect(
                    response, payload.success_indicators, payload.refusal_indicators
                )
                return fallback.with_confidence(
                    fallback.confidence * 0.6,
                    reasoning=(
                        "LLM judge unavailable; used signature fallback at reduced "
                        f"confidence. Original: {fallback.reasoning}"
                    ),
                )
            return self._judge.detect(payload, response)

        # Exhaustive enum check: raise asserts unreachable for validated enums.
        assert_never(strategy)
