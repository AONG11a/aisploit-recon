"""Integration test: scanner against the intentionally-vulnerable mock app.

Boots the Flask mock in-process (via its WSGI app using a real socket) in both
vulnerable and secure modes and asserts the scanner's verdicts match ground
truth. This is how we quantify precision/recall rather than trusting the
detectors in isolation.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from wsgiref.simple_server import WSGIServer, make_server

import pytest

from aisploit_recon.config.scope import AuthorizationProof, ScopeConfig, ScopeRule
from aisploit_recon.core.scheduler import Campaign
from aisploit_recon.core.scope_guard import ScopeGuard
from aisploit_recon.core.session import RateLimiter
from aisploit_recon.detection.pipeline import DetectionPipeline
from aisploit_recon.detection.types import Verdict
from aisploit_recon.payloads.registry import PayloadRegistry
from aisploit_recon.transport.http_driver import HttpConfig, HttpDriver

_LIB = Path(__file__).parents[2] / "src" / "aisploit_recon" / "payloads" / "library"
_MOCK = Path(__file__).parents[1] / "fixtures" / "mock_ai_app" / "app.py"


def _load_mock_app():
    spec = importlib.util.spec_from_file_location("mock_ai_app", _MOCK)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ServerCtx:
    def __init__(self, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.port = _free_port()
        self._httpd: WSGIServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> str:
        os.environ["AISPLOIT_MOCK_VULNERABLE"] = "1" if self.vulnerable else "0"
        app = _load_mock_app()
        self._httpd = make_server("127.0.0.1", self.port, app)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}/chat"

    def __exit__(self, *exc: object) -> None:
        if self._httpd:
            self._httpd.shutdown()


def _campaign(
    target: str,
    confirm_trials: int = 1,
    confirm_policy: str = "majority",
) -> Campaign:
    scope = ScopeConfig(
        proof=AuthorizationProof(
            program="internal:test",
            scope_reference="local",
            authorized_by="ci",
            authorized_at=datetime.now(UTC),
        ),
        rules=ScopeRule(
            allowed_hosts=["127.0.0.1"],
            max_requests_per_minute=600,
            allow_private_destinations=True,
            confirm_trials=confirm_trials,
            confirm_policy=confirm_policy,
        ),
    )
    driver = HttpDriver(
        HttpConfig(body_template={"message": "{payload}"}, response_path="response")
    )
    return Campaign(
        target_url=target,
        transport=driver,
        pipeline=DetectionPipeline(llm_judge=None),
        scope_guard=ScopeGuard(scope),
        rate_limiter=RateLimiter(600),
        max_concurrent=4,
        confirm_trials=confirm_trials,
        confirm_policy=confirm_policy,
    )


@pytest.mark.asyncio
async def test_vulnerable_mode_triggers_canary_injection() -> None:
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _ServerCtx(vulnerable=True) as target:
        result = await _campaign(target).run(pi_payloads)
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("PI-001") is Verdict.VULNERABLE


@pytest.mark.asyncio
async def test_secure_mode_does_not_trigger() -> None:
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _ServerCtx(vulnerable=False) as target:
        result = await _campaign(target).run(pi_payloads)
    # No vulnerable finding for PI-001 in secure mode (canary not echoed).
    vulns = [f for f in result.findings if f.result.verdict is Verdict.VULNERABLE]
    assert not vulns


@pytest.mark.asyncio
async def test_system_prompt_extraction_detected_in_vulnerable_mode() -> None:
    registry = PayloadRegistry.from_directory(_LIB)
    spe = [p for p in registry.enabled() if p.id == "SPE-001"]
    with _ServerCtx(vulnerable=True) as target:
        result = await _campaign(target).run(spe)
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("SPE-001") is Verdict.VULNERABLE


# --- D1: baseline-diff detection ----------------------------------------------


class _EchoServerCtx:
    """Server context that sets ECHO mode (target echoes all input)."""

    def __init__(self) -> None:
        self.port = _free_port()
        self._httpd: WSGIServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> str:
        os.environ["AISPLOIT_MOCK_VULNERABLE"] = "1"
        os.environ["AISPLOIT_MOCK_ECHO"] = "1"
        app = _load_mock_app()
        self._httpd = make_server("127.0.0.1", self.port, app)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}/chat"

    def __exit__(self, *exc: object) -> None:
        os.environ["AISPLOIT_MOCK_ECHO"] = "0"
        if self._httpd:
            self._httpd.shutdown()


@pytest.mark.asyncio
async def test_echo_mode_canary_hit_is_not_high_confidence() -> None:
    """D1 acceptance: in echo mode, PI-001 must NOT be high-confidence VULNERABLE.

    The echo target reflects everything, so a canary hit is a false positive.
    With baseline_diff enabled, the canary hit is downgraded to INCONCLUSIVE.
    """
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _EchoServerCtx() as target:
        result = await _campaign(target).run(pi_payloads)
    # The finding exists (canary was reflected) but must NOT be VULNERABLE.
    vulns = [f for f in result.findings if f.payload.id == "PI-001"
             and f.result.verdict is Verdict.VULNERABLE
             and f.result.confidence >= 0.9]
    assert not vulns, "Echo target produced a high-confidence VULNERABLE (false positive!)"


@pytest.mark.asyncio
async def test_echo_mode_finding_is_inconclusive() -> None:
    """D1: the echo-mode canary hit should be INCONCLUSIVE with baseline_delta note."""
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _EchoServerCtx() as target:
        result = await _campaign(target).run(pi_payloads)
    findings = [f for f in result.findings if f.payload.id == "PI-001"]
    assert findings, "Expected at least a finding (canary reflected)"
    assert findings[0].result.verdict is Verdict.INCONCLUSIVE
    assert findings[0].result.baseline_delta != ""


# --- D4: repeat-and-confirm --------------------------------------------------


class _IntermittentServerCtx:
    """Server context that sets INTERMITTENT mode (vulnerable ~1-in-3)."""

    def __init__(self) -> None:
        self.port = _free_port()
        self._httpd: WSGIServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> str:
        os.environ["AISPLOIT_MOCK_VULNERABLE"] = "1"
        os.environ["AISPLOIT_MOCK_INTERMITTENT"] = "1"
        app = _load_mock_app()
        self._httpd = make_server("127.0.0.1", self.port, app)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}/chat"

    def __exit__(self, *exc: object) -> None:
        os.environ["AISPLOIT_MOCK_INTERMITTENT"] = "0"
        if self._httpd:
            self._httpd.shutdown()


@pytest.mark.asyncio
async def test_intermittent_majority_is_inconclusive() -> None:
    """D4 acceptance: a 1-in-3 intermittent target under 'majority' yields INCONCLUSIVE."""
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _IntermittentServerCtx() as target:
        result = await _campaign(target, confirm_trials=3, confirm_policy="majority").run(
            pi_payloads
        )
    findings = [f for f in result.findings if f.payload.id == "PI-001"]
    assert findings, "Expected a finding from the intermittent target"
    assert findings[0].result.verdict is Verdict.INCONCLUSIVE
    assert "Repeat-and-confirm" in findings[0].result.reasoning


@pytest.mark.asyncio
async def test_intermittent_any_policy_is_vulnerable() -> None:
    """D4 acceptance: the same intermittent target under 'any' yields VULNERABLE."""
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _IntermittentServerCtx() as target:
        result = await _campaign(target, confirm_trials=3, confirm_policy="any").run(
            pi_payloads
        )
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("PI-001") is Verdict.VULNERABLE


@pytest.mark.asyncio
async def test_confirm_trials_default_one_unchanged() -> None:
    """D4 backward-compat: confirm_trials=1 must equal today's behaviour.

    The deterministic vulnerable mock with confirm_trials=1 produces VULNERABLE
    in a single probe — no re-probe.
    """
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _ServerCtx(vulnerable=True) as target:
        result = await _campaign(target, confirm_trials=1).run(pi_payloads)
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("PI-001") is Verdict.VULNERABLE


# --- D2: multi-turn probes ---------------------------------------------------


class _ConversationServerCtx:
    """Server context for D2 multi-turn tests. Uses the /conversation endpoint."""

    def __init__(self, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.port = _free_port()
        self._httpd: WSGIServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> str:
        os.environ["AISPLOIT_MOCK_VULNERABLE"] = "1" if self.vulnerable else "0"
        app = _load_mock_app()
        self._httpd = make_server("127.0.0.1", self.port, app)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}/conversation"

    def __exit__(self, *exc: object) -> None:
        if self._httpd:
            self._httpd.shutdown()


def _conversation_campaign(
    target: str,
    confirm_trials: int = 1,
) -> Campaign:
    """Campaign configured for native multi-turn via /conversation endpoint."""
    scope = ScopeConfig(
        proof=AuthorizationProof(
            program="internal:test",
            scope_reference="local",
            authorized_by="ci",
            authorized_at=datetime.now(UTC),
        ),
        rules=ScopeRule(
            allowed_hosts=["127.0.0.1"],
            max_requests_per_minute=600,
            allow_private_destinations=True,
            confirm_trials=confirm_trials,
        ),
    )
    driver = HttpDriver(
        HttpConfig(
            body_template={"turns": "{turns}"},
            response_path="response",
            conversation_endpoint="/conversation",
        )
    )
    return Campaign(
        target_url=target,
        transport=driver,
        pipeline=DetectionPipeline(llm_judge=None),
        scope_guard=ScopeGuard(scope),
        rate_limiter=RateLimiter(600),
        max_concurrent=4,
        confirm_trials=confirm_trials,
    )


@pytest.mark.asyncio
async def test_multi_turn_canary_fires_vulnerable_mode() -> None:
    """D2 acceptance: a 2-turn canary payload fires against the vulnerable mock."""
    registry = PayloadRegistry.from_directory(_LIB)
    mt_payloads = [p for p in registry.enabled() if p.id == "MT-001"]
    assert mt_payloads, "MT-001 payload not found in library"
    with _ConversationServerCtx(vulnerable=True) as target:
        result = await _conversation_campaign(target).run(mt_payloads)
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("MT-001") is Verdict.VULNERABLE


@pytest.mark.asyncio
async def test_multi_turn_canary_quiet_secure_mode() -> None:
    """D2 acceptance: the same multi-turn payload must NOT fire in secure mode."""
    registry = PayloadRegistry.from_directory(_LIB)
    mt_payloads = [p for p in registry.enabled() if p.id == "MT-001"]
    with _ConversationServerCtx(vulnerable=False) as target:
        result = await _conversation_campaign(target).run(mt_payloads)
    vulns = [f for f in result.findings if f.result.verdict is Verdict.VULNERABLE]
    assert not vulns


@pytest.mark.asyncio
async def test_multi_turn_sequential_fallback() -> None:
    """D2: when conversation_endpoint is None, ConversationMixin sends turns
    sequentially via /chat and detection still works on the final response.
    """
    registry = PayloadRegistry.from_directory(_LIB)
    mt_payloads = [p for p in registry.enabled() if p.id == "MT-001"]
    # No conversation_endpoint: use the standard /chat campaign.
    with _ServerCtx(vulnerable=True) as target:
        result = await _campaign(target).run(mt_payloads)
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("MT-001") is Verdict.VULNERABLE


@pytest.mark.asyncio
async def test_single_shot_unchanged_after_d2() -> None:
    """D2 backward-compat: single-shot PI-001 still fires VULNERABLE after the
    multi-turn changes. Ensures no regression in the single-shot path.
    """
    registry = PayloadRegistry.from_directory(_LIB)
    pi_payloads = [p for p in registry.enabled() if p.id == "PI-001"]
    with _ServerCtx(vulnerable=True) as target:
        result = await _campaign(target).run(pi_payloads)
    verdicts = {f.payload.id: f.result.verdict for f in result.findings}
    assert verdicts.get("PI-001") is Verdict.VULNERABLE
