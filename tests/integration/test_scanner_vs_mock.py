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


def _campaign(target: str) -> Campaign:
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
