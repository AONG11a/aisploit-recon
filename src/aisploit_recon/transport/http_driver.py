"""HTTP/API transport driver.

For targets that expose the AI feature via an HTTP endpoint (chat API), this
is far faster and more stable than driving a browser. The request shape is
configurable so it adapts to different APIs: you supply where the payload goes
(a JSON pointer / template) and where the answer comes from (a JSON path).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from aisploit_recon.transport.base import ProbeRequest, ProbeResponse
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class HttpConfig:
    method: str = "POST"
    # Template for the JSON body; "{payload}" is replaced with the probe text.
    body_template: dict[str, Any] | None = None
    # Dotted path to the response text in the JSON reply, e.g. "response" or
    # "choices.0.message.content".
    response_path: str = "response"
    headers: dict[str, str] | None = None
    timeout_s: float = 30.0
    # The placeholder token used inside body_template values.
    payload_placeholder: str = "{payload}"


def _inject_payload(obj: Any, placeholder: str, value: str) -> Any:
    """Recursively replace the placeholder in strings within a JSON structure."""
    if isinstance(obj, str):
        return obj.replace(placeholder, value)
    if isinstance(obj, dict):
        return {k: _inject_payload(v, placeholder, value) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_inject_payload(v, placeholder, value) for v in obj]
    return obj


def _extract_path(data: Any, dotted: str) -> str:
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(f"Cannot descend into {part!r} of {type(cur).__name__}")
    return str(cur)


class HttpDriver:
    def __init__(self, config: HttpConfig, storage_headers: dict[str, str] | None = None):
        self._cfg = config
        # Auth headers (e.g. a session cookie / bearer) provided by the operator,
        # never sourced from target content.
        self._auth_headers = storage_headers or {}
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        headers = {**(self._cfg.headers or {}), **self._auth_headers}
        self._client = httpx.AsyncClient(timeout=self._cfg.timeout_s, headers=headers)

    async def send(self, request: ProbeRequest) -> ProbeResponse:
        if self._client is None:
            raise RuntimeError("HttpDriver.setup() must be called before send()")
        start = time.perf_counter()
        body = None
        if self._cfg.body_template is not None:
            body = _inject_payload(
                self._cfg.body_template, self._cfg.payload_placeholder, request.payload_text
            )
        try:
            resp = await self._client.request(
                self._cfg.method, request.target_url, json=body
            )
            latency = (time.perf_counter() - start) * 1000
            if resp.status_code == 429:
                return ProbeResponse(
                    text="", latency_ms=latency,
                    error="HTTP 429 rate-limited by target",
                )
            resp.raise_for_status()
            text = _extract_path(resp.json(), self._cfg.response_path)
            return ProbeResponse(text=text, latency_ms=latency)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            latency = (time.perf_counter() - start) * 1000
            log.warning("http.probe_error", target=request.target_url, error=str(exc))
            return ProbeResponse(text="", latency_ms=latency, error=str(exc))

    async def teardown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
