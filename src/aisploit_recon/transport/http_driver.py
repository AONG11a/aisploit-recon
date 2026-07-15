"""HTTP/API transport driver.

For targets that expose the AI feature via an HTTP endpoint (chat API), this
is far faster and more stable than driving a browser. The request shape is
configurable so it adapts to different APIs: you supply where the payload goes
(a JSON pointer / template) and where the answer comes from (a JSON path).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, cast

import httpx

from aisploit_recon.transport.base import (
    ConversationRequest,
    ProbeRequest,
    ProbeResponse,
    send_turns_sequentially,
)
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
    # D2: multi-turn config. When set, ``send_conversation`` sends all turns as
    # a single POST to ``conversation_endpoint`` (a separate endpoint that
    # accepts a ``turns`` array). If None, ``send_turns_sequentially`` replays
    # turns one at a time via ``send``.
    conversation_endpoint: str | None = None
    # The placeholder for the turns array inside conversation body_template.
    turns_placeholder: str = "{turns}"
    # D3: streaming. When ``stream`` is true, ``send`` reads a streamed response
    # (Server-Sent Events or NDJSON) and assembles the full message from deltas.
    # This is what most modern chat APIs return; without it a streaming target
    # raises on ``resp.json()`` and silently yields zero findings.
    stream: bool = False
    stream_format: str = "sse"  # "sse" | "ndjson"
    # Dotted path to the incremental text inside each streamed chunk.
    stream_delta_path: str = "choices.0.delta.content"
    # A ``data:`` line equal to this sentinel ends the stream (SSE convention).
    stream_done_sentinel: str = "[DONE]"
    # Safety cap on assembled length so a hung/adversarial stream can't grow
    # unbounded (the request is also bound by ``timeout_s``).
    stream_max_chars: int = 1_000_000


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


def _replace_turns_sentinel(obj: Any, sentinel: str, turns: list[str]) -> Any:
    """Recursively replace a string sentinel with the turns list."""
    if isinstance(obj, str):
        return turns if obj == sentinel else obj
    if isinstance(obj, dict):
        return {k: _replace_turns_sentinel(v, sentinel, turns) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_turns_sentinel(v, sentinel, turns) for v in obj]
    return obj


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
        if self._cfg.stream:
            return await self._send_streaming(request.target_url, request, start)
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

    async def _send_streaming(
        self, url: str, request: ProbeRequest, start: float
    ) -> ProbeResponse:
        """D3: POST and assemble a streamed (SSE/NDJSON) response.

        Streams the response, extracts the incremental text from each chunk via
        ``stream_delta_path``, and concatenates until the done-sentinel or the
        stream ends. Only reached when ``HttpConfig.stream`` is true, so the
        non-stream path is byte-for-byte unchanged.
        """
        if self._client is None:  # pragma: no cover - guarded by caller
            raise RuntimeError("HttpDriver.setup() must be called before send()")
        body = None
        if self._cfg.body_template is not None:
            body = _inject_payload(
                self._cfg.body_template, self._cfg.payload_placeholder, request.payload_text
            )
        try:
            async with self._client.stream(self._cfg.method, url, json=body) as resp:
                if resp.status_code == 429:
                    latency = (time.perf_counter() - start) * 1000
                    return ProbeResponse(
                        text="", latency_ms=latency,
                        error="HTTP 429 rate-limited by target",
                    )
                resp.raise_for_status()
                text = await self._assemble_stream(resp)
            latency = (time.perf_counter() - start) * 1000
            return ProbeResponse(text=text, latency_ms=latency)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            latency = (time.perf_counter() - start) * 1000
            log.warning("http.stream_error", target=url, error=str(exc))
            return ProbeResponse(text="", latency_ms=latency, error=str(exc))

    async def _assemble_stream(self, resp: httpx.Response) -> str:
        """Concatenate the delta text from each streamed line."""
        parts: list[str] = []
        total = 0
        sse = self._cfg.stream_format == "sse"
        async for raw in resp.aiter_lines():
            line = raw.strip()
            if not line:
                continue
            if sse:
                if not line.startswith("data:"):
                    continue
                data = line[len("data:"):].strip()
            else:  # ndjson: one JSON object per line
                data = line
            if data == self._cfg.stream_done_sentinel:
                break
            try:
                chunk = json.loads(data)
            except ValueError:
                continue  # keep-alive / comment / non-JSON line
            try:
                delta = _extract_path(chunk, self._cfg.stream_delta_path)
            except (KeyError, IndexError, ValueError):
                continue  # e.g. a role-only opening chunk with no content
            parts.append(delta)
            total += len(delta)
            if total >= self._cfg.stream_max_chars:
                break
        return "".join(parts)

    async def teardown(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def send_conversation(self, request: ConversationRequest) -> ProbeResponse:
        """D2: send a multi-turn conversation.

        If ``conversation_endpoint`` is configured, send all turns in a single
        POST to that endpoint (native multi-turn support). Otherwise, fall
        back to :func:`send_turns_sequentially`, which replays turns one by one
        via ``send``.
        """
        if self._client is None:
            raise RuntimeError("HttpDriver.setup() must be called before send_conversation()")
        if self._cfg.conversation_endpoint is None:
            # Fallback: sequential single-shot replay.
            return await send_turns_sequentially(self.send, request)

        # Native multi-turn: build the URL and body.
        # The conversation_endpoint is appended to the request's target_url
        # (replacing the path), or used as-is if it's a full URL.
        url = self._build_conversation_url(request.target_url)
        start = time.perf_counter()
        body = self._build_conversation_body(request.turns)
        try:
            resp = await self._client.request(self._cfg.method, url, json=body)
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
            log.warning(
                "http.conversation_error",
                target=url, error=str(exc),
            )
            return ProbeResponse(text="", latency_ms=latency, error=str(exc))

    def _build_conversation_url(self, target_url: str) -> str:
        """Replace the path of target_url with the conversation endpoint."""
        endpoint = self._cfg.conversation_endpoint or ""
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        # Replace the path component of target_url.
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(target_url)
        return urlunsplit((parts.scheme, parts.netloc, endpoint, "", ""))

    def _build_conversation_body(self, turns: list[str]) -> dict[str, Any]:
        """Build the JSON body for a native multi-turn request."""
        template = self._cfg.body_template
        if template is None:
            return {"turns": turns}
        # Inject the turns list into the template.
        body = _inject_payload(template, self._cfg.turns_placeholder, "__TURNS__")
        # Replace the sentinel with the actual list (handled separately since
        # _inject_payload only handles strings). A body_template is a JSON
        # object, so the result is a dict.
        return cast("dict[str, Any]", _replace_turns_sentinel(body, "__TURNS__", turns))
