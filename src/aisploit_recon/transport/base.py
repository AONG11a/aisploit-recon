"""Transport abstraction.

The orchestrator must not care *how* a payload reaches the target — through a
browser UI (Playwright) or a raw HTTP/API call. Both implement this Protocol,
so drivers are swappable and the detection logic stays identical. This is the
Dependency-Inversion boundary of the system.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class ProbeRequest:
    target_url: str
    payload_text: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ConversationRequest:
    """D2: multi-turn conversation request.

    Carries an ordered list of ``turns``. A transport with a native
    multi-turn endpoint sends them together and returns the reply to the
    *final* turn; a single-shot transport replays them one at a time via
    :func:`send_turns_sequentially` and returns the last reply. Detection
    always runs against that final response.
    """

    target_url: str
    turns: list[str]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeResponse:
    text: str
    latency_ms: float
    screenshot_path: str | None = None
    har_path: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@runtime_checkable
class Transport(Protocol):
    async def setup(self) -> None: ...
    async def send(self, request: ProbeRequest) -> ProbeResponse: ...

    async def send_conversation(self, request: ConversationRequest) -> ProbeResponse: ...

    async def teardown(self) -> None: ...


async def send_turns_sequentially(
    send: Callable[[ProbeRequest], Awaitable[ProbeResponse]],
    request: ConversationRequest,
) -> ProbeResponse:
    """Fallback multi-turn for transports without a native conversation endpoint.

    Replays each turn as its own single-shot ``send`` (tagging metadata with a
    1-based ``turn`` index) and returns the final response — or the first error
    if a turn fails. ``ConversationRequest.turns`` is guaranteed non-empty by the
    Payload schema (multi-turn payloads require at least 2 turns).
    """
    resp: ProbeResponse | None = None
    for i, turn in enumerate(request.turns):
        meta = {**request.metadata, "turn": str(i + 1)}
        resp = await send(
            ProbeRequest(
                target_url=request.target_url,
                payload_text=turn,
                metadata=meta,
            )
        )
        if not resp.ok:
            return resp
    if resp is None:
        raise RuntimeError("ConversationRequest.turns was empty")
    return resp
