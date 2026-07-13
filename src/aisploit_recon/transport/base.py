"""Transport abstraction.

The orchestrator must not care *how* a payload reaches the target — through a
browser UI (Playwright) or a raw HTTP/API call. Both implement this Protocol,
so drivers are swappable and the detection logic stays identical. This is the
Dependency-Inversion boundary of the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class ProbeRequest:
    target_url: str
    payload_text: str
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
    async def teardown(self) -> None: ...
