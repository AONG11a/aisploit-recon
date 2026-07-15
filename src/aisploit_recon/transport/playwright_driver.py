"""Playwright transport driver.

Drives the AI feature through the real UI, exactly as a user would type. This
matters because many injection defences live in the front end / API gateway
and only trigger on the genuine request path. It also captures screenshots and
a HAR file per probe — the artifacts a bug-bounty triager needs to reproduce.

The trickiest correctness detail is waiting for *streamed* responses to finish
before reading them; ``_wait_for_stable_response`` polls until the text stops
changing, avoiding false negatives from reading a half-rendered answer.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aisploit_recon.transport.base import (
    ConversationRequest,
    ProbeRequest,
    ProbeResponse,
    send_turns_sequentially,
)
from aisploit_recon.utils.logging import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Browser, BrowserContext, Page, Playwright

log = get_logger(__name__)

# Playwright is imported lazily in setup() so the module can be imported
# (and --help can run) without the [browser] extra installed.
try:
    from playwright.async_api import TimeoutError as PwTimeout
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None  # type: ignore[assignment]
    PwTimeout = TimeoutError  # type: ignore[misc,assignment]


@dataclass
class PlaywrightConfig:
    input_selector: str
    submit_selector: str
    response_selector: str
    response_timeout_ms: int = 30_000
    stable_ms: int = 1_500
    max_stream_wait_ms: int = 20_000
    headless: bool = True
    evidence_dir: Path = Path("./evidence")


class PlaywrightDriver:
    def __init__(self, config: PlaywrightConfig, storage_state: str | None = None):
        self._cfg = config
        # Path to a Playwright storage_state JSON (cookies/localStorage) captured
        # from a logged-in session by the operator. Never derived from target
        # content; kept out of VCS and ideally in the OS keyring.
        self._storage_state = storage_state
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None

    async def setup(self) -> None:
        if async_playwright is None:
            raise RuntimeError(
                "Playwright is not installed. Install the [browser] extra: "
                "pip install 'aisploit-recon[browser]'"
            )
        self._cfg.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self._cfg.headless)
        self._context = await self._browser.new_context(
            storage_state=self._storage_state,
            record_har_path=str(self._cfg.evidence_dir / "session.har"),
        )

    async def send(self, request: ProbeRequest) -> ProbeResponse:
        if self._context is None:
            raise RuntimeError("PlaywrightDriver.setup() must be called before send()")
        page = await self._context.new_page()
        start = time.perf_counter()
        pid = request.metadata.get("payload_id", "probe")
        try:
            await page.goto(request.target_url, wait_until="networkidle")
            await page.fill(self._cfg.input_selector, request.payload_text)
            await page.click(self._cfg.submit_selector)
            await page.wait_for_selector(
                self._cfg.response_selector, timeout=self._cfg.response_timeout_ms
            )
            await self._wait_for_stable_response(page)

            text = await page.inner_text(self._cfg.response_selector)
            latency = (time.perf_counter() - start) * 1000

            shot = self._cfg.evidence_dir / f"{pid}.png"
            await page.screenshot(path=str(shot), full_page=True)

            return ProbeResponse(
                text=text,
                latency_ms=latency,
                screenshot_path=str(shot),
                har_path=str(self._cfg.evidence_dir / "session.har"),
            )
        except PwTimeout:
            latency = (time.perf_counter() - start) * 1000
            return ProbeResponse(
                text="", latency_ms=latency,
                error="Response timeout — target may be rate-limiting or hung",
            )
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            log.warning(
                "playwright.probe_error",
                target=request.target_url,
                error=str(exc),
            )
            return ProbeResponse(
                text="", latency_ms=latency, error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            await page.close()

    async def send_conversation(self, request: ConversationRequest) -> ProbeResponse:
        """D2: multi-turn over the real UI.

        The browser transport has no native multi-turn endpoint, so each turn
        is typed and submitted as its own single-shot ``send`` (a fresh page per
        turn); detection runs on the final turn's response. Evidence artifacts
        (screenshot/HAR) are captured per turn as usual.
        """
        if self._context is None:
            raise RuntimeError(
                "PlaywrightDriver.setup() must be called before send_conversation()"
            )
        return await send_turns_sequentially(self.send, request)

    async def _wait_for_stable_response(self, page: Page) -> None:
        last = ""
        stable_since = time.perf_counter()
        deadline = time.perf_counter() + self._cfg.max_stream_wait_ms / 1000
        while time.perf_counter() < deadline:
            current = await page.inner_text(self._cfg.response_selector)
            if current != last:
                last = current
                stable_since = time.perf_counter()
            elif (time.perf_counter() - stable_since) * 1000 >= self._cfg.stable_ms:
                return
            await asyncio.sleep(0.3)

    async def teardown(self) -> None:
        if self._context is not None:
            await self._context.close()  # flushes HAR
        if self._browser is not None:
            await self._browser.close()
        if self._pw is not None:
            await self._pw.stop()
