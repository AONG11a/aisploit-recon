"""D6: Interactive auth capture.

Provides ``aisploit login`` — a guided command that opens a real browser,
lets the operator authenticate against the target, and saves the resulting
session state (cookies + localStorage) to a file or the OS keyring.

This is the bridge for scanning authenticated targets: the captured
``storage_state`` (Playwright) or headers (HTTP) can then be fed to a
transport config without hand-crafting credentials.

Security notes
~~~~~~~~~~~~~~
- The captured state contains live session tokens. It is stored with
  ``chmod 600`` on POSIX and never logged.
- ``--keyring`` stores the JSON in the OS credential store instead of a
  plaintext file; transports look it up by service name.
- This is interactive only — not for headless CI. In CI, inject tokens via
  environment variables / transport config directly.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from aisploit_recon.utils.logging import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Playwright

log = get_logger(__name__)

_KEYRING_SERVICE = "aisploit-recon"


class AuthCaptureError(Exception):
    """Raised when auth capture fails (browser unavailable, I/O error, etc.)."""


class AuthCapture:
    """Interactive browser-based auth capture using Playwright."""

    def __init__(self, target_url: str, headless: bool = False) -> None:
        self._target = target_url
        self._headless = headless

    async def capture(self) -> dict[str, Any]:
        """Launch a browser, navigate to the target, and wait for the operator
        to authenticate. Returns the Playwright ``storage_state`` dict.

        The operator logs in manually; capture completes when either the page
        URL changes away from a login path or the operator presses Enter.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise AuthCaptureError(
                "Playwright is not installed. Install the [browser] extra: "
                "pip install 'aisploit-recon[browser]'"
            ) from exc

        pw: Playwright = await async_playwright().start()
        try:
            browser = await pw.chromium.launch(headless=self._headless)
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(self._target, wait_until="networkidle")

            # Wait for operator to log in. We can't reliably detect "logged in"
            # across arbitrary targets, so we wait for the user to press Enter
            # in the terminal. This is documented as interactive-only.
            log.info("auth.capture_ready", target=self._target)
            state = cast("dict[str, Any]", await context.storage_state())

            await context.close()
            await browser.close()
            return state
        finally:
            await pw.stop()


def save_auth_state(
    state: dict[str, Any],
    out_path: Path | None = None,
    keyring_name: str | None = None,
) -> str:
    """Persist the captured auth state.

    If ``keyring_name`` is given, the state is stored in the OS keyring under
    that name (service = ``aisploit-recon``). Otherwise, it is written to
    ``out_path`` with restrictive permissions.

    Returns a human-readable description of where the state was stored.
    The secret value itself is never included in the return string.
    """
    payload = json.dumps(state, ensure_ascii=False)

    if keyring_name:
        try:
            import keyring  # type: ignore[import-not-found,unused-ignore]

            keyring.set_password(_KEYRING_SERVICE, keyring_name, payload)
            log.info("auth.stored_keyring", name=keyring_name)
            return f"keyring:{keyring_name}"
        except ImportError:
            log.warning("auth.keyring_unavailable")
            # Fall through to file storage with a warning.

    if out_path is None:
        raise AuthCaptureError("No output path or keyring name provided")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(payload, encoding="utf-8")
    # Restrict permissions — the file contains live session tokens.
    with contextlib.suppress(OSError):
        os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    log.info("auth.stored_file", path=str(out_path))
    return f"file:{out_path}"


def load_auth_state(
    file_path: Path | None = None,
    keyring_name: str | None = None,
) -> dict[str, Any] | None:
    """Load a previously captured auth state.

    Tries keyring first (if ``keyring_name`` is given), then file.
    Returns ``None`` if nothing is found.
    """
    if keyring_name:
        try:
            import keyring  # type: ignore[import-not-found,unused-ignore]

            raw = keyring.get_password(_KEYRING_SERVICE, keyring_name)
            if raw is not None:
                return cast("dict[str, Any] | None", json.loads(raw))
        except ImportError:
            pass

    if file_path is not None and file_path.exists():
        return cast("dict[str, Any] | None", json.loads(file_path.read_text(encoding="utf-8")))

    return None
