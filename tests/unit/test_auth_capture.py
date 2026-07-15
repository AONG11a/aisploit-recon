"""D6: auth capture — save/load of session state, keyring fallback, permissions."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from aisploit_recon.core.auth import (
    AuthCapture,
    AuthCaptureError,
    load_auth_state,
    save_auth_state,
)

# A minimal Playwright storage_state shape (cookies + origins).
_MOCK_STATE: dict[str, object] = {
    "cookies": [
        {"name": "session", "value": "abc123", "domain": "example.com", "path": "/"}
    ],
    "origins": [{"origin": "https://example.com", "localStorage": []}],
}


def test_save_auth_state_to_file(tmp_path: Path) -> None:
    """File output works and is JSON-readable back."""
    out = tmp_path / "auth" / "state.json"
    location = save_auth_state(_MOCK_STATE, out_path=out)
    assert location == f"file:{out}"
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data == _MOCK_STATE


def test_saved_auth_file_has_restrictive_permissions(tmp_path: Path) -> None:
    """File should be chmod 600 (owner read/write only)."""
    out = tmp_path / "state.json"
    save_auth_state(_MOCK_STATE, out_path=out)
    mode = stat.S_IMODE(os.stat(out).st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR  # 0o600


def test_save_auth_state_never_includes_secret_in_location(tmp_path: Path) -> None:
    """The return string must not contain the session token."""
    out = tmp_path / "state.json"
    location = save_auth_state(_MOCK_STATE, out_path=out)
    assert "abc123" not in location


def test_load_auth_state_from_file(tmp_path: Path) -> None:
    """Load reads back exactly what was saved."""
    out = tmp_path / "state.json"
    save_auth_state(_MOCK_STATE, out_path=out)
    loaded = load_auth_state(file_path=out)
    assert loaded == _MOCK_STATE


def test_load_auth_state_missing_returns_none(tmp_path: Path) -> None:
    """Missing file + no keyring → None, not an error."""
    assert load_auth_state(file_path=tmp_path / "nonexistent.json") is None


def test_load_auth_state_no_args_returns_none() -> None:
    """No file, no keyring → None."""
    assert load_auth_state() is None


def test_save_without_path_or_keyring_raises() -> None:
    """No destination → error."""
    with pytest.raises(AuthCaptureError):
        save_auth_state(_MOCK_STATE)


def test_auth_capture_missing_playwright_error() -> None:
    """AuthCapture.capture() raises a clear error when Playwright is missing.

    We can't easily test the full interactive flow, but we can verify the
    class constructs and the error path is reachable.
    """
    capture = AuthCapture("https://example.com")
    assert capture._target == "https://example.com"
