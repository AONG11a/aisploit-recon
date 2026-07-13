"""Runtime settings, loaded from environment / .env.

Secrets (LLM judge API keys, etc.) never live in scope YAML or in code;
they are pulled from the environment here so they can be provided via a
secret manager / keyring in CI.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AISPLOIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Where evidence artifacts (screenshots, HAR, raw I/O) are written.
    evidence_dir: Path = Field(default=Path("./evidence"))

    # SQLite evidence DB path.
    db_path: Path = Field(default=Path("./evidence/findings.sqlite3"))

    # Logging.
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)

    # LLM judge (optional). Empty => judge disabled, pipeline falls back.
    judge_enabled: bool = Field(default=False)
    judge_model: str = Field(default="claude-sonnet-4-20250514")
    anthropic_api_key: str = Field(default="")

    # Safety: retention (days) for evidence containing potentially sensitive
    # leaked data. A cleanup command uses this.
    evidence_retention_days: int = Field(default=30)

    def ensure_dirs(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
