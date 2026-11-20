"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_DEV_SECRET = "dev-only-change-me-in-production"  # noqa: S105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CHAOSLAB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./data/chaoslab.db"
    secret_key: str = _DEFAULT_DEV_SECRET
    cookie_secure: bool = False
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    session_idle_hours: int = 12
    session_absolute_days: int = 7

    login_rate_limit_max_attempts: int = 10
    login_rate_limit_window_seconds: int = 300

    max_upload_bytes: int = 10 * 1024 * 1024
    max_import_rows: int = 50_000

    retention_snapshots_days: int = 180
    retention_runs_days: int = 365
    retention_sessions_grace_days: int = 30
    retention_audit_days: int = 730

    @field_validator("secret_key")
    @classmethod
    def _validate_secret_in_prod(cls, v: str, info) -> str:
        env = info.data.get("env", "development")
        if env == "production" and (not v or v == _DEFAULT_DEV_SECRET or len(v) < 32):
            raise ValueError(
                "CHAOSLAB_SECRET_KEY must be set to a random >=32-char secret in production"
            )
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
