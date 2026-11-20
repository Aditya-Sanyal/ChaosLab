"""Shared pytest fixtures for CHAOS LAB backend tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from chaoslab.api.app import create_app
from chaoslab.auth.security import reset_rate_limiter
from chaoslab.config import Settings
from chaoslab.demo.seeder import seed_demo


@pytest.fixture(autouse=True)
def _clear_rate_limit() -> None:
    reset_rate_limiter()


@pytest.fixture()
def temp_settings(tmp_path: Path) -> Settings:
    db_file = tmp_path / "test_chaoslab.db"
    return Settings(
        env="test",
        database_url=f"sqlite:///{db_file.as_posix()}",
        secret_key="test-secret-key-not-for-prod-use",
        cookie_secure=False,
    )


@pytest.fixture()
def seeded_app(temp_settings: Settings):
    backend_dir = Path(__file__).resolve().parent.parent
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", temp_settings.database_url)
    command.upgrade(cfg, "head")

    app = create_app(temp_settings)
    with app.state.session_factory() as db:
        seed_info = seed_demo(db)
    app.state.seed_info = seed_info
    return app


@pytest.fixture()
def client(seeded_app):
    with TestClient(seeded_app) as c:
        yield c
