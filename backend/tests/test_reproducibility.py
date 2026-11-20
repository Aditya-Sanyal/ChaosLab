"""Determinism and cross-database reproducibility tests."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from chaoslab.api.app import create_app
from chaoslab.config import Settings
from chaoslab.demo.seeder import seed_demo
from chaoslab.scenarios.models import Scenario
from chaoslab.scenarios.service import execute_scenario_run


def _init_and_seed(db_path: Path) -> tuple[str, str, str]:
    settings = Settings(
        env="test",
        database_url=f"sqlite:///{db_path.as_posix()}",
        secret_key="repro-test-secret",
    )
    backend_dir = Path(__file__).resolve().parent.parent
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")

    app = create_app(settings)
    with app.state.session_factory() as db:
        seed_info = seed_demo(db)
        sc = db.query(Scenario).filter(Scenario.name.like("%Orders DB%")).first()
        assert sc is not None
        r1 = execute_scenario_run(
            db,
            snapshot_id=seed_info["snapshot_id"],
            scenario_id=sc.id,
            actions=[{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
            created_by="repro-test",
        )
        r2 = execute_scenario_run(
            db,
            snapshot_id=seed_info["snapshot_id"],
            scenario_id=sc.id,
            actions=[{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
            created_by="repro-test",
        )
        assert r1.input_sha256 == r2.input_sha256
        assert r1.result_sha256 == r2.result_sha256
        return seed_info["snapshot_sha256"], r1.input_sha256, r1.result_sha256


def test_identical_snapshot_and_result_hashes_across_fresh_databases(tmp_path: Path) -> None:
    snap_a, in_a, out_a = _init_and_seed(tmp_path / "db_a.sqlite")
    snap_b, in_b, out_b = _init_and_seed(tmp_path / "db_b.sqlite")

    assert snap_a == snap_b
    assert in_a == in_b
    assert out_a == out_b
