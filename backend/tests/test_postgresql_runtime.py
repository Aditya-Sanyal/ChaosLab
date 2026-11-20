"""Live PostgreSQL 16 runtime verification and SQLite parity tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pgserver
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

from chaoslab.api.app import create_app
from chaoslab.audit.service import verify_chain
from chaoslab.config import Settings
from chaoslab.demo.seeder import seed_demo
from chaoslab.retention import run_retention
from chaoslab.scenarios.models import Scenario
from chaoslab.scenarios.service import execute_scenario_run


@pytest.fixture()
def live_pg_url(tmp_path: Path):
    env_url = os.environ.get("CHAOSLAB_TEST_POSTGRES_URL")
    if env_url:
        pg_url = (
            make_url(env_url)
            .set(drivername="postgresql+psycopg")
            .render_as_string(hide_password=False)
        )
        yield pg_url
        return

    pg_data = tmp_path / "pgdata"
    srv = pgserver.get_server(pg_data, cleanup_mode="stop")
    try:
        pg_url = (
            make_url(srv.get_uri())
            .set(drivername="postgresql+psycopg")
            .render_as_string(hide_password=False)
        )
        yield pg_url
    finally:
        srv.cleanup()


def test_live_postgresql_16_full_lifecycle_and_sqlite_hash_parity(
    live_pg_url: str, tmp_path: Path
) -> None:
    backend_dir = Path(__file__).resolve().parent.parent
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", live_pg_url)
    command.upgrade(cfg, "head")

    pg_settings = Settings(
        env="test",
        database_url=live_pg_url,
        secret_key="pg-live-runtime-test-secret",
        cookie_secure=False,
    )
    app = create_app(pg_settings)
    with app.state.session_factory() as db:
        pg_version = db.execute(text("SELECT version()")).scalar_one()
        assert "PostgreSQL" in pg_version
        seed_info = seed_demo(db)

    csrf = {"X-Requested-With": "chaoslab"}
    env_id = seed_info["environment_id"]
    snap_1_id = seed_info["snapshot_id"]

    with TestClient(app) as client:
        assert client.get("/api/health/ready").json()["database"] == "ok"
        assert (
            client.post(
                "/api/auth/login",
                json={"email": "admin@meridian.example", "password": "ChaosAdmin!2026"},
            ).status_code
            == 200
        )

        # Overview, Assets, Topology
        ov = client.get(f"/api/environments/{env_id}/overview")
        assert ov.status_code == 200
        assert ov.json()["counts"]["assets"] == 15
        assert client.get(f"/api/environments/{env_id}/assets").status_code == 200
        assert client.get(f"/api/environments/{env_id}/graph").status_code == 200

        # Findings update (JSON status_history dirty-tracking on PostgreSQL) + Snapshot #2
        patch_f = client.patch(
            f"/api/environments/{env_id}/findings/F-005",
            headers=csrf,
            json={"status": "remediated", "comment": "Patched on PG16"},
        )
        assert patch_f.status_code == 200
        assert len(patch_f.json()["status_history"]) == 1

        snap_2 = client.post(
            f"/api/environments/{env_id}/snapshots",
            headers=csrf,
            json={"label": "PG16 Post Patch"},
        ).json()

        # Attack Path Sweep comparison across Snapshot #1 (before) vs Snapshot #2 (after)
        sweep_1 = client.get(f"/api/snapshots/{snap_1_id}/attack-paths").json()
        sweep_2 = client.get(f"/api/snapshots/{snap_2['id']}/attack-paths").json()
        assert sweep_1["headline_score"] == 22
        assert sweep_2["headline_score"] == 0

        # Scenario Lab CRUD + Defensive CTRL-01 + ON DELETE SET NULL + Run Compare
        orders_sc = next(
            s
            for s in client.get(f"/api/environments/{env_id}/scenarios").json()
            if "Orders DB" in s["name"]
        )
        run_ctrl = client.post(
            f"/api/snapshots/{snap_1_id}/runs",
            headers=csrf,
            json={
                "scenario_id": orders_sc["id"],
                "actions": [{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
            },
        ).json()
        assert run_ctrl["result"]["modified"]["headline_score"] == 11

        custom_sc = client.post(
            f"/api/environments/{env_id}/scenarios",
            headers=csrf,
            json={
                "name": "PG Custom <script>alert(1)</script>",
                "start_kind": "zone",
                "start_key": "internet",
                "targets": [{"asset_key": "db-01", "level": "user"}],
            },
        ).json()
        run_base = client.post(
            f"/api/snapshots/{snap_1_id}/runs",
            headers=csrf,
            json={"scenario_id": custom_sc["id"], "actions": []},
        ).json()
        assert (
            client.delete(
                f"/api/environments/{env_id}/scenarios/{custom_sc['id']}", headers=csrf
            ).status_code
            == 204
        )

        # Historical ScenarioRun persists with scenario_id=None on Postgres
        pg_runs = client.get(f"/api/environments/{env_id}/runs").json()
        surviving = next(r for r in pg_runs if r["id"] == run_base["id"])
        assert surviving["scenario_id"] is None

        cmp_res = client.get(
            "/api/runs/compare",
            params={"run_a_id": run_base["id"], "run_b_id": run_ctrl["id"]},
        )
        assert cmp_res.status_code == 200
        assert cmp_res.json()["comparison"]["score_delta"] == -11

        # Imports (Nmap XML) & JSON Export
        nmap_xml = (
            b'<?xml version="1.0"?>'
            b'<nmaprun scanner="nmap"><host><status state="up"/>'
            b'<address addr="198.51.100.77" addrtype="ipv4"/>'
            b'<hostnames><hostname name="edge-pg.example" type="PTR"/></hostnames>'
            b'<ports><port protocol="tcp" portid="443">'
            b'<state state="open"/><service name="https" method="probed" conf="10"/>'
            b"</port></ports></host></nmaprun>"
        )
        imp = client.post(
            f"/api/environments/{env_id}/imports/commit",
            headers=csrf,
            data={"format": "nmap_xml", "vantage_zone_key": "internet", "target_zone_key": "dmz"},
            files={"file": ("scan.xml", nmap_xml, "application/xml")},
        )
        assert imp.status_code == 200
        assert imp.json()["status"] == "committed"

        # HTML & Markdown report exports + XSS escaping
        html_exp = client.post(
            f"/api/runs/{run_base['id']}/report/export",
            headers=csrf,
            json={"format": "html"},
        )
        assert html_exp.status_code == 200
        assert "<script>" not in html_exp.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_exp.text

        # Audit filters & chain verify (including timezone-aware ISO since/until on PostgreSQL)
        since_iso = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        aud = client.get(
            "/api/audit",
            params={"action": "report.exported", "actor": "admin@", "since": since_iso},
        )
        assert aud.status_code == 200
        assert aud.json()["total"] == 1
        assert client.get("/api/audit/verify").json()["valid"] is True

        # Admin user creation, last-admin 409, session revocation on disable
        users = client.get("/api/admin/users").json()
        admin_id = next(u["id"] for u in users if u["email"] == "admin@meridian.example")
        assert (
            client.patch(
                f"/api/admin/users/{admin_id}", headers=csrf, json={"role": "viewer"}
            ).status_code
            == 409
        )
        created_u = client.post(
            "/api/admin/users",
            headers=csrf,
            json={
                "email": "pg-sec@meridian.example",
                "display_name": "PG Sec",
                "password": "StrongPgPass!2026",
                "role": "analyst",
            },
        )
        assert created_u.status_code == 201
        assert (
            client.patch(
                f"/api/admin/users/{created_u.json()['id']}",
                headers=csrf,
                json={"is_active": False},
            ).status_code
            == 200
        )

    # Retention check directly against PostgreSQL session
    with app.state.session_factory() as db:
        ret = run_retention(db, settings=pg_settings, dry_run=False)
        assert ret["audit_chain_preserved"] is True
        assert verify_chain(db)["valid"] is True

    # Byte-for-byte hash parity vs SQLite
    sq_db = tmp_path / "sqlite_parity.db"
    sq_settings = Settings(
        env="test",
        database_url=f"sqlite:///{sq_db.as_posix()}",
        secret_key="sqlite-parity-secret",
    )
    sq_cfg = Config(str(backend_dir / "alembic.ini"))
    sq_cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    sq_cfg.set_main_option("sqlalchemy.url", sq_settings.database_url)
    command.upgrade(sq_cfg, "head")

    sq_app = create_app(sq_settings)
    with sq_app.state.session_factory() as sq_sess:
        sq_seed = seed_demo(sq_sess)
        sq_sc = sq_sess.query(Scenario).filter(Scenario.name.like("%Orders DB%")).first()
        assert sq_sc is not None
        sq_run = execute_scenario_run(
            sq_sess,
            snapshot_id=sq_seed["snapshot_id"],
            scenario_id=sq_sc.id,
            actions=[{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
            created_by="parity-check",
        )

    assert seed_info["snapshot_sha256"] == sq_seed["snapshot_sha256"]
    assert run_ctrl["input_sha256"] == sq_run.input_sha256
    assert run_ctrl["result_sha256"] == sq_run.result_sha256
