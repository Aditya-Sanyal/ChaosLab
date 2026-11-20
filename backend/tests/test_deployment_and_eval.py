"""Verification tests for readiness, PG DDL parity, Compose hardening, RBAC, and determinism."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

import chaoslab.db.registry  # noqa: F401
from chaoslab import cli
from chaoslab.config import Settings, get_settings
from chaoslab.db.base import Base

EXPECTED_TABLES = {
    "users",
    "sessions",
    "audit_events",
    "environments",
    "import_batches",
    "zones",
    "assets",
    "services",
    "relationships",
    "reachability_rules",
    "findings",
    "finding_assets",
    "controls",
    "evidence",
    "evidence_links",
    "snapshots",
    "scenarios",
    "scenario_runs",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _login(client: TestClient, email: str, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200


def test_health_and_readiness_endpoints(client: TestClient) -> None:
    h = client.get("/api/health")
    assert h.status_code == 200
    assert h.json()["status"] == "ok"
    assert h.json()["mode"] == "offline_simulation"

    r = client.get("/api/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["database"] == "ok"
    assert body["mode"] == "offline_simulation"


def test_postgresql_ddl_compilation_and_offline_alembic_migration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    pg_dialect = postgresql.dialect()
    compiled_tables = {table.name for table in Base.metadata.sorted_tables}
    assert EXPECTED_TABLES <= compiled_tables

    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=pg_dialect))
        assert f"CREATE TABLE {table.name}" in ddl

    backend_dir = _repo_root() / "backend"
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option(
        "sqlalchemy.url", "postgresql+psycopg://chaoslab:placeholder@localhost:5432/chaoslab"
    )
    command.upgrade(cfg, "head", sql=True)

    rendered_sql = capsys.readouterr().out
    assert rendered_sql.strip()
    for table_name in EXPECTED_TABLES:
        assert f"CREATE TABLE {table_name}" in rendered_sql


def test_production_settings_require_strong_secret_key() -> None:
    with pytest.raises(ValidationError):
        Settings(env="production", secret_key="dev-only-change-me-in-production")
    with pytest.raises(ValidationError):
        Settings(env="production", secret_key="too-short")
    with pytest.raises(ValidationError):
        Settings(env="production", secret_key="")

    ok = Settings(env="production", secret_key="A" * 40)
    assert ok.env == "production"


def test_deployment_files_enforce_no_egress_and_hardening() -> None:
    root = _repo_root()
    compose_text = (root / "docker-compose.yml").read_text(encoding="utf-8")
    backend_df = (root / "backend" / "Dockerfile").read_text(encoding="utf-8")
    frontend_df = (root / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    nginx_conf = (root / "deploy" / "nginx.conf").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    backend_dockerignore_path = root / "backend" / ".dockerignore"
    assert backend_dockerignore_path.is_file()
    backend_dockerignore = backend_dockerignore_path.read_text(encoding="utf-8")
    env_example = (root / ".env.example").read_text(encoding="utf-8")

    # No-egress internal network + read-only / non-root / no-new-privileges controls
    assert "internal: true" in compose_text
    assert "read_only: true" in compose_text
    assert "no-new-privileges:true" in compose_text
    assert "cap_drop:" in compose_text
    assert "127.0.0.1:${CHAOSLAB_PORT:-8080}:8080" in compose_text

    # Structural YAML verification of Docker Compose hardening & no-egress isolation
    compose_doc = yaml.safe_load(compose_text)
    assert compose_doc["networks"]["internal"]["internal"] is True

    services = compose_doc["services"]
    db_svc = services["db"]
    api_svc = services["api"]
    web_svc = services["web"]

    assert "edge" not in db_svc["networks"]
    assert "edge" not in api_svc["networks"]
    assert "internal" in db_svc["networks"]
    assert "internal" in api_svc["networks"]
    assert "ports" not in db_svc
    assert "ports" not in api_svc
    assert "no-new-privileges:true" in db_svc["security_opt"]
    assert "ALL" in db_svc["cap_drop"]

    assert api_svc["read_only"] is True
    assert "ALL" in api_svc["cap_drop"]
    assert "no-new-privileges:true" in api_svc["security_opt"]
    assert api_svc["depends_on"]["db"]["condition"] == "service_healthy"
    assert "healthcheck" in api_svc

    assert web_svc["read_only"] is True
    assert "ALL" in web_svc["cap_drop"]
    assert "no-new-privileges:true" in web_svc["security_opt"]
    assert web_svc["depends_on"]["api"]["condition"] == "service_healthy"
    assert any(str(p).startswith("127.0.0.1:") for p in web_svc["ports"])

    assert "USER 10001:10001" in backend_df
    assert "sed -i 's/\\r$//'" in backend_df
    assert "/api/health/ready" in backend_df
    assert "nginxinc/nginx-unprivileged" in frontend_df
    assert "server_tokens off;" in nginx_conf
    assert 'X-Frame-Options "DENY"' in nginx_conf
    assert ".env" in dockerignore
    assert "backend/" in dockerignore
    assert ".venv/" in backend_dockerignore
    assert ".env" in backend_dockerignore
    assert "CHAOSLAB_RETENTION_SNAPSHOTS_DAYS" in env_example


def test_cross_process_determinism_across_pythonhashseed() -> None:
    backend_dir = _repo_root() / "backend"
    script = """
import hashlib, json
from pathlib import Path
from chaoslab.analysis import (
    DefensiveAction,
    EnvironmentModel,
    ScenarioSpec,
    TargetSpec,
    run_scenario,
)

raw = json.loads(Path("chaoslab/demo/meridian_freight.json").read_text(encoding="utf-8"))
dp = raw["default_provenance"]
wp = lambda x: {
    **x,
    "origin": x.get("origin", dp["origin"]),
    "source": x.get("source", dp["source"]),
    "observed_at": x.get("observed_at", dp["observed_at"]),
    "confidence": x.get("confidence", dp["confidence"]),
}
snap = {
    "schema_version": 1,
    "environment": {"id": "d", "name": raw["environment"]["name"]},
    "zones": [wp(z) for z in raw["zones"]],
    "assets": [wp(a) for a in raw["assets"]],
    "services": [wp(s) for s in raw["services"]],
    "relationships": [wp(r) for r in raw["relationships"]],
    "reachability": [wp(rr) for rr in raw["reachability"]],
    "findings": [wp(f) for f in raw["findings"]],
    "controls": [wp(c) for c in raw["controls"]],
    "evidence": [
        {**wp(e), "sha256": hashlib.sha256(e["excerpt"].encode()).hexdigest()}
        for e in raw["evidence"]
    ],
}
m = EnvironmentModel.from_snapshot_dict(snap)
sp = ScenarioSpec(
    name="S",
    start_kind="zone",
    start_key="internet",
    targets=(TargetSpec("db-01", "user"),),
)
out = run_scenario(
    m,
    sp,
    actions=[DefensiveAction("activate_control", {"control_key": "CTRL-01"})],
    snapshot_sha256="fixed",
)
print(
    json.dumps(
        {
            "in": out["input_sha256"],
            "out": out["result_sha256"],
            "score": out["modified"]["headline_score"],
        }
    )
)
"""

    results = []
    for seed in ("1", "987654"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(backend_dir),
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        results.append(json.loads(proc.stdout.strip()))

    assert results[0] == results[1]
    assert results[0]["score"] == 11


def test_full_role_authorization_matrix(client: TestClient, seeded_app) -> None:
    csrf = {"X-Requested-With": "chaoslab"}
    env_id = seeded_app.state.seed_info["environment_id"]
    snap_id = seeded_app.state.seed_info["snapshot_id"]

    # Seed one run as analyst first so report endpoints have a concrete run ID
    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")
    scenarios = client.get(f"/api/environments/{env_id}/scenarios").json()
    sc_id = scenarios[0]["id"]
    run_id = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={"scenario_id": sc_id, "actions": []},
    ).json()["id"]

    # Check unauthenticated access (401)
    with TestClient(seeded_app) as anon:
        for method, path in (
            ("GET", f"/api/environments/{env_id}/assets"),
            ("GET", f"/api/snapshots/{snap_id}/attack-paths"),
            ("GET", f"/api/runs/{run_id}/report"),
            ("GET", "/api/audit"),
            ("GET", "/api/admin/users"),
        ):
            assert anon.request(method, path).status_code == 401

    matrix: dict[str, list[tuple[str, str, dict | None, int]]] = {
        "viewer": [
            ("GET", f"/api/environments/{env_id}/assets", None, 200),
            ("GET", f"/api/environments/{env_id}/findings", None, 200),
            ("GET", f"/api/snapshots/{snap_id}/attack-paths", None, 200),
            ("GET", f"/api/runs/{run_id}/report", None, 200),
            ("PATCH", f"/api/environments/{env_id}/findings/F-005", {"status": "in_progress"}, 403),
            ("POST", f"/api/environments/{env_id}/snapshots", {"label": "V"}, 403),
            ("POST", f"/api/snapshots/{snap_id}/runs", {"scenario_id": sc_id, "actions": []}, 403),
            ("POST", f"/api/runs/{run_id}/report/export", {"format": "markdown"}, 403),
            ("GET", "/api/audit", None, 403),
            ("GET", "/api/admin/users", None, 403),
            ("GET", "/api/admin/retention-policy", None, 403),
        ],
        "analyst": [
            ("GET", f"/api/environments/{env_id}/assets", None, 200),
            ("PATCH", f"/api/environments/{env_id}/findings/F-005", {"status": "open"}, 200),
            ("POST", f"/api/environments/{env_id}/snapshots", {"label": "A"}, 201),
            ("POST", f"/api/snapshots/{snap_id}/runs", {"scenario_id": sc_id, "actions": []}, 201),
            ("POST", f"/api/runs/{run_id}/report/export", {"format": "markdown"}, 200),
            ("GET", "/api/audit", None, 200),
            ("GET", "/api/audit/verify", None, 403),
            ("GET", "/api/admin/users", None, 403),
            ("GET", "/api/admin/retention-policy", None, 403),
            ("POST", "/api/environments", {"name": "Blocked Env", "description": ""}, 403),
        ],
        "admin": [
            ("GET", "/api/audit", None, 200),
            ("GET", "/api/audit/verify", None, 200),
            ("GET", "/api/admin/users", None, 200),
            ("GET", "/api/admin/retention-policy", None, 200),
            ("POST", "/api/environments", {"name": "Admin Created Env", "description": ""}, 201),
        ],
    }

    creds = {
        "viewer": ("viewer@meridian.example", "ChaosViewer!2026"),
        "analyst": ("analyst@meridian.example", "ChaosAnalyst!2026"),
        "admin": ("admin@meridian.example", "ChaosAdmin!2026"),
    }

    for role, cases in matrix.items():
        _login(client, *creds[role])
        for method, path, body, expected_status in cases:
            headers = csrf if method in ("POST", "PATCH", "DELETE") else {}
            resp = client.request(method, path, headers=headers, json=body)
            assert resp.status_code == expected_status, (
                f"{role} {method} {path}: expected {expected_status}, got {resp.status_code}"
            )


def test_cli_resolve_backend_dir_and_create_admin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_file = tmp_path / "cli_admin.db"
    monkeypatch.setenv("CHAOSLAB_DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("CHAOSLAB_ENV", "test")
    get_settings.cache_clear()
    try:
        resolved = cli._resolve_backend_dir()
        assert (resolved / "alembic.ini").is_file()
        assert (resolved / "alembic").is_dir()

        assert cli.main(["init-db"]) == 0
        capsys.readouterr()

        monkeypatch.setattr(sys, "stdin", io.StringIO("ChaosOpsAdmin!2026\n"))
        rc = cli.main(
            [
                "create-admin",
                "--email",
                "ops@example.com",
                "--name",
                "Ops Admin",
                "--password-stdin",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "Created admin user ops@example.com" in out

        monkeypatch.setattr(sys, "stdin", io.StringIO("ChaosOpsAdmin!2026\n"))
        rc_dup = cli.main(
            [
                "create-admin",
                "--email",
                "ops@example.com",
                "--name",
                "Ops Admin",
                "--password-stdin",
            ]
        )
        assert rc_dup == 1

        monkeypatch.setattr(sys, "stdin", io.StringIO("weak\n"))
        rc_weak = cli.main(
            [
                "create-admin",
                "--email",
                "ops2@example.com",
                "--name",
                "Ops Admin 2",
                "--password-stdin",
            ]
        )
        assert rc_weak == 1
    finally:
        get_settings.cache_clear()
