"""Integration and CLI tests for user/role administration and data retention sweeps."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from chaoslab.audit.models import AuditEvent
from chaoslab.audit.service import verify_chain
from chaoslab.auth.models import User, UserSession
from chaoslab.cli import main as cli_main
from chaoslab.config import get_settings
from chaoslab.retention import run_retention
from chaoslab.scenarios.models import ScenarioRun
from chaoslab.snapshots.models import Snapshot


def _login(client: TestClient, email: str, password: str) -> int:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    return resp.status_code


def test_admin_user_lifecycle_last_admin_protection_and_rbac(
    client: TestClient, seeded_app
) -> None:
    csrf = {"X-Requested-With": "chaoslab"}

    # Non-admins cannot reach admin endpoints
    assert _login(client, "viewer@meridian.example", "ChaosViewer!2026") == 200
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/admin/retention-policy").status_code == 403

    assert _login(client, "analyst@meridian.example", "ChaosAnalyst!2026") == 200
    assert client.get("/api/admin/users").status_code == 403
    assert (
        client.post(
            "/api/admin/users",
            headers=csrf,
            json={
                "email": "nope@meridian.example",
                "display_name": "Nope",
                "password": "ValidPassword!2026",
                "role": "viewer",
            },
        ).status_code
        == 403
    )

    # Admin logs in
    assert _login(client, "admin@meridian.example", "ChaosAdmin!2026") == 200

    # CSRF check
    assert (
        client.post(
            "/api/admin/users",
            json={
                "email": "nocsrf@meridian.example",
                "display_name": "NoCSRF",
                "password": "ValidPassword!2026",
                "role": "viewer",
            },
        ).status_code
        == 403
    )

    users = client.get("/api/admin/users").json()
    sole_admin = next(u for u in users if u["email"] == "admin@meridian.example")

    # Last-admin protection: cannot demote or disable sole active admin
    assert (
        client.patch(
            f"/api/admin/users/{sole_admin['id']}",
            headers=csrf,
            json={"role": "analyst"},
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/admin/users/{sole_admin['id']}",
            headers=csrf,
            json={"is_active": False},
        ).status_code
        == 409
    )

    # Weak password rejected (422)
    assert (
        client.post(
            "/api/admin/users",
            headers=csrf,
            json={
                "email": "weak@meridian.example",
                "display_name": "Weak",
                "password": "short",
                "role": "viewer",
            },
        ).status_code
        == 422
    )

    # Create a new analyst account
    created_resp = client.post(
        "/api/admin/users",
        headers=csrf,
        json={
            "email": "secops@meridian.example",
            "display_name": "SecOps User",
            "password": "InitialPass!2026",
            "role": "analyst",
        },
    )
    assert created_resp.status_code == 201
    secops = created_resp.json()

    # Duplicate email returns 409
    assert (
        client.post(
            "/api/admin/users",
            headers=csrf,
            json={
                "email": "secops@meridian.example",
                "display_name": "Dup",
                "password": "InitialPass!2026",
                "role": "viewer",
            },
        ).status_code
        == 409
    )

    # Use a second TestClient for the newly created user so admin keeps its cookie
    with TestClient(seeded_app) as sec_client:
        assert _login(sec_client, "secops@meridian.example", "InitialPass!2026") == 200
        assert sec_client.get("/api/auth/me").status_code == 200

        # Admin resets password -> sec_client's session is revoked immediately
        reset_resp = client.post(
            f"/api/admin/users/{secops['id']}/reset-password",
            headers=csrf,
            json={"new_password": "RotatedPass!2026"},
        )
        assert reset_resp.status_code == 200
        assert reset_resp.json()["sessions_revoked"] == 1
        assert sec_client.get("/api/auth/me").status_code == 401

        # Old password rejected, new password succeeds
        assert _login(sec_client, "secops@meridian.example", "InitialPass!2026") == 401
        assert _login(sec_client, "secops@meridian.example", "RotatedPass!2026") == 200

        # Admin disables secops -> session immediately revoked
        disable_resp = client.patch(
            f"/api/admin/users/{secops['id']}",
            headers=csrf,
            json={"is_active": False},
        )
        assert disable_resp.status_code == 200
        assert disable_resp.json()["is_active"] is False
        assert sec_client.get("/api/auth/me").status_code == 401

    # Promote secops (re-enabled) to second admin -> sole_admin can demote self to analyst
    # (which immediately revokes client's admin:users permission -> 403), and secops as
    # sole remaining admin still cannot demote itself (409).
    client.patch(
        f"/api/admin/users/{secops['id']}",
        headers=csrf,
        json={"role": "admin", "is_active": True},
    )
    assert (
        client.patch(
            f"/api/admin/users/{sole_admin['id']}",
            headers=csrf,
            json={"role": "analyst"},
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/admin/users/{secops['id']}",
            headers=csrf,
            json={"role": "viewer"},
        ).status_code
        == 403
    )
    with TestClient(seeded_app) as admin2_client:
        assert _login(admin2_client, "secops@meridian.example", "RotatedPass!2026") == 200
        assert (
            admin2_client.patch(
                f"/api/admin/users/{secops['id']}",
                headers=csrf,
                json={"role": "viewer"},
            ).status_code
            == 409
        )
        # Re-promote sole_admin or inspect audit as remaining admin
        audit_events = admin2_client.get("/api/audit", params={"limit": 100}).json()["items"]

    # Verify audit records exist and never leak raw passwords
    actions = {e["action"] for e in audit_events}
    assert {"admin.user_created", "admin.user_updated", "admin.password_reset"} <= actions
    raw_audit_dump = json.dumps(audit_events)
    assert "InitialPass!2026" not in raw_audit_dump
    assert "RotatedPass!2026" not in raw_audit_dump


def test_retention_protects_referenced_snapshots_preserves_audit_and_cli(
    seeded_app, tmp_path: Path, monkeypatch, capsys
) -> None:
    env_id = seeded_app.state.seed_info["environment_id"]
    now = datetime.now(UTC) + timedelta(minutes=5)

    with seeded_app.state.session_factory() as db:
        admin = db.query(User).filter(User.email == "admin@meridian.example").one()

        # Sessions: 1 expired 40 days ago (beyond 30d grace), 1 still valid
        db.add(
            UserSession(
                user_id=admin.id,
                token_sha256="a" * 64,
                created_at=now - timedelta(days=50),
                expires_at=now - timedelta(days=40),
                last_seen_at=now - timedelta(days=45),
            )
        )
        db.add(
            UserSession(
                user_id=admin.id,
                token_sha256="b" * 64,
                created_at=now - timedelta(days=1),
                expires_at=now + timedelta(days=6),
                last_seen_at=now,
            )
        )

        # Snapshots (200d old > 180d policy):
        # 1) referenced ONLY by an aged run (>365d -> run purged, snapshot becomes deletable)
        # 2) unreferenced aged snapshot (deletable)
        # 3) referenced by a RECENT run (10d old -> MUST BE PROTECTED!)
        snap_old_unused = Snapshot(
            environment_id=env_id,
            label="Aged Unreferenced",
            sha256="1" * 64,
            document={"schema_version": 1},
            counts={},
            created_by="test",
            created_at=now - timedelta(days=200),
        )
        snap_old_expired_run = Snapshot(
            environment_id=env_id,
            label="Aged Only Old Run",
            sha256="2" * 64,
            document={"schema_version": 1},
            counts={},
            created_by="test",
            created_at=now - timedelta(days=200),
        )
        snap_old_kept_run = Snapshot(
            environment_id=env_id,
            label="Aged Kept By Recent Run",
            sha256="3" * 64,
            document={"schema_version": 1},
            counts={},
            created_by="test",
            created_at=now - timedelta(days=200),
        )
        db.add_all([snap_old_unused, snap_old_expired_run, snap_old_kept_run])
        db.flush()

        kept_snap_id = snap_old_kept_run.id

        # Runs
        db.add(
            ScenarioRun(
                environment_id=env_id,
                scenario_id=None,
                snapshot_id=snap_old_expired_run.id,
                actions=[],
                engine_version="0.1.0",
                ruleset_version="2026.11-r1",
                input_sha256="4" * 64,
                result_sha256="5" * 64,
                result={"baseline": {"headline_score": 0, "paths": []}},
                status="completed",
                duration_ms=1,
                created_by="test",
                created_at=now - timedelta(days=400),
            )
        )
        db.add(
            ScenarioRun(
                environment_id=env_id,
                scenario_id=None,
                snapshot_id=kept_snap_id,
                actions=[],
                engine_version="0.1.0",
                ruleset_version="2026.11-r1",
                input_sha256="6" * 64,
                result_sha256="7" * 64,
                result={"baseline": {"headline_score": 0, "paths": []}},
                status="completed",
                duration_ms=1,
                created_by="test",
                created_at=now - timedelta(days=10),
            )
        )

        # Pass audit_days=0 so seeded audit events are counted without mutating the hash chain
        db.commit()

        settings = seeded_app.state.settings
        dry = run_retention(db, settings=settings, now=now, dry_run=True, audit_days=0)
        assert dry["dry_run"] is True
        assert dry["counts"]["sessions"] == 1
        assert dry["counts"]["scenario_runs"] == 1
        assert dry["counts"]["snapshots"] == 2
        assert dry["counts"]["snapshots_protected_by_runs"] == 1
        assert dry["counts"]["audit_events_ready_for_archive"] >= 1
        assert db.get(Snapshot, snap_old_unused.id) is not None

        applied = run_retention(db, settings=settings, now=now, dry_run=False, audit_days=0)
        assert applied["dry_run"] is False
        assert db.get(Snapshot, snap_old_unused.id) is None
        assert db.get(Snapshot, snap_old_expired_run.id) is None
        assert db.get(Snapshot, kept_snap_id) is not None
        assert verify_chain(db)["valid"] is True
        assert db.query(AuditEvent).filter(AuditEvent.action == "retention.executed").count() == 1

    # CLI subcommands: run-retention --json and verify-audit against seeded temp SQLite DB
    db_file = Path(tmp_path / "test_chaoslab.db")
    monkeypatch.setenv("CHAOSLAB_DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    get_settings.cache_clear()
    try:
        assert cli_main(["verify-audit"]) == 0
        out = capsys.readouterr().out
        assert "Audit hash chain OK" in out

        assert cli_main(["run-retention", "--json"]) == 0
        cli_json = json.loads(capsys.readouterr().out)
        assert cli_json["dry_run"] is True
        assert cli_json["audit_chain_preserved"] is True

        assert cli_main(["run-retention", "--apply", "--json"]) == 0
        apply_json = json.loads(capsys.readouterr().out)
        assert apply_json["dry_run"] is False
    finally:
        get_settings.cache_clear()
