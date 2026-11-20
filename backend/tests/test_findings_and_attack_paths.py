"""API integration tests for findings workflow, status history, RBAC, and attack-path sweeps."""

from __future__ import annotations

from fastapi.testclient import TestClient

CSRF = {"X-Requested-With": "chaoslab"}


def _login(client: TestClient, email: str, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200


def test_finding_detail_status_workflow_and_snapshot_remediation(
    client: TestClient, seeded_app
) -> None:
    env_id = seeded_app.state.seed_info["environment_id"]
    snap1_id = seeded_app.state.seed_info["snapshot_id"]

    # Viewer can read finding detail and attack paths sweep, cannot PATCH finding
    _login(client, "viewer@meridian.example", "ChaosViewer!2026")
    f_detail = client.get(f"/api/environments/{env_id}/findings/F-005")
    assert f_detail.status_code == 200
    f_data = f_detail.json()
    assert f_data["key"] == "F-005"
    assert f_data["evidence"][0]["key"] == "EV-009"
    assert f_data["affected_assets"][0]["effective_status"] == "open"

    # Baseline crown-jewel sweep on Snapshot #1
    sweep1 = client.get(f"/api/snapshots/{snap1_id}/attack-paths")
    assert sweep1.status_code == 200
    s1 = sweep1.json()
    assert s1["result_kind"] == "modeled_attack_paths"
    assert s1["start_key"] == "internet"
    assert s1["headline_score"] == 22
    assert {t["asset_key"] for t in s1["targets_evaluated"]} == {
        "db-01",
        "dc-01",
        "bkt-backups",
        "id-it-admin",
    }
    db_target = next(t for t in s1["targets_evaluated"] if t["asset_key"] == "db-01")
    assert db_target["path_count"] == 2
    assert db_target["max_score"] == 22

    # Assumed-breach sweep from ws-101 with goal_level=admin reaches dc-01
    sweep_ws = client.get(
        f"/api/snapshots/{snap1_id}/attack-paths",
        params={"start_kind": "asset", "start_key": "ws-101", "goal_level": "admin"},
    )
    assert sweep_ws.status_code == 200
    dc_target = next(
        t for t in sweep_ws.json()["targets_evaluated"] if t["asset_key"] == "dc-01"
    )
    assert dc_target["path_count"] == 1

    # Viewer denied PATCH
    assert (
        client.patch(
            f"/api/environments/{env_id}/findings/F-005",
            headers=CSRF,
            json={"status": "remediated"},
        ).status_code
        == 403
    )
    client.post("/api/auth/logout", headers=CSRF)

    # Analyst updates F-005: missing CSRF -> 403, valid PATCH -> status_history + audit
    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")
    assert (
        client.patch(
            f"/api/environments/{env_id}/findings/F-005",
            json={"status": "in_progress"},
        ).status_code
        == 403
    )

    p1 = client.patch(
        f"/api/environments/{env_id}/findings/F-005",
        headers=CSRF,
        json={
            "status": "in_progress",
            "comment": "Scheduled deserialization filter PR",
            "remediation_notes": "Upgrade to JSON parser v3.",
        },
    )
    assert p1.status_code == 200
    assert p1.json()["status"] == "in_progress"
    assert len(p1.json()["status_history"]) == 1
    assert p1.json()["status_history"][0]["from_status"] == "open"
    assert p1.json()["status_history"][0]["to_status"] == "in_progress"

    # Set per-asset status_override on app-01 to remediated, then clear it, then remediate finding
    p2 = client.patch(
        f"/api/environments/{env_id}/findings/F-005",
        headers=CSRF,
        json={
            "asset_status_overrides": [
                {"asset_key": "app-01", "port": 8080, "status_override": "remediated"}
            ]
        },
    )
    assert p2.status_code == 200
    assert p2.json()["affected_assets"][0]["effective_status"] == "remediated"

    p3 = client.patch(
        f"/api/environments/{env_id}/findings/F-005",
        headers=CSRF,
        json={
            "status": "remediated",
            "comment": "Deployed fix in production release",
            "asset_status_overrides": [
                {"asset_key": "app-01", "port": 8080, "status_override": None}
            ],
        },
    )
    assert p3.status_code == 200
    assert p3.json()["status"] == "remediated"
    assert p3.json()["affected_assets"][0]["status_override"] is None
    assert p3.json()["affected_assets"][0]["effective_status"] == "remediated"
    assert len(p3.json()["status_history"]) == 2

    # Search/category filter on findings list
    filtered = client.get(
        f"/api/environments/{env_id}/findings",
        params={"search": "CWE-502", "status": "remediated"},
    )
    assert filtered.status_code == 200
    assert [f["key"] for f in filtered.json()] == ["F-005"]

    # Freeze Snapshot #2 -> attack-paths sweep now yields 0 paths to db-01
    # while Snapshot #1 remains untouched at 2 paths!
    snap2 = client.post(
        f"/api/environments/{env_id}/snapshots",
        headers=CSRF,
        json={"label": "Post-F005-Remediation"},
    )
    assert snap2.status_code == 201
    snap2_id = snap2.json()["id"]

    sweep2 = client.get(f"/api/snapshots/{snap2_id}/attack-paths")
    assert sweep2.status_code == 200
    assert sweep2.json()["total_paths"] == 0
    assert sweep2.json()["headline_score"] == 0

    sweep1_again = client.get(f"/api/snapshots/{snap1_id}/attack-paths")
    assert sweep1_again.json()["total_paths"] == 2
    client.post("/api/auth/logout", headers=CSRF)

    # Admin verifies audit chain stays intact across finding status transitions
    _login(client, "admin@meridian.example", "ChaosAdmin!2026")
    verify = client.get("/api/audit/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
