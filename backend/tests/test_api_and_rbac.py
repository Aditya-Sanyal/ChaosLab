"""API integration, CSRF, RBAC matrix, and tamper-evident audit chain tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from chaoslab.analysis import RESULT_DISCLAIMER
from chaoslab.audit.models import AuditEvent


def _login(client: TestClient, email: str, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200


def test_health_and_unauthenticated_access_rejected(client: TestClient) -> None:
    h = client.get("/api/health")
    assert h.status_code == 200
    assert h.json()["mode"] == "offline_simulation"

    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/environments").status_code == 401


def test_rbac_matrix_and_csrf_and_thin_slice_flow(client: TestClient, seeded_app) -> None:
    env_id = seeded_app.state.seed_info["environment_id"]
    snap_id = seeded_app.state.seed_info["snapshot_id"]

    # 1. Viewer role: reads allowed, writes & audit denied
    _login(client, "viewer@meridian.example", "ChaosViewer!2026")
    assert client.get("/api/environments").status_code == 200
    assets = client.get(f"/api/environments/{env_id}/assets", params={"zone_key": "dmz"})
    assert assets.status_code == 200
    assert {a["key"] for a in assets.json()} == {"web-01", "vpn-01", "mail-01"}

    detail = client.get(f"/api/environments/{env_id}/assets/web-01")
    assert detail.status_code == 200
    assert detail.json()["internet_exposed"] is True
    assert detail.json()["provenance"]["origin"] == "imported"

    graph = client.get(f"/api/environments/{env_id}/graph")
    assert graph.status_code == 200
    assert len(graph.json()["zones"]) == 7

    findings = client.get(f"/api/environments/{env_id}/findings")
    assert findings.status_code == 200
    assert len(findings.json()) == 5

    scenarios = client.get(f"/api/environments/{env_id}/scenarios")
    assert scenarios.status_code == 200
    orders_sc = next(s for s in scenarios.json() if "Orders DB" in s["name"])

    assert (
        client.post(
            f"/api/environments/{env_id}/snapshots",
            headers={"X-Requested-With": "chaoslab"},
            json={"label": "viewer attempt"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/snapshots/{snap_id}/runs",
            headers={"X-Requested-With": "chaoslab"},
            json={"scenario_id": orders_sc["id"]},
        ).status_code
        == 403
    )
    assert client.get("/api/audit").status_code == 403
    assert client.get("/api/audit/verify").status_code == 403

    # Logout requires CSRF header
    assert client.post("/api/auth/logout").status_code == 403
    assert (
        client.post("/api/auth/logout", headers={"X-Requested-With": "chaoslab"}).status_code == 204
    )

    # 2. Analyst role: can create snapshots, run scenarios, read audit; denied audit/verify
    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")
    # Missing CSRF header on mutation -> 403
    assert (
        client.post(
            f"/api/snapshots/{snap_id}/runs", json={"scenario_id": orders_sc["id"]}
        ).status_code
        == 403
    )

    run_resp = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers={"X-Requested-With": "chaoslab"},
        json={"scenario_id": orders_sc["id"]},
    )
    assert run_resp.status_code == 201
    run_data = run_resp.json()
    assert run_data["result_kind"] == "scenario_result"
    assert run_data["disclaimer"] == RESULT_DISCLAIMER
    assert run_data["result"]["baseline"]["headline_score"] == 22

    assert client.get("/api/audit").status_code == 200
    assert client.get("/api/audit/verify").status_code == 403
    client.post("/api/auth/logout", headers={"X-Requested-With": "chaoslab"})

    # 3. Admin role: audit verification passes, then detects DB tampering
    _login(client, "admin@meridian.example", "ChaosAdmin!2026")
    verify_ok = client.get("/api/audit/verify")
    assert verify_ok.status_code == 200
    assert verify_ok.json()["valid"] is True
    assert verify_ok.json()["checked_count"] >= 4

    # Simulate out-of-band DB row tampering on seq 2
    with seeded_app.state.session_factory() as db:
        ev = db.get(AuditEvent, 2)
        assert ev is not None
        ev.action = "tampered.action"
        db.commit()

    verify_tampered = client.get("/api/audit/verify")
    assert verify_tampered.status_code == 200
    assert verify_tampered.json()["valid"] is False
    assert verify_tampered.json()["first_broken_seq"] == 2
