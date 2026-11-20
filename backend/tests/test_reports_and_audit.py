"""Integration tests for report exports (HTML/Markdown), XSS escaping, and audit verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from chaoslab.audit.models import AuditEvent


def _login(client: TestClient, email: str, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200


def test_report_preview_export_xss_escaping_and_rbac(client: TestClient, seeded_app) -> None:
    csrf = {"X-Requested-With": "chaoslab"}
    env_id = seeded_app.state.seed_info["environment_id"]
    snap_id = seeded_app.state.seed_info["snapshot_id"]

    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")
    scenarios = client.get(f"/api/environments/{env_id}/scenarios").json()
    orders_sc = next(s for s in scenarios if "Orders DB" in s["name"])

    run = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={
            "scenario_id": orders_sc["id"],
            "actions": [{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
        },
    ).json()
    run_id = run["id"]

    # Export Markdown
    md_resp = client.post(
        f"/api/runs/{run_id}/report/export",
        headers=csrf,
        json={"format": "markdown"},
    )
    assert md_resp.status_code == 200
    assert "text/markdown" in md_resp.headers["content-type"]
    assert md_resp.headers["cache-control"] == "no-store"
    assert ".md" in md_resp.headers["content-disposition"]
    assert len(md_resp.headers["x-report-sha256"]) == 64
    md_text = md_resp.text
    assert "Modeled Result Notice" in md_text
    assert run["result"]["snapshot_sha256"] in md_text
    assert "EV-014" in md_text
    assert "Defensive Actions" in md_text
    assert "Model Limitations" in md_text

    # Export HTML
    html_resp = client.post(
        f"/api/runs/{run_id}/report/export",
        headers=csrf,
        json={"format": "html"},
    )
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["content-type"]
    assert "default-src 'none'" in html_resp.headers["content-security-policy"]
    assert ".html" in html_resp.headers["content-disposition"]
    assert "EV-014" in html_resp.text
    assert "Model Limitations" in html_resp.text

    # Audit trail records both exports
    exports = client.get("/api/audit", params={"action": "report.exported"}).json()
    assert exports["total"] >= 2
    assert all(e["subject_id"] == run_id for e in exports["items"])

    # XSS escaping test (Threat T3) via malicious inline scenario name
    xss_name = "Test <script>alert('xss')</script><img src=x onerror=alert(1)>"
    xss_run = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={
            "inline_scenario": {
                "name": xss_name,
                "start_kind": "zone",
                "start_key": "internet",
                "targets": [{"asset_key": "db-01", "level": "user"}],
            },
            "actions": [],
        },
    ).json()

    xss_html = client.post(
        f"/api/runs/{xss_run['id']}/report/export",
        headers=csrf,
        json={"format": "html"},
    )
    assert xss_html.status_code == 200
    assert "<script>" not in xss_html.text
    assert "<img " not in xss_html.text
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in xss_html.text

    xss_md = client.post(
        f"/api/runs/{xss_run['id']}/report/export",
        headers=csrf,
        json={"format": "markdown"},
    )
    assert xss_md.status_code == 200
    assert "<script>" not in xss_md.text
    assert "&lt;script&gt;" in xss_md.text

    # CSRF check
    no_csrf = client.post(
        f"/api/runs/{run_id}/report/export",
        json={"format": "html"},
    )
    assert no_csrf.status_code == 403

    # Viewer can preview (GET) but is denied audited export (POST -> 403)
    _login(client, "viewer@meridian.example", "ChaosViewer!2026")
    preview = client.get(f"/api/runs/{run_id}/report")
    assert preview.status_code == 200
    assert preview.json()["result_kind"] == "modeled_report"
    assert preview.json()["evidence_count"] >= 1
    assert (
        client.post(
            f"/api/runs/{run_id}/report/export",
            headers=csrf,
            json={"format": "markdown"},
        ).status_code
        == 403
    )


def test_audit_filters_pagination_and_tamper_detection(client: TestClient, seeded_app) -> None:
    csrf = {"X-Requested-With": "chaoslab"}
    env_id = seeded_app.state.seed_info["environment_id"]
    snap_id = seeded_app.state.seed_info["snapshot_id"]

    _login(client, "admin@meridian.example", "ChaosAdmin!2026")
    client.post(
        f"/api/environments/{env_id}/snapshots",
        headers=csrf,
        json={"label": "Audit Filter Snap"},
    )

    # Filter by action & subject_type & actor & search
    snap_events = client.get(
        "/api/audit",
        params={
            "action": "snapshot.created",
            "subject_type": "snapshot",
            "actor": "admin@meridian",
        },
    )
    assert snap_events.status_code == 200
    assert snap_events.json()["total"] >= 1
    assert all(e["action"] == "snapshot.created" for e in snap_events.json()["items"])

    # Pagination
    p1 = client.get("/api/audit", params={"limit": 2, "offset": 0}).json()
    p2 = client.get("/api/audit", params={"limit": 2, "offset": 2}).json()
    assert len(p1["items"]) == 2
    assert p1["items"][0]["seq"] != p2["items"][0]["seq"]

    # Time range filtering (since/until)
    future_since = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    empty_range = client.get("/api/audit", params={"since": future_since}).json()
    assert empty_range["total"] == 0

    past_since = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    all_recent = client.get("/api/audit", params={"since": past_since, "limit": 500}).json()
    assert all_recent["total"] >= 3

    # Verify chain intact before tampering
    ok_verify = client.get("/api/audit/verify").json()
    assert ok_verify["valid"] is True

    # Simulate direct DB tampering on seq=2 without recalculating hashes -> verify detects seq=2
    with seeded_app.state.session_factory() as db:
        ev2 = db.query(AuditEvent).filter(AuditEvent.seq == 2).one()
        ev2.details = {"tampered": True}
        db.commit()

    broken_verify = client.get("/api/audit/verify").json()
    assert broken_verify["valid"] is False
    assert broken_verify["first_broken_seq"] == 2
    assert snap_id  # referenced cleanly
