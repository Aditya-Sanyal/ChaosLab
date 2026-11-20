"""Integration tests for Scenario Lab endpoints, run comparisons, RBAC, and CSRF."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _login(client: TestClient, email: str, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200


def test_scenario_builder_crud_inline_runs_validation_and_run_compare(
    client: TestClient, seeded_app
) -> None:
    csrf = {"X-Requested-With": "chaoslab"}
    env_id = seeded_app.state.seed_info["environment_id"]
    snap_id = seeded_app.state.seed_info["snapshot_id"]

    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")

    # 1. Create a saved custom assumed-breach scenario (ws-101 -> dc-01:admin)
    create_sc = client.post(
        f"/api/environments/{env_id}/scenarios",
        headers=csrf,
        json={
            "name": "Custom Lateral to DC",
            "description": "Assumed breach on analyst workstation",
            "start_kind": "asset",
            "start_key": "ws-101",
            "start_level": "user",
            "targets": [{"asset_key": "dc-01", "level": "admin"}],
            "max_depth": 6,
            "k_paths": 5,
            "max_expansions": 10000,
        },
    )
    assert create_sc.status_code == 201
    custom_sc = create_sc.json()
    sc_id = custom_sc["id"]

    # 2. Run the saved scenario with D-like inline actions and rerun to confirm hash determinism
    run_payload = {
        "scenario_id": sc_id,
        "actions": [
            {
                "kind": "add_control",
                "params": {
                    "key": "CTRL-BLOCK-JUMP",
                    "name": "Segment Jump Host",
                    "type": "segmentation",
                    "asset_key": "jump-01",
                    "affects_rules": ["R-IDENTITY-ACCESS"],
                    "factor": 0.0,
                },
            }
        ],
    }
    r1 = client.post(f"/api/snapshots/{snap_id}/runs", headers=csrf, json=run_payload)
    assert r1.status_code == 201
    r1_body = r1.json()
    assert r1_body["result"]["baseline"]["total_paths"] == 1
    assert r1_body["result"]["modified"]["total_paths"] == 0
    assert r1_body["result"]["comparison"]["removed"][0]["target_key"] == "dc-01"

    r2 = client.post(f"/api/snapshots/{snap_id}/runs", headers=csrf, json=run_payload)
    assert r2.status_code == 201
    assert r2.json()["input_sha256"] == r1_body["input_sha256"]
    assert r2.json()["result_sha256"] == r1_body["result_sha256"]

    # 3. Delete the saved scenario -> historical run survives with scenario_id = None, audit logged
    del_sc = client.delete(f"/api/environments/{env_id}/scenarios/{sc_id}", headers=csrf)
    assert del_sc.status_code == 204
    runs_after_del = client.get(
        f"/api/environments/{env_id}/runs", params={"snapshot_id": snap_id}
    )
    assert runs_after_del.status_code == 200
    surviving = next(r for r in runs_after_del.json() if r["id"] == r1_body["id"])
    assert surviving["scenario_id"] is None

    audit_actions = [
        e["action"] for e in client.get("/api/audit?limit=30").json()["items"]
    ]
    assert "scenario.created" in audit_actions
    assert "scenario.deleted" in audit_actions

    # 4. Ad-hoc inline scenario runs + tight max_expansions truncation check
    inline_trunc = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={
            "inline_scenario": {
                "name": "Budget Capped Sweep",
                "start_kind": "zone",
                "start_key": "internet",
                "start_level": "user",
                "targets": [{"asset_key": "db-01", "level": "user"}],
                "max_depth": 6,
                "k_paths": 5,
                "max_expansions": 10,
            },
            "actions": [],
        },
    )
    assert inline_trunc.status_code == 201
    assert inline_trunc.json()["result"]["baseline"]["search_truncated"] is True

    # 5. Same-snapshot D2 vs D3 Run-to-Run comparison
    all_scenarios = client.get(f"/api/environments/{env_id}/scenarios").json()
    orders_sc = next(s for s in all_scenarios if "Orders DB" in s["name"])
    run_d2 = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={
            "scenario_id": orders_sc["id"],
            "actions": [{"kind": "remove_reachability", "params": {"reachability_key": "RR-04"}}],
        },
    ).json()
    run_d3 = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={
            "scenario_id": orders_sc["id"],
            "actions": [{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
        },
    ).json()

    cmp_same = client.get(
        "/api/runs/compare",
        params={"run_a_id": run_d2["id"], "run_b_id": run_d3["id"]},
    )
    assert cmp_same.status_code == 200
    cmp_body = cmp_same.json()
    assert cmp_body["result_kind"] == "run_comparison"
    assert cmp_body["same_snapshot"] is True
    assert cmp_body["same_scenario"] is True
    assert cmp_body["warnings"] == []
    assert cmp_body["comparison"]["baseline_headline_score"] == 5
    assert cmp_body["comparison"]["modified_headline_score"] == 11
    assert len(cmp_body["comparison"]["new"]) == 1

    # 6. Cross-snapshot comparison after remediation emits warning and removed paths
    patch_f = client.patch(
        f"/api/environments/{env_id}/findings/F-005",
        headers=csrf,
        json={"status": "remediated", "comment": "Patched deserialization"},
    )
    assert patch_f.status_code == 200
    snap_2 = client.post(
        f"/api/environments/{env_id}/snapshots",
        headers=csrf,
        json={"label": "Post F-005 Patch"},
    ).json()
    run_snap2 = client.post(
        f"/api/snapshots/{snap_2['id']}/runs",
        headers=csrf,
        json={"scenario_id": orders_sc["id"], "actions": []},
    ).json()

    cmp_cross = client.get(
        "/api/runs/compare",
        params={"run_a_id": run_d3["id"], "run_b_id": run_snap2["id"]},
    )
    assert cmp_cross.status_code == 200
    cross_body = cmp_cross.json()
    assert cross_body["same_snapshot"] is False
    assert len(cross_body["warnings"]) == 1
    assert cross_body["comparison"]["modified_headline_score"] == 0
    assert len(cross_body["comparison"]["removed"]) == 2

    # Filter runs by scenario_id
    filtered = client.get(
        f"/api/environments/{env_id}/runs", params={"scenario_id": orders_sc["id"]}
    )
    assert filtered.status_code == 200
    assert all(r["scenario_id"] == orders_sc["id"] for r in filtered.json())

    # 7. Validation errors return 422 cleanly
    bad_action_req = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=csrf,
        json={
            "scenario_id": orders_sc["id"],
            "actions": [{"kind": "remove_reachability", "params": {"reachability_key": "RR-NOPE"}}],
        },
    )
    assert bad_action_req.status_code == 422

    bad_sc_req = client.post(
        f"/api/environments/{env_id}/scenarios",
        headers=csrf,
        json={
            "name": "Bad Start",
            "start_kind": "zone",
            "start_key": "does-not-exist",
            "targets": [{"asset_key": "db-01", "level": "user"}],
        },
    )
    assert bad_sc_req.status_code == 422

    missing_cmp = client.get(
        "/api/runs/compare",
        params={"run_a_id": run_d2["id"], "run_b_id": "missing-run-id"},
    )
    assert missing_cmp.status_code == 404

    # Cross-environment comparison returns 422 (admin creates second env + snapshot + run)
    _login(client, "admin@meridian.example", "ChaosAdmin!2026")
    env2 = client.post(
        "/api/environments",
        headers=csrf,
        json={"name": "Secondary Env", "description": "Isolation check"},
    ).json()
    imp = client.post(
        f"/api/environments/{env2['id']}/imports/commit",
        headers=csrf,
        data={"format": "json"},
        files={
            "file": (
                "mini.json",
                b'{"schema_version":1,"zones":[{"key":"internet","name":"Internet",'
                b'"trust_level":"untrusted","intra_zone_policy":"deny"}],'
                b'"assets":[{"key":"web-x","name":"Web X","type":"server",'
                b'"zone_key":"internet","criticality":3}]}',
                "application/json",
            )
        },
    )
    assert imp.status_code == 200
    snap_env2 = client.post(
        f"/api/environments/{env2['id']}/snapshots", headers=csrf, json={"label": "S2"}
    ).json()
    run_env2 = client.post(
        f"/api/snapshots/{snap_env2['id']}/runs",
        headers=csrf,
        json={
            "inline_scenario": {
                "name": "Mini",
                "start_kind": "zone",
                "start_key": "internet",
                "targets": [{"asset_key": "web-x", "level": "user"}],
            },
            "actions": [],
        },
    ).json()
    cross_env_cmp = client.get(
        "/api/runs/compare",
        params={"run_a_id": run_d2["id"], "run_b_id": run_env2["id"]},
    )
    assert cross_env_cmp.status_code == 422

    # 8. CSRF + RBAC enforcement
    no_csrf = client.post(
        f"/api/environments/{env_id}/scenarios",
        json={
            "name": "No CSRF",
            "start_kind": "zone",
            "start_key": "internet",
            "targets": [{"asset_key": "db-01", "level": "user"}],
        },
    )
    assert no_csrf.status_code == 403

    _login(client, "viewer@meridian.example", "ChaosViewer!2026")
    assert (
        client.post(
            f"/api/environments/{env_id}/scenarios",
            headers=csrf,
            json={
                "name": "Viewer Create",
                "start_kind": "zone",
                "start_key": "internet",
                "targets": [{"asset_key": "db-01", "level": "user"}],
            },
        ).status_code
        == 403
    )
    assert client.get(
        "/api/runs/compare", params={"run_a_id": run_d2["id"], "run_b_id": run_d3["id"]}
    ).status_code == 200
