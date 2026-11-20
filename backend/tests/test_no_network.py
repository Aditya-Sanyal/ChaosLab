"""Verify offline scenario runs produce zero outbound socket or DNS calls."""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient


def test_scenario_run_makes_no_network_calls(
    client: TestClient, seeded_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    login = client.post(
        "/api/auth/login",
        json={"email": "analyst@meridian.example", "password": "ChaosAnalyst!2026"},
    )
    assert login.status_code == 200

    env_id = seeded_app.state.seed_info["environment_id"]
    snap_id = seeded_app.state.seed_info["snapshot_id"]
    scenarios = client.get(f"/api/environments/{env_id}/scenarios").json()
    orders_sc = next(s for s in scenarios if "Orders DB" in s["name"])

    def _blocked(*_args, **_kwargs):
        raise AssertionError("Outbound network activity is forbidden during simulation")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "gethostbyname", _blocked)

    resp = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers={"X-Requested-With": "chaoslab"},
        json={
            "scenario_id": orders_sc["id"],
            "actions": [{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["result_kind"] == "scenario_result"
    assert body["result"]["modified"]["headline_score"] == 11
