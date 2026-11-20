"""Unit and scenario tests for the pure deterministic analysis engine."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chaoslab.analysis import (
    ENGINE_VERSION,
    RESULT_DISCLAIMER,
    RULESET_VERSION,
    DefensiveAction,
    EnvironmentModel,
    ScenarioSpec,
    TargetSpec,
    analyze_scenario,
    run_scenario,
)


def _meridian_snapshot_dict() -> dict:
    fixture = (
        Path(__file__).resolve().parent.parent / "chaoslab" / "demo" / "meridian_freight.json"
    )
    raw = json.loads(fixture.read_text(encoding="utf-8"))
    default_prov = raw["default_provenance"]

    def _with_prov(item: dict) -> dict:
        return {
            **item,
            "origin": item.get("origin", default_prov["origin"]),
            "source": item.get("source", default_prov["source"]),
            "observed_at": item.get("observed_at", default_prov["observed_at"]),
            "confidence": item.get("confidence", default_prov["confidence"]),
        }

    return {
        "schema_version": 1,
        "environment": {"id": "demo-env", "name": raw["environment"]["name"]},
        "zones": [_with_prov(z) for z in raw["zones"]],
        "assets": [_with_prov(a) for a in raw["assets"]],
        "services": [_with_prov(s) for s in raw["services"]],
        "relationships": [_with_prov(r) for r in raw["relationships"]],
        "reachability": [_with_prov(rr) for rr in raw["reachability"]],
        "findings": [_with_prov(f) for f in raw["findings"]],
        "controls": [_with_prov(c) for c in raw["controls"]],
        "evidence": [
            {
                **_with_prov(e),
                "sha256": hashlib.sha256(e["excerpt"].encode("utf-8")).hexdigest(),
            }
            for e in raw["evidence"]
        ],
    }


def test_meridian_scenario_1_orders_db_baseline_paths() -> None:
    model = EnvironmentModel.from_snapshot_dict(_meridian_snapshot_dict())
    spec = ScenarioSpec(
        name="Internet to Customer Orders DB",
        start_kind="zone",
        start_key="internet",
        targets=(TargetSpec(asset_key="db-01", level="user"),),
    )
    result = run_scenario(model, spec, snapshot_sha256="abc123")
    assert result["result_kind"] == "scenario_result"
    assert result["disclaimer"] == RESULT_DISCLAIMER
    assert result["engine_version"] == ENGINE_VERSION
    assert result["ruleset_version"] == RULESET_VERSION

    baseline = result["baseline"]
    assert baseline["headline_score"] == 22
    assert baseline["total_paths"] == 2
    assert baseline["search_truncated"] is False

    p1, p2 = baseline["paths"]
    assert p1["modeled_score"] == 22
    assert p1["path_likelihood"] == 0.432
    assert p1["path_confidence"] == 0.7
    assert p1["low_confidence"] is False
    assert [s["rule_id"] for s in p1["steps"]] == ["R-EXP-REMOTE", "R-EXP-REMOTE", "R-CRED-USE"]
    assert [s["target_key"] for s in p1["steps"]] == ["web-01", "app-01", "db-01"]
    assert any("zone-wide rule RR-04" in a for a in p1["steps"][1]["assumptions"])
    assert "EV-014" in p1["steps"][2]["evidence_keys"]

    assert p2["modeled_score"] == 5
    assert p2["path_likelihood"] == 0.216
    assert p2["path_confidence"] == 0.4
    assert p2["low_confidence"] is True
    assert [s["target_key"] for s in p2["steps"]] == ["vpn-01", "app-01", "db-01"]


def test_meridian_defensive_actions_d1_d2_d3_and_combinations() -> None:
    model = EnvironmentModel.from_snapshot_dict(_meridian_snapshot_dict())
    spec = ScenarioSpec(
        name="Internet to Customer Orders DB",
        start_kind="zone",
        start_key="internet",
        targets=(TargetSpec(asset_key="db-01", level="user"),),
    )

    # D1: Remediate F-005 -> both paths disappear
    r_d1 = run_scenario(
        model, spec, actions=[DefensiveAction("remediate_finding", {"finding_key": "F-005"})]
    )
    assert r_d1["modified"]["headline_score"] == 0
    assert r_d1["modified"]["total_paths"] == 0
    assert len(r_d1["comparison"]["removed"]) == 2

    # D2: Remove zone flow RR-04 -> Path 1 disappears, Path 2 remains via RR-05
    r_d2 = run_scenario(
        model, spec, actions=[DefensiveAction("remove_reachability", {"reachability_key": "RR-04"})]
    )
    assert r_d2["modified"]["headline_score"] == 5
    assert r_d2["modified"]["total_paths"] == 1
    assert r_d2["modified"]["paths"][0]["steps"][0]["target_key"] == "vpn-01"
    assert len(r_d2["comparison"]["removed"]) == 1
    assert len(r_d2["comparison"]["remaining"]) == 1

    # D3: Activate WAF CTRL-01 -> Path 1 halved 22 -> 11, Path 2 stays 5
    r_d3 = run_scenario(
        model, spec, actions=[DefensiveAction("activate_control", {"control_key": "CTRL-01"})]
    )
    assert r_d3["modified"]["headline_score"] == 11
    assert r_d3["modified"]["total_paths"] == 2
    mod_p1 = r_d3["modified"]["paths"][0]
    assert mod_p1["modeled_score"] == 11
    assert mod_p1["steps"][0]["controls_applied"][0]["key"] == "CTRL-01"
    assert r_d3["modified"]["paths"][1]["modeled_score"] == 5

    # D2 + D3 combined -> only Path 2 remains at score 5
    r_d2_d3 = run_scenario(
        model,
        spec,
        actions=[
            DefensiveAction("remove_reachability", {"reachability_key": "RR-04"}),
            DefensiveAction("activate_control", {"control_key": "CTRL-01"}),
        ],
    )
    assert r_d2_d3["modified"]["headline_score"] == 5
    assert r_d2_d3["modified"]["total_paths"] == 1

    # Zero-factor control blocks step entirely
    r_block = run_scenario(
        model,
        spec,
        actions=[
            DefensiveAction(
                "add_control",
                {
                    "key": "CTRL-BLOCK-APP",
                    "name": "Virtual patch blocking deserialization",
                    "type": "waf",
                    "asset_key": "app-01",
                    "affects_rules": ["R-EXP-REMOTE"],
                    "ports": [8080],
                    "factor": 0.0,
                },
            )
        ],
    )
    assert r_block["modified"]["total_paths"] == 0
    assert r_block["modified"]["headline_score"] == 0


def test_meridian_scenario_2_and_3_exercise_all_five_rules() -> None:
    model = EnvironmentModel.from_snapshot_dict(_meridian_snapshot_dict())

    # Scenario 2: R-EXP-REMOTE -> R-EXP-LOCAL -> R-CRED-HARVEST (file -> T1552) -> R-IDENTITY-ACCESS
    s2 = ScenarioSpec(
        name="Internet to Finance File Share",
        start_kind="zone",
        start_key="internet",
        targets=(TargetSpec(asset_key="files-01", level="user"),),
    )
    res2 = analyze_scenario(model, s2)
    assert res2.total_paths == 2
    top_rules = [s.rule_id for s in res2.paths[0].steps]
    assert top_rules == [
        "R-EXP-REMOTE",
        "R-EXP-REMOTE",
        "R-EXP-LOCAL",
        "R-CRED-HARVEST",
        "R-IDENTITY-ACCESS",
    ]
    assert res2.paths[0].steps[3].reference_labels == ("T1552",)
    assert res2.paths[0].steps[4].reference_labels == ("T1078",)

    # Scenario 3: Assumed breach ws-101 -> R-EXP-LOCAL -> R-CRED-HARVEST -> jump-01 -> dc-01:admin
    s3 = ScenarioSpec(
        name="Workstation Assumed Breach to Domain Controller",
        start_kind="asset",
        start_key="ws-101",
        start_level="user",
        targets=(TargetSpec(asset_key="dc-01", level="admin"),),
    )
    res3 = analyze_scenario(model, s3)
    assert res3.total_paths == 1
    p = res3.paths[0]
    assert [s.rule_id for s in p.steps] == [
        "R-EXP-LOCAL",
        "R-CRED-HARVEST",
        "R-IDENTITY-ACCESS",
        "R-IDENTITY-ACCESS",
    ]
    assert p.steps[1].reference_labels == ("T1003",)
    # jump-01 step has active MFA CTRL-02 (x0.20)
    assert p.steps[2].controls_applied[0].key == "CTRL-02"
    assert p.steps[2].likelihood == 0.18
    assert p.steps[3].gains == "foothold:dc-01:admin"


def test_zone_isolation_and_relationship_removal_and_search_limits() -> None:
    snap = _meridian_snapshot_dict()
    # Add lateral finding on app-02 reachable only via app intra_zone_policy=allow
    snap["findings"].append(
        {
            "key": "F-TEST-APP2",
            "title": "Unauthenticated RCE on app-02",
            "category": "remote_exploitable",
            "severity": "high",
            "status": "open",
            "grants": "user",
            "requires_auth": False,
            "affected_assets": [{"asset_key": "app-02", "port": 8443, "status_override": None}],
            "origin": "manual",
            "source": "test",
            "observed_at": "2026-11-18T14:00:00Z",
            "confidence": 0.9,
            "evidence_keys": [],
        }
    )
    model = EnvironmentModel.from_snapshot_dict(snap)
    spec = ScenarioSpec(
        name="Reach app-02 from app-01",
        start_kind="asset",
        start_key="app-01",
        targets=(TargetSpec(asset_key="app-02", level="user"),),
    )
    baseline = run_scenario(model, spec)
    assert baseline["baseline"]["total_paths"] == 1
    isolated = run_scenario(
        model,
        spec,
        actions=[
            DefensiveAction(
                "set_zone_isolation", {"zone_key": "app", "intra_zone_policy": "deny"}
            )
        ],
    )
    assert isolated["modified"]["total_paths"] == 0

    # Removing REL-01 breaks all paths to db-01
    no_rel = run_scenario(
        model,
        ScenarioSpec(
            name="Internet -> db-01",
            start_kind="zone",
            start_key="internet",
            targets=(TargetSpec(asset_key="db-01", level="user"),),
        ),
        actions=[DefensiveAction("remove_relationship", {"relationship_key": "REL-01"})],
    )
    assert no_rel["modified"]["total_paths"] == 0

    # Expansion budget truncation flag
    truncated = analyze_scenario(
        model,
        ScenarioSpec(
            name="Budget test",
            start_kind="zone",
            start_key="internet",
            targets=(TargetSpec(asset_key="db-01", level="user"),),
            max_expansions=1,
        ),
    )
    assert truncated.search_truncated is True
    assert truncated.total_paths == 0
