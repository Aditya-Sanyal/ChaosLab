"""Unit tests for Scenario Lab validation, all 6 defensive actions, and run diffing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chaoslab.analysis import (
    DefensiveAction,
    EnvironmentModel,
    ScenarioSpec,
    TargetSpec,
    compare_outputs,
    compare_serialized_analyses,
    run_scenario,
    validate_scenario_and_actions,
)
from chaoslab.analysis.search import analyze_scenario


def _meridian_doc() -> dict:
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


def _orders_spec() -> ScenarioSpec:
    return ScenarioSpec(
        name="Internet to Customer Orders DB",
        start_kind="zone",
        start_key="internet",
        targets=(TargetSpec(asset_key="db-01", level="user"),),
    )


def test_all_six_defensive_action_kinds_and_asset_scoped_remediation() -> None:
    doc = _meridian_doc()
    # Add a second asset app-02 to F-005 and allow lateral flow to test asset-scoped remediation
    for f in doc["findings"]:
        if f["key"] == "F-005":
            f["affected_assets"].append(
                {"asset_key": "app-02", "port": 8080, "status_override": None}
            )
    doc["reachability"].append(
        {
            "key": "RR-TEST-APP2",
            "source_kind": "asset",
            "source_key": "dmz",
            "target_kind": "asset",
            "target_key": "app-02",
            "ports": [8080],
            "protocol": "tcp",
            "description": "Test link",
            "origin": "manual",
            "source": "test",
            "observed_at": "2026-11-18T00:00:00Z",
            "confidence": 0.9,
            "evidence_keys": [],
        }
    )
    model = EnvironmentModel.from_snapshot_dict(doc)
    spec = _orders_spec()

    # 1. remediate_finding scoped strictly to app-02 keeps app-01 paths open
    r_scoped = run_scenario(
        model,
        spec,
        actions=[
            DefensiveAction("remediate_finding", {"finding_key": "F-005", "asset_key": "app-02"})
        ],
    )
    assert r_scoped["modified"]["total_paths"] == 2

    # 2. remediate_finding globally drops both paths
    r_global = run_scenario(
        model, spec, actions=[DefensiveAction("remediate_finding", {"finding_key": "F-005"})]
    )
    assert r_global["modified"]["total_paths"] == 0
    assert r_global["modified"]["headline_score"] == 0

    # 3. remove_reachability (RR-04) removes Path 1, preserves Path 2
    r_rr = run_scenario(
        model,
        spec,
        actions=[DefensiveAction("remove_reachability", {"reachability_key": "RR-04"})],
    )
    assert r_rr["modified"]["headline_score"] == 5
    assert r_rr["modified"]["total_paths"] == 1

    # 4. remove_relationship (REL-01) removes all paths to db-01
    r_rel = run_scenario(
        model,
        spec,
        actions=[DefensiveAction("remove_relationship", {"relationship_key": "REL-01"})],
    )
    assert r_rel["modified"]["total_paths"] == 0

    # 5. activate_control (CTRL-01) halves Path 1 score 22 -> 11, leaves Path 2 at 5
    r_act = run_scenario(
        model,
        spec,
        actions=[DefensiveAction("activate_control", {"control_key": "CTRL-01"})],
    )
    assert r_act["modified"]["headline_score"] == 11
    statuses_by_target = {
        entry["path_key"]: entry["status"] for entry in r_act["comparison"]["remaining"]
    }
    assert set(statuses_by_target.values()) == {"reduced", "unchanged"}
    web_entry = next(
        e for e in r_act["comparison"]["remaining"] if "web-01" in e["path_key"]
    )
    assert web_entry["score_before"] == 22
    assert web_entry["score_after"] == 11
    assert web_entry["status"] == "reduced"

    # 6. add_control zero factor blocks target step completely
    r_add = run_scenario(
        model,
        spec,
        actions=[
            DefensiveAction(
                "add_control",
                {
                    "key": "CTRL-VPATCH",
                    "name": "Block 8080",
                    "type": "waf",
                    "asset_key": "app-01",
                    "affects_rules": ["R-EXP-REMOTE"],
                    "ports": [8080],
                    "factor": 0.0,
                },
            )
        ],
    )
    assert r_add["modified"]["total_paths"] == 0

    # Determinism across repeat runs
    r_act_repeat = run_scenario(
        model,
        spec,
        actions=[DefensiveAction("activate_control", {"control_key": "CTRL-01"})],
    )
    assert r_act["input_sha256"] == r_act_repeat["input_sha256"]
    assert r_act["result_sha256"] == r_act_repeat["result_sha256"]


def test_compare_outputs_and_serialized_analyses_detect_increased_scores() -> None:
    doc = _meridian_doc()
    model = EnvironmentModel.from_snapshot_dict(doc)
    spec = _orders_spec()

    # Artificially weaken/bypass CTRL-02-like scenario OR boost via zone policy / lower factor
    # Here we create a snapshot where db-01 criticality rises OR compare WAF on -> WAF off (A -> B)
    baseline_out = analyze_scenario(model, spec)
    waf_run = run_scenario(
        model, spec, actions=[DefensiveAction("activate_control", {"control_key": "CTRL-01"})]
    )
    # Reverse order: comparing WAF-mitigated (A) vs unmitigated baseline (B) shows score INCREASE
    waf_out = analyze_scenario(model, spec)
    from chaoslab.analysis.actions import apply_defensive_actions

    mitigated_model = apply_defensive_actions(
        model, [DefensiveAction("activate_control", {"control_key": "CTRL-01"})]
    )
    mitigated_out = analyze_scenario(mitigated_model, spec)

    rev_outputs = compare_outputs(mitigated_out, waf_out)
    statuses = {entry["status"] for entry in rev_outputs["remaining"]}
    assert "increased" in statuses

    rev_serialized = compare_serialized_analyses(waf_run["modified"], waf_run["baseline"])
    assert rev_serialized["score_delta"] == 11
    assert any(entry["status"] == "increased" for entry in rev_serialized["remaining"])
    assert any(len(entry["changed_steps"]) > 0 for entry in rev_serialized["remaining"])
    assert baseline_out.headline_score == 22


def test_validate_scenario_and_actions_rejects_invalid_and_normalizes_valid() -> None:
    model = EnvironmentModel.from_snapshot_dict(_meridian_doc())
    spec = _orders_spec()

    normalized = validate_scenario_and_actions(
        model,
        spec,
        [
            DefensiveAction(
                "add_control",
                {
                    "key": "  CTRL-NEW ",
                    "asset_key": "app-01",
                    "affects_rules": ["R-EXP-REMOTE", "R-CRED-USE", "R-EXP-REMOTE"],
                    "ports": [8080, 443, 8080],
                    "factor": 0.25,
                },
            ),
            DefensiveAction("set_zone_isolation", {"zone_key": "app"}),
        ],
    )
    assert normalized[0].params["key"] == "CTRL-NEW"
    assert normalized[0].params["affects_rules"] == ["R-CRED-USE", "R-EXP-REMOTE"]
    assert normalized[0].params["ports"] == [443, 8080]
    assert normalized[1].params["intra_zone_policy"] == "deny"

    # Spec errors
    with pytest.raises(ValueError, match="Start zone"):
        validate_scenario_and_actions(
            model,
            ScenarioSpec(
                name="bad", start_kind="zone", start_key="missing-zone", targets=spec.targets
            ),
        )
    with pytest.raises(ValueError, match="Target asset"):
        validate_scenario_and_actions(
            model,
            ScenarioSpec(
                name="bad",
                start_kind="zone",
                start_key="internet",
                targets=(TargetSpec("no-host", "user"),),
            ),
        )
    with pytest.raises(ValueError, match="Duplicate target"):
        validate_scenario_and_actions(
            model,
            ScenarioSpec(
                name="bad",
                start_kind="zone",
                start_key="internet",
                targets=(TargetSpec("db-01", "user"), TargetSpec("db-01", "user")),
            ),
        )
    with pytest.raises(ValueError, match="max_expansions"):
        validate_scenario_and_actions(
            model,
            ScenarioSpec(
                name="bad",
                start_kind="zone",
                start_key="internet",
                targets=spec.targets,
                max_expansions=5,
            ),
        )

    # Action validation errors (including Python bool-is-int edge case)
    bad_actions = [
        DefensiveAction("unsupported_kind", {}),
        DefensiveAction("remediate_finding", {"finding_key": "F-NOPE"}),
        DefensiveAction("remediate_finding", {"finding_key": "F-005", "asset_key": "db-01"}),
        DefensiveAction("remove_relationship", {"relationship_key": "REL-NOPE"}),
        DefensiveAction("remove_reachability", {"reachability_key": "RR-NOPE"}),
        DefensiveAction("set_zone_isolation", {"zone_key": "app", "intra_zone_policy": "open"}),
        DefensiveAction("activate_control", {"control_key": "CTRL-NOPE"}),
        DefensiveAction(
            "add_control",
            {
                "key": "C1",
                "asset_key": "app-01",
                "affects_rules": ["R-BAD"],
                "factor": 0.5,
            },
        ),
        DefensiveAction(
            "add_control",
            {
                "key": "C2",
                "asset_key": "app-01",
                "affects_rules": ["R-EXP-REMOTE"],
                "ports": [True],
                "factor": 0.5,
            },
        ),
        DefensiveAction(
            "add_control",
            {
                "key": "C3",
                "asset_key": "app-01",
                "affects_rules": ["R-EXP-REMOTE"],
                "factor": True,
            },
        ),
        DefensiveAction(
            "add_control",
            {
                "key": "C4",
                "asset_key": "app-01",
                "affects_rules": ["R-EXP-REMOTE"],
                "factor": 1.5,
            },
        ),
    ]
    for bad in bad_actions:
        with pytest.raises(ValueError):
            validate_scenario_and_actions(model, spec, [bad])
