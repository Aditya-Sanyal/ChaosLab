"""Parametrized evaluation suite verifying expected path sets, scores, and traceability."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chaoslab.analysis import (
    DefensiveAction,
    EnvironmentModel,
    ScenarioSpec,
    TargetSpec,
    run_scenario,
)

EVAL_DIR = Path(__file__).resolve().parent / "fixtures" / "eval"
EVAL_FILES = sorted(EVAL_DIR.glob("eval_*.json"))


@pytest.mark.parametrize("fixture_path", EVAL_FILES, ids=lambda p: p.stem)
def test_evaluation_fixture_yields_expected_paths_and_traceability(fixture_path: Path) -> None:
    spec_doc = json.loads(fixture_path.read_text(encoding="utf-8"))
    snap = spec_doc["snapshot"]
    known_evidence = {e["key"] for e in snap.get("evidence", [])}
    model = EnvironmentModel.from_snapshot_dict(snap)

    sc_raw = spec_doc["scenario"]
    spec = ScenarioSpec(
        name=sc_raw["name"],
        start_kind=sc_raw["start_kind"],
        start_key=sc_raw["start_key"],
        start_level=sc_raw.get("start_level", "user"),
        targets=tuple(
            TargetSpec(asset_key=t["asset_key"], level=t.get("level", "user"))
            for t in sc_raw["targets"]
        ),
    )
    actions = [
        DefensiveAction(kind=a["kind"], params=dict(a.get("params") or {}))
        for a in spec_doc.get("actions", [])
    ]

    result = run_scenario(model, spec, actions=actions, snapshot_sha256="eval-snap")
    baseline = result["baseline"]
    exp = spec_doc["expected_baseline"]

    assert baseline["headline_score"] == exp["headline_score"]
    assert baseline["total_paths"] == exp["total_paths"]
    assert baseline["search_truncated"] is exp["search_truncated"]

    for actual_path, exp_path in zip(baseline["paths"], exp["paths"], strict=True):
        assert actual_path["modeled_score"] == exp_path["modeled_score"]
        assert actual_path["low_confidence"] is exp_path["low_confidence"]
        actual_steps = [[s["rule_id"], s["target_key"]] for s in actual_path["steps"]]
        assert actual_steps == exp_path["steps"]

        for step in actual_path["steps"]:
            assert step["rule_id"]
            assert len(step["prerequisites"]) >= 2
            for ev_key in step["evidence_keys"]:
                assert ev_key in known_evidence

    if spec_doc.get("expected_modified") is not None:
        mod = result["modified"]
        exp_mod = spec_doc["expected_modified"]
        assert mod is not None
        assert mod["headline_score"] == exp_mod["headline_score"]
        assert mod["total_paths"] == exp_mod["total_paths"]
