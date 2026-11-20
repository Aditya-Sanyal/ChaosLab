"""Pure offline attack-path simulation engine public entrypoints."""

from __future__ import annotations

from typing import Any

from chaoslab.analysis.actions import (
    apply_defensive_actions,
    compare_outputs,
    compare_serialized_analyses,
    validate_scenario_and_actions,
)
from chaoslab.analysis.canonical import normalize_for_canonical, sha256_canonical
from chaoslab.analysis.models import (
    ENGINE_VERSION,
    GLOBAL_ASSUMPTIONS,
    RESULT_DISCLAIMER,
    RULESET_VERSION,
    VALID_DEFENSIVE_ACTION_KINDS,
    VALID_RULE_IDS,
    AnalysisOutput,
    DefensiveAction,
    EnvironmentModel,
    ScenarioSpec,
    TargetSpec,
)
from chaoslab.analysis.search import analyze_scenario

__all__ = [
    "ENGINE_VERSION",
    "GLOBAL_ASSUMPTIONS",
    "RESULT_DISCLAIMER",
    "RULESET_VERSION",
    "VALID_DEFENSIVE_ACTION_KINDS",
    "VALID_RULE_IDS",
    "DefensiveAction",
    "EnvironmentModel",
    "ScenarioSpec",
    "TargetSpec",
    "analyze_scenario",
    "apply_defensive_actions",
    "compare_outputs",
    "compare_serialized_analyses",
    "run_scenario",
    "sha256_canonical",
    "validate_scenario_and_actions",
]


def _serialize_analysis(output: AnalysisOutput) -> dict[str, Any]:
    return normalize_for_canonical(
        {
            "headline_score": output.headline_score,
            "total_paths": output.total_paths,
            "search_truncated": output.search_truncated,
            "limits": output.limits,
            "paths": list(output.paths),
            "results_by_target": list(output.results_by_target),
        }
    )


def run_scenario(
    model: EnvironmentModel,
    spec: ScenarioSpec,
    actions: tuple[DefensiveAction, ...] | list[DefensiveAction] = (),
    snapshot_id: str = "",
    snapshot_sha256: str = "",
) -> dict[str, Any]:
    """Execute deterministic baseline (+ optional defensive action comparison) simulation."""
    action_tuple = tuple(actions)
    input_payload = {
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "snapshot_sha256": snapshot_sha256,
        "scenario": spec,
        "actions": list(action_tuple),
    }
    input_sha256 = sha256_canonical(input_payload)

    baseline_output = analyze_scenario(model, spec)
    baseline_dict = _serialize_analysis(baseline_output)

    modified_dict = None
    comparison_dict = None
    if action_tuple:
        modified_model = apply_defensive_actions(model, action_tuple)
        modified_output = analyze_scenario(modified_model, spec)
        modified_dict = _serialize_analysis(modified_output)
        comparison_dict = normalize_for_canonical(compare_outputs(baseline_output, modified_output))

    core_result = {
        "result_kind": "scenario_result",
        "disclaimer": RESULT_DISCLAIMER,
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_sha256": snapshot_sha256,
        "scenario": normalize_for_canonical(spec),
        "actions": normalize_for_canonical(list(action_tuple)),
        "global_assumptions": list(GLOBAL_ASSUMPTIONS),
        "baseline": baseline_dict,
        "modified": modified_dict,
        "comparison": comparison_dict,
        "input_sha256": input_sha256,
    }
    # Compute result hash over deterministic simulation content (excluding DB snapshot_id UUID
    # so identical content yields identical result_sha256 across databases/re-seeds).
    result_hash_material = {k: v for k, v in core_result.items() if k != "snapshot_id"}
    core_result["result_sha256"] = sha256_canonical(result_hash_material)
    return core_result
