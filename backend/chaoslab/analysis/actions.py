"""Defensive action application (in-memory model mutations) and before/after diffing."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from chaoslab.analysis.canonical import round_float
from chaoslab.analysis.models import (
    VALID_DEFENSIVE_ACTION_KINDS,
    VALID_RULE_IDS,
    AnalysisOutput,
    ControlModel,
    DefensiveAction,
    EnvironmentModel,
    Provenance,
    ScenarioSpec,
)


def validate_scenario_and_actions(
    model: EnvironmentModel,
    spec: ScenarioSpec,
    actions: tuple[DefensiveAction, ...] | list[DefensiveAction] = (),
) -> list[DefensiveAction]:
    """Validate scenario bounds/references and normalize defensive actions against a snapshot."""
    if spec.start_kind == "zone":
        if spec.start_key not in model.zones_by_key:
            raise ValueError(f"Start zone '{spec.start_key}' not found in snapshot.")
    elif spec.start_kind == "asset":
        if spec.start_key not in model.assets_by_key:
            raise ValueError(f"Start asset '{spec.start_key}' not found in snapshot.")
    else:
        raise ValueError("start_kind must be 'zone' or 'asset'.")

    if spec.start_level not in ("user", "admin"):
        raise ValueError("start_level must be 'user' or 'admin'.")

    if not (1 <= len(spec.targets) <= 20):
        raise ValueError("Scenario must specify between 1 and 20 targets.")

    seen_targets: set[tuple[str, str]] = set()
    for target in spec.targets:
        if target.asset_key not in model.assets_by_key:
            raise ValueError(f"Target asset '{target.asset_key}' not found in snapshot.")
        if target.level not in ("user", "admin", "identity"):
            raise ValueError(f"Invalid target level '{target.level}' for '{target.asset_key}'.")
        pair = (target.asset_key, target.level)
        if pair in seen_targets:
            raise ValueError(
                f"Duplicate target '{target.asset_key}:{target.level}' in scenario."
            )
        seen_targets.add(pair)

    if not (1 <= spec.max_depth <= 12):
        raise ValueError("max_depth must be between 1 and 12.")
    if not (1 <= spec.k_paths <= 20):
        raise ValueError("k_paths must be between 1 and 20.")
    if not (10 <= spec.max_expansions <= 50000):
        raise ValueError("max_expansions must be between 10 and 50000.")

    normalized: list[DefensiveAction] = []
    for idx, action in enumerate(actions):
        if action.kind not in VALID_DEFENSIVE_ACTION_KINDS:
            raise ValueError(f"Unsupported defensive action kind: '{action.kind}'.")
        params = dict(action.params or {})

        if action.kind == "remediate_finding":
            finding_key = params.get("finding_key")
            if not isinstance(finding_key, str) or finding_key not in model.findings_by_key:
                raise ValueError(
                    f"Action #{idx + 1} (remediate_finding): finding '{finding_key}' not found."
                )
            finding = model.findings_by_key[finding_key]
            asset_key = params.get("asset_key")
            if asset_key == "":
                asset_key = None
            if asset_key is not None:
                if not isinstance(asset_key, str) or asset_key not in model.assets_by_key:
                    raise ValueError(
                        f"Action #{idx + 1} (remediate_finding): asset '{asset_key}' not found."
                    )
                affected = {fa.asset_key for fa in finding.affected_assets}
                if asset_key not in affected:
                    raise ValueError(
                        f"Action #{idx + 1} (remediate_finding): asset '{asset_key}' is not "
                        f"affected by finding '{finding_key}'."
                    )
            norm_params: dict[str, Any] = {"finding_key": finding_key}
            if asset_key is not None:
                norm_params["asset_key"] = asset_key
            normalized.append(DefensiveAction(kind=action.kind, params=norm_params))

        elif action.kind == "remove_relationship":
            rel_key = params.get("relationship_key")
            if not isinstance(rel_key, str) or rel_key not in model.relationships_by_key:
                raise ValueError(
                    f"Action #{idx + 1} (remove_relationship): relationship '{rel_key}' not found."
                )
            normalized.append(
                DefensiveAction(kind=action.kind, params={"relationship_key": rel_key})
            )

        elif action.kind == "remove_reachability":
            rr_key = params.get("reachability_key")
            if not isinstance(rr_key, str) or rr_key not in model.reachability_by_key:
                raise ValueError(
                    f"Action #{idx + 1} (remove_reachability): reachability '{rr_key}' not found."
                )
            normalized.append(
                DefensiveAction(kind=action.kind, params={"reachability_key": rr_key})
            )

        elif action.kind == "set_zone_isolation":
            zone_key = params.get("zone_key")
            if not isinstance(zone_key, str) or zone_key not in model.zones_by_key:
                raise ValueError(
                    f"Action #{idx + 1} (set_zone_isolation): zone '{zone_key}' not found."
                )
            policy = params.get("intra_zone_policy", "deny")
            if policy not in ("deny", "allow"):
                raise ValueError(
                    f"Action #{idx + 1} (set_zone_isolation): intra_zone_policy must be "
                    "'deny' or 'allow'."
                )
            normalized.append(
                DefensiveAction(
                    kind=action.kind,
                    params={"zone_key": zone_key, "intra_zone_policy": policy},
                )
            )

        elif action.kind == "activate_control":
            ctrl_key = params.get("control_key")
            if not isinstance(ctrl_key, str) or ctrl_key not in model.controls_by_key:
                raise ValueError(
                    f"Action #{idx + 1} (activate_control): control '{ctrl_key}' not found."
                )
            normalized.append(
                DefensiveAction(kind=action.kind, params={"control_key": ctrl_key})
            )

        elif action.kind == "add_control":
            raw_key = params.get("key")
            if not isinstance(raw_key, str) or not (1 <= len(raw_key.strip()) <= 128):
                raise ValueError(
                    f"Action #{idx + 1} (add_control): non-empty control key (<=128 chars) needed."
                )
            ctrl_key = raw_key.strip()

            raw_name = params.get("name", ctrl_key)
            if not isinstance(raw_name, str) or len(raw_name) > 255:
                raise ValueError(
                    f"Action #{idx + 1} (add_control): control name must be <=255 chars."
                )
            ctrl_name = raw_name.strip() or ctrl_key

            raw_type = params.get("type", "other")
            if not isinstance(raw_type, str) or not (1 <= len(raw_type.strip()) <= 32):
                raise ValueError(
                    f"Action #{idx + 1} (add_control): control type must be 1..32 chars."
                )
            ctrl_type = raw_type.strip()

            asset_key = params.get("asset_key")
            if not isinstance(asset_key, str) or asset_key not in model.assets_by_key:
                raise ValueError(
                    f"Action #{idx + 1} (add_control): asset '{asset_key}' not found in snapshot."
                )

            raw_rules = params.get("affects_rules")
            if not isinstance(raw_rules, (list, tuple)) or len(raw_rules) == 0:
                raise ValueError(
                    f"Action #{idx + 1} (add_control): affects_rules must be a non-empty list."
                )
            clean_rules: list[str] = []
            for rule_id in raw_rules:
                if not isinstance(rule_id, str) or rule_id not in VALID_RULE_IDS:
                    raise ValueError(
                        f"Action #{idx + 1} (add_control): invalid rule id '{rule_id}'."
                    )
                clean_rules.append(rule_id)

            raw_ports = params.get("ports")
            if raw_ports is None:
                raw_ports = []
            if not isinstance(raw_ports, (list, tuple)):
                raise ValueError(f"Action #{idx + 1} (add_control): ports must be a list.")
            clean_ports: list[int] = []
            for port in raw_ports:
                if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ValueError(
                        f"Action #{idx + 1} (add_control): invalid port '{port}' "
                        "(must be 1..65535)."
                    )
                clean_ports.append(port)

            raw_factor = params.get("factor")
            if isinstance(raw_factor, bool) or not isinstance(raw_factor, (int, float)):
                raise ValueError(
                    f"Action #{idx + 1} (add_control): numeric factor in [0.0, 1.0] is required."
                )
            factor_val = float(raw_factor)
            if not (0.0 <= factor_val <= 1.0):
                raise ValueError(
                    f"Action #{idx + 1} (add_control): factor must be between 0.0 and 1.0."
                )

            normalized.append(
                DefensiveAction(
                    kind=action.kind,
                    params={
                        "key": ctrl_key,
                        "name": ctrl_name,
                        "type": ctrl_type,
                        "asset_key": asset_key,
                        "affects_rules": sorted(set(clean_rules)),
                        "ports": sorted(set(clean_ports)),
                        "factor": round_float(factor_val),
                    },
                )
            )

    return normalized


def apply_defensive_actions(
    model: EnvironmentModel,
    actions: tuple[DefensiveAction, ...] | list[DefensiveAction],
) -> EnvironmentModel:
    """Return a new EnvironmentModel reflecting the defensive actions without mutating input."""
    zones = list(model.zones)
    relationships = list(model.relationships)
    reachability = list(model.reachability)
    findings = list(model.findings)
    controls = list(model.controls)

    for action in actions:
        params = action.params
        if action.kind == "remediate_finding":
            finding_key = params["finding_key"]
            asset_key = params.get("asset_key")
            new_findings = []
            for f in findings:
                if f.key != finding_key:
                    new_findings.append(f)
                    continue
                if asset_key is None:
                    new_findings.append(replace(f, status="remediated"))
                else:
                    new_affected = tuple(
                        replace(fa, status_override="remediated")
                        if fa.asset_key == asset_key
                        else fa
                        for fa in f.affected_assets
                    )
                    new_findings.append(replace(f, affected_assets=new_affected))
            findings = new_findings

        elif action.kind == "remove_relationship":
            rel_key = params["relationship_key"]
            relationships = [r for r in relationships if r.key != rel_key]

        elif action.kind == "remove_reachability":
            rr_key = params["reachability_key"]
            reachability = [rr for rr in reachability if rr.key != rr_key]

        elif action.kind == "set_zone_isolation":
            zone_key = params["zone_key"]
            policy = params.get("intra_zone_policy", "deny")
            zones = [
                replace(z, intra_zone_policy=policy) if z.key == zone_key else z for z in zones
            ]

        elif action.kind == "activate_control":
            ctrl_key = params["control_key"]
            controls = [
                replace(c, status="active") if c.key == ctrl_key else c for c in controls
            ]

        elif action.kind == "add_control":
            ctrl_key = params["key"]
            new_ctrl = ControlModel(
                key=ctrl_key,
                name=params.get("name", ctrl_key),
                type=params.get("type", "other"),
                asset_key=params["asset_key"],
                affects_rules=tuple(sorted(params.get("affects_rules", []))),
                ports=tuple(sorted(int(p) for p in params.get("ports") or ())),
                factor=float(params["factor"]),
                status="active",
                provenance=Provenance(
                    origin="manual",
                    source="scenario:defensive_action",
                    observed_at="",
                    confidence=1.0,
                ),
                evidence_keys=(),
            )
            controls = [c for c in controls if c.key != ctrl_key]
            controls.append(new_ctrl)

        else:
            raise ValueError(f"Unsupported defensive action kind: {action.kind}")

    zones.sort(key=lambda x: x.key)
    relationships.sort(key=lambda x: x.key)
    reachability.sort(key=lambda x: x.key)
    findings.sort(key=lambda x: x.key)
    controls.sort(key=lambda x: x.key)

    return EnvironmentModel(
        environment_id=model.environment_id,
        environment_name=model.environment_name,
        zones=tuple(zones),
        assets=model.assets,
        services=model.services,
        relationships=tuple(relationships),
        reachability=tuple(reachability),
        findings=tuple(findings),
        controls=tuple(controls),
        evidence=model.evidence,
    )


def compare_outputs(baseline: AnalysisOutput, modified: AnalysisOutput) -> dict:
    """Produce structured before/after path comparison."""
    base_by_key = {p.path_key: p for p in baseline.paths}
    mod_by_key = {p.path_key: p for p in modified.paths}

    removed = []
    remaining = []
    new = []

    for path_key in sorted(base_by_key):
        bp = base_by_key[path_key]
        if path_key not in mod_by_key:
            removed.append(
                {
                    "path_key": path_key,
                    "target_key": bp.target_key,
                    "score_before": bp.modeled_score,
                    "score_after": 0,
                    "score_delta": -bp.modeled_score,
                    "status": "removed",
                }
            )
        else:
            mp = mod_by_key[path_key]
            changed_steps = []
            for bs, ms in zip(bp.steps, mp.steps, strict=True):
                if (
                    bs.likelihood != ms.likelihood
                    or bs.controls_applied != ms.controls_applied
                ):
                    changed_steps.append(
                        {
                            "step_key": bs.step_key,
                            "likelihood_before": bs.likelihood,
                            "likelihood_after": ms.likelihood,
                            "controls_after": [c.key for c in ms.controls_applied],
                        }
                    )
            if mp.modeled_score < bp.modeled_score:
                path_status = "reduced"
            elif mp.modeled_score > bp.modeled_score:
                path_status = "increased"
            else:
                path_status = "unchanged"
            remaining.append(
                {
                    "path_key": path_key,
                    "target_key": bp.target_key,
                    "score_before": bp.modeled_score,
                    "score_after": mp.modeled_score,
                    "score_delta": mp.modeled_score - bp.modeled_score,
                    "status": path_status,
                    "changed_steps": changed_steps,
                }
            )

    for path_key in sorted(mod_by_key):
        if path_key not in base_by_key:
            mp = mod_by_key[path_key]
            new.append(
                {
                    "path_key": path_key,
                    "target_key": mp.target_key,
                    "score_before": 0,
                    "score_after": mp.modeled_score,
                    "score_delta": mp.modeled_score,
                    "status": "new",
                }
            )

    return {
        "baseline_headline_score": baseline.headline_score,
        "modified_headline_score": modified.headline_score,
        "score_delta": modified.headline_score - baseline.headline_score,
        "baseline_path_count": baseline.total_paths,
        "modified_path_count": modified.total_paths,
        "removed": removed,
        "remaining": remaining,
        "new": new,
    }


def compare_serialized_analyses(
    analysis_a: dict[str, Any],
    analysis_b: dict[str, Any],
) -> dict[str, Any]:
    """Compare two serialized AnalysisSection payloads by path_key."""
    base_by_key = {p["path_key"]: p for p in analysis_a.get("paths", [])}
    mod_by_key = {p["path_key"]: p for p in analysis_b.get("paths", [])}

    removed: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    new: list[dict[str, Any]] = []

    for path_key in sorted(base_by_key):
        bp = base_by_key[path_key]
        score_before = int(bp.get("modeled_score", 0))
        if path_key not in mod_by_key:
            removed.append(
                {
                    "path_key": path_key,
                    "target_key": bp["target_key"],
                    "score_before": score_before,
                    "score_after": 0,
                    "score_delta": -score_before,
                    "status": "removed",
                }
            )
            continue

        mp = mod_by_key[path_key]
        score_after = int(mp.get("modeled_score", 0))
        changed_steps: list[dict[str, Any]] = []
        steps_a = bp.get("steps", [])
        steps_b = mp.get("steps", [])
        if len(steps_a) == len(steps_b):
            for sa, sb in zip(steps_a, steps_b, strict=True):
                ctrls_a = sorted(c["key"] for c in sa.get("controls_applied", []))
                ctrls_b = sorted(c["key"] for c in sb.get("controls_applied", []))
                if sa.get("likelihood") != sb.get("likelihood") or ctrls_a != ctrls_b:
                    changed_steps.append(
                        {
                            "step_key": sa["step_key"],
                            "likelihood_before": sa.get("likelihood"),
                            "likelihood_after": sb.get("likelihood"),
                            "controls_after": ctrls_b,
                        }
                    )

        if score_after < score_before:
            path_status = "reduced"
        elif score_after > score_before:
            path_status = "increased"
        else:
            path_status = "unchanged"

        remaining.append(
            {
                "path_key": path_key,
                "target_key": bp["target_key"],
                "score_before": score_before,
                "score_after": score_after,
                "score_delta": score_after - score_before,
                "status": path_status,
                "changed_steps": changed_steps,
            }
        )

    for path_key in sorted(mod_by_key):
        if path_key not in base_by_key:
            mp = mod_by_key[path_key]
            score_after = int(mp.get("modeled_score", 0))
            new.append(
                {
                    "path_key": path_key,
                    "target_key": mp["target_key"],
                    "score_before": 0,
                    "score_after": score_after,
                    "score_delta": score_after,
                    "status": "new",
                }
            )

    head_a = int(analysis_a.get("headline_score", 0))
    head_b = int(analysis_b.get("headline_score", 0))
    count_a = int(analysis_a.get("total_paths", len(base_by_key)))
    count_b = int(analysis_b.get("total_paths", len(mod_by_key)))

    return {
        "baseline_headline_score": head_a,
        "modified_headline_score": head_b,
        "score_delta": head_b - head_a,
        "baseline_path_count": count_a,
        "modified_path_count": count_b,
        "removed": removed,
        "remaining": remaining,
        "new": new,
    }
