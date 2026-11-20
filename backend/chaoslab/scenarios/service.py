"""Scenario execution service bridging snapshots, pure analysis engine, and audit."""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from chaoslab.analysis import (
    ENGINE_VERSION,
    RESULT_DISCLAIMER,
    RULESET_VERSION,
    DefensiveAction,
    ScenarioSpec,
    TargetSpec,
    compare_serialized_analyses,
    run_scenario,
    validate_scenario_and_actions,
)
from chaoslab.audit.service import record_event
from chaoslab.db.base import to_utc_iso
from chaoslab.inventory.models import Asset, Environment, Zone
from chaoslab.scenarios.models import Scenario, ScenarioRun
from chaoslab.snapshots.models import Snapshot
from chaoslab.snapshots.repository import SqlGraphRepository


def list_scenarios(db: Session, env_id: str) -> list[Scenario]:
    return list(
        db.execute(
            select(Scenario).where(Scenario.environment_id == env_id).order_by(Scenario.name.asc())
        )
        .scalars()
        .all()
    )


def create_scenario(
    db: Session,
    *,
    env_id: str,
    name: str,
    description: str,
    start_kind: str,
    start_key: str,
    start_level: str,
    targets: list[dict[str, str]],
    max_depth: int,
    k_paths: int,
    max_expansions: int,
    created_by: str,
    actor_user_id: str | None = None,
) -> Scenario:
    if db.get(Environment, env_id) is None:
        raise LookupError(f"Environment '{env_id}' not found.")

    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Scenario name cannot be empty.")

    if start_kind == "zone":
        exists = db.execute(
            select(Zone.id).where(Zone.environment_id == env_id, Zone.key == start_key)
        ).first()
        if exists is None:
            raise ValueError(f"Start zone '{start_key}' not found in environment.")
    elif start_kind == "asset":
        exists = db.execute(
            select(Asset.id).where(Asset.environment_id == env_id, Asset.key == start_key)
        ).first()
        if exists is None:
            raise ValueError(f"Start asset '{start_key}' not found in environment.")
    else:
        raise ValueError("start_kind must be 'zone' or 'asset'.")

    if start_level not in ("user", "admin"):
        raise ValueError("start_level must be 'user' or 'admin'.")

    asset_keys = set(
        db.execute(select(Asset.key).where(Asset.environment_id == env_id)).scalars().all()
    )
    clean_targets: list[dict[str, str]] = []
    seen_targets: set[tuple[str, str]] = set()
    for t in targets:
        a_key = t["asset_key"]
        lvl = t.get("level", "user")
        if a_key not in asset_keys:
            raise ValueError(f"Target asset '{a_key}' not found in environment.")
        if lvl not in ("user", "admin", "identity"):
            raise ValueError(f"Invalid target level '{lvl}' for '{a_key}'.")
        pair = (a_key, lvl)
        if pair in seen_targets:
            raise ValueError(f"Duplicate target '{a_key}:{lvl}' in scenario.")
        seen_targets.add(pair)
        clean_targets.append({"asset_key": a_key, "level": lvl})

    sc = Scenario(
        environment_id=env_id,
        name=clean_name,
        description=description.strip(),
        start_kind=start_kind,
        start_key=start_key,
        start_level=start_level,
        targets=clean_targets,
        parameters={
            "max_depth": int(max_depth),
            "k_paths": int(k_paths),
            "max_expansions": int(max_expansions),
        },
        created_by=created_by,
    )
    db.add(sc)
    db.flush()

    record_event(
        db,
        action="scenario.created",
        subject_type="scenario",
        subject_id=sc.id,
        actor_user_id=actor_user_id,
        actor_email=created_by,
        details={
            "environment_id": env_id,
            "name": sc.name,
            "start_kind": sc.start_kind,
            "start_key": sc.start_key,
            "target_count": len(clean_targets),
        },
    )
    db.commit()
    return sc


def delete_scenario(
    db: Session,
    *,
    env_id: str,
    scenario_id: str,
    actor_email: str,
    actor_user_id: str | None = None,
) -> None:
    sc = db.get(Scenario, scenario_id)
    if sc is None or sc.environment_id != env_id:
        raise LookupError(f"Scenario '{scenario_id}' not found in environment.")

    record_event(
        db,
        action="scenario.deleted",
        subject_type="scenario",
        subject_id=sc.id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={"environment_id": env_id, "name": sc.name},
    )
    db.delete(sc)
    db.commit()


def list_runs(
    db: Session,
    env_id: str,
    *,
    snapshot_id: str | None = None,
    scenario_id: str | None = None,
    limit: int = 50,
) -> list[ScenarioRun]:
    stmt = select(ScenarioRun).where(ScenarioRun.environment_id == env_id)
    if snapshot_id is not None:
        stmt = stmt.where(ScenarioRun.snapshot_id == snapshot_id)
    if scenario_id is not None:
        stmt = stmt.where(ScenarioRun.scenario_id == scenario_id)
    stmt = stmt.order_by(ScenarioRun.created_at.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())


def get_run(db: Session, run_id: str) -> ScenarioRun | None:
    return db.get(ScenarioRun, run_id)


def execute_scenario_run(
    db: Session,
    *,
    snapshot_id: str,
    created_by: str,
    actor_user_id: str | None = None,
    scenario_id: str | None = None,
    inline_scenario: dict[str, Any] | None = None,
    actions: list[dict[str, Any]] | None = None,
) -> ScenarioRun:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise LookupError(f"Snapshot {snapshot_id} not found")

    if scenario_id is not None:
        sc = db.get(Scenario, scenario_id)
        if sc is None or sc.environment_id != snap.environment_id:
            raise LookupError(f"Scenario {scenario_id} not found in snapshot environment")
        spec = ScenarioSpec(
            name=sc.name,
            start_kind=sc.start_kind,
            start_key=sc.start_key,
            start_level=sc.start_level,
            targets=tuple(
                TargetSpec(asset_key=t["asset_key"], level=t.get("level", "user"))
                for t in sc.targets
            ),
            max_depth=int(sc.parameters.get("max_depth", 6)),
            k_paths=int(sc.parameters.get("k_paths", 5)),
            max_expansions=int(sc.parameters.get("max_expansions", 20000)),
        )
    elif inline_scenario is not None:
        spec = ScenarioSpec(
            name=inline_scenario["name"],
            start_kind=inline_scenario["start_kind"],
            start_key=inline_scenario["start_key"],
            start_level=inline_scenario.get("start_level", "user"),
            targets=tuple(
                TargetSpec(asset_key=t["asset_key"], level=t.get("level", "user"))
                for t in inline_scenario["targets"]
            ),
            max_depth=int(inline_scenario.get("max_depth", 6)),
            k_paths=int(inline_scenario.get("k_paths", 5)),
            max_expansions=int(inline_scenario.get("max_expansions", 20000)),
        )
    else:
        raise ValueError("Either scenario_id or inline_scenario must be provided")

    parsed_actions = [
        DefensiveAction(kind=a["kind"], params=dict(a.get("params") or {}))
        for a in (actions or [])
    ]

    repo = SqlGraphRepository(db)
    model = repo.load_snapshot(snapshot_id)
    normalized_actions = validate_scenario_and_actions(model, spec, parsed_actions)
    stored_actions = [{"kind": a.kind, "params": dict(a.params)} for a in normalized_actions]

    t0 = time.perf_counter()
    result = run_scenario(
        model,
        spec,
        actions=normalized_actions,
        snapshot_id=snap.id,
        snapshot_sha256=snap.sha256,
    )
    duration_ms = int((time.perf_counter() - t0) * 1000)

    run = ScenarioRun(
        environment_id=snap.environment_id,
        scenario_id=scenario_id,
        snapshot_id=snap.id,
        actions=stored_actions,
        engine_version=ENGINE_VERSION,
        ruleset_version=RULESET_VERSION,
        input_sha256=result["input_sha256"],
        result_sha256=result["result_sha256"],
        result=result,
        status="completed",
        duration_ms=duration_ms,
        created_by=created_by,
    )
    db.add(run)
    db.flush()

    record_event(
        db,
        action="scenario.run",
        subject_type="scenario_run",
        subject_id=run.id,
        actor_user_id=actor_user_id,
        actor_email=created_by,
        details={
            "environment_id": snap.environment_id,
            "snapshot_id": snap.id,
            "snapshot_sha256": snap.sha256,
            "scenario_name": spec.name,
            "headline_score": result["baseline"]["headline_score"],
            "result_sha256": result["result_sha256"],
            "action_count": len(normalized_actions),
        },
    )
    db.commit()
    return run


def _run_brief(run: ScenarioRun, effective_analysis: dict[str, Any]) -> dict[str, Any]:
    actions = list(run.actions or [])
    scenario_meta = run.result.get("scenario") or {}
    return {
        "id": run.id,
        "environment_id": run.environment_id,
        "scenario_id": run.scenario_id,
        "scenario_name": str(scenario_meta.get("name") or "Ad-hoc scenario"),
        "snapshot_id": run.snapshot_id,
        "snapshot_sha256": str(run.result.get("snapshot_sha256") or ""),
        "action_count": len(actions),
        "actions": actions,
        "effective_headline_score": int(effective_analysis.get("headline_score", 0)),
        "effective_path_count": int(effective_analysis.get("total_paths", 0)),
        "input_sha256": run.input_sha256,
        "result_sha256": run.result_sha256,
        "created_by": run.created_by,
        "created_at": to_utc_iso(run.created_at),
    }


def compare_scenario_runs(
    db: Session,
    *,
    run_a_id: str,
    run_b_id: str,
) -> dict[str, Any]:
    """Compare effective modeled outcomes of two stored scenario runs."""
    run_a = db.get(ScenarioRun, run_a_id)
    if run_a is None:
        raise LookupError(f"Run '{run_a_id}' not found.")
    run_b = db.get(ScenarioRun, run_b_id)
    if run_b is None:
        raise LookupError(f"Run '{run_b_id}' not found.")
    if run_a.environment_id != run_b.environment_id:
        raise ValueError("Cannot compare runs from different environments.")

    eff_a = run_a.result.get("modified") or run_a.result["baseline"]
    eff_b = run_b.result.get("modified") or run_b.result["baseline"]
    comparison = compare_serialized_analyses(eff_a, eff_b)

    same_snapshot = run_a.snapshot_id == run_b.snapshot_id
    same_scenario = run_a.result.get("scenario") == run_b.result.get("scenario")
    warnings: list[str] = []
    if not same_snapshot:
        warnings.append(
            "Runs belong to different snapshots; path differences may reflect inventory or "
            "finding status changes as well as defensive actions."
        )
    if not same_scenario:
        warnings.append(
            "Runs use different scenario definitions (start point, targets, or limits); "
            "compare scores cautiously."
        )

    return {
        "result_kind": "run_comparison",
        "disclaimer": RESULT_DISCLAIMER,
        "run_a": _run_brief(run_a, eff_a),
        "run_b": _run_brief(run_b, eff_b),
        "same_snapshot": same_snapshot,
        "same_scenario": same_scenario,
        "same_input_hash": run_a.input_sha256 == run_b.input_sha256,
        "same_result_hash": run_a.result_sha256 == run_b.result_sha256,
        "warnings": warnings,
        "comparison": comparison,
    }


def analyze_snapshot_attack_paths(
    db: Session,
    *,
    snapshot_id: str,
    start_kind: str = "zone",
    start_key: str | None = None,
    start_level: str = "user",
    target_mode: str = "crown_jewels",
    goal_level: str = "user",
    k_paths: int = 5,
    max_depth: int = 6,
    max_expansions: int = 20000,
) -> dict[str, Any]:
    """Read-only deterministic multi-target modeled attack path sweep over a snapshot."""
    from chaoslab.analysis import GLOBAL_ASSUMPTIONS, RESULT_DISCLAIMER, sha256_canonical

    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise LookupError(f"Snapshot {snapshot_id} not found")

    zones = snap.document.get("zones", [])
    assets = snap.document.get("assets", [])
    zone_keys = {z["key"] for z in zones}
    asset_by_key = {a["key"]: a for a in assets}

    resolved_start_key = start_key
    if start_kind == "zone":
        if resolved_start_key is None:
            untrusted = [z["key"] for z in zones if z.get("trust_level") == "untrusted"]
            resolved_start_key = untrusted[0] if untrusted else (zones[0]["key"] if zones else "")
        if resolved_start_key not in zone_keys:
            raise ValueError(f"Start zone '{resolved_start_key}' not found in snapshot.")
    elif start_kind == "asset":
        if not resolved_start_key or resolved_start_key not in asset_by_key:
            raise ValueError(f"Start asset '{resolved_start_key}' not found in snapshot.")
    else:
        raise ValueError("start_kind must be 'zone' or 'asset'.")

    if target_mode == "crown_jewels":
        selected_assets = [
            a
            for a in assets
            if int(a.get("criticality", 1)) >= 5 or "crown_jewel" in (a.get("tags") or [])
        ]
    elif target_mode == "high_criticality":
        selected_assets = [a for a in assets if int(a.get("criticality", 1)) >= 4]
    elif target_mode == "all_assets":
        selected_assets = sorted(
            assets, key=lambda a: (-int(a.get("criticality", 1)), a["key"])
        )[:25]
    else:
        raise ValueError("target_mode must be 'crown_jewels', 'high_criticality', or 'all_assets'.")

    selected_assets.sort(key=lambda a: (-int(a.get("criticality", 1)), a["key"]))

    if not selected_assets:
        return {
            "result_kind": "modeled_attack_paths",
            "disclaimer": RESULT_DISCLAIMER,
            "engine_version": ENGINE_VERSION,
            "ruleset_version": RULESET_VERSION,
            "snapshot_id": snap.id,
            "snapshot_sha256": snap.sha256,
            "start_kind": start_kind,
            "start_key": resolved_start_key,
            "start_level": start_level,
            "target_mode": target_mode,
            "goal_level": goal_level,
            "headline_score": 0,
            "total_paths": 0,
            "search_truncated": False,
            "limits": {
                "max_depth": max_depth,
                "k_paths": k_paths,
                "max_expansions": max_expansions,
            },
            "targets_evaluated": [],
            "paths": [],
            "global_assumptions": list(GLOBAL_ASSUMPTIONS),
            "input_sha256": sha256_canonical(
                {"snapshot_sha256": snap.sha256, "target_mode": target_mode}
            ),
            "result_sha256": sha256_canonical({"paths": []}),
        }

    spec = ScenarioSpec(
        name=f"Attack Path Sweep ({target_mode})",
        start_kind=start_kind,
        start_key=resolved_start_key,
        start_level=start_level,
        targets=tuple(
            TargetSpec(
                asset_key=a["key"],
                level="identity" if a.get("type") == "identity" else goal_level,
            )
            for a in selected_assets
        ),
        max_depth=max_depth,
        k_paths=k_paths,
        max_expansions=max_expansions,
    )

    model = SqlGraphRepository(db).load_snapshot(snapshot_id)
    sim = run_scenario(model, spec, snapshot_id=snap.id, snapshot_sha256=snap.sha256)
    baseline = sim["baseline"]

    targets_evaluated = []
    for res in baseline["results_by_target"]:
        a = asset_by_key[res["target_key"]]
        t_paths = res["paths"]
        targets_evaluated.append(
            {
                "asset_key": a["key"],
                "asset_name": a["name"],
                "asset_type": a["type"],
                "zone_key": a.get("zone_key"),
                "criticality": int(a.get("criticality", 1)),
                "crown_jewel": (
                    int(a.get("criticality", 1)) >= 5 or "crown_jewel" in (a.get("tags") or [])
                ),
                "goal_capability": res["goal_capability"],
                "path_count": len(t_paths),
                "max_score": max((p["modeled_score"] for p in t_paths), default=0),
                "search_truncated": res["search_truncated"],
                "expansions_used": res["expansions_used"],
            }
        )

    return {
        "result_kind": "modeled_attack_paths",
        "disclaimer": sim["disclaimer"],
        "engine_version": sim["engine_version"],
        "ruleset_version": sim["ruleset_version"],
        "snapshot_id": snap.id,
        "snapshot_sha256": snap.sha256,
        "start_kind": start_kind,
        "start_key": resolved_start_key,
        "start_level": start_level,
        "target_mode": target_mode,
        "goal_level": goal_level,
        "headline_score": baseline["headline_score"],
        "total_paths": baseline["total_paths"],
        "search_truncated": baseline["search_truncated"],
        "limits": baseline["limits"],
        "targets_evaluated": targets_evaluated,
        "paths": baseline["paths"],
        "global_assumptions": sim["global_assumptions"],
        "input_sha256": sim["input_sha256"],
        "result_sha256": sim["result_sha256"],
    }
