"""Scenarios and offline simulation execution endpoints."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from chaoslab.analysis import RESULT_DISCLAIMER
from chaoslab.api.schemas import (
    AttackPathSweepResponse,
    RunComparisonResponse,
    ScenarioCreateRequest,
    ScenarioRunCreateRequest,
    ScenarioRunResponse,
    ScenarioSummary,
)
from chaoslab.auth.dependencies import require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.db.base import to_utc_iso
from chaoslab.db.session import get_db
from chaoslab.inventory.service import get_environment
from chaoslab.scenarios import service as scn_svc
from chaoslab.scenarios.models import Scenario, ScenarioRun

router = APIRouter(tags=["scenarios"])


def _scenario_out(s: Scenario) -> ScenarioSummary:
    return ScenarioSummary(
        id=s.id,
        environment_id=s.environment_id,
        name=s.name,
        description=s.description,
        start_kind=s.start_kind,
        start_key=s.start_key,
        start_level=s.start_level,
        targets=list(s.targets or []),
        parameters=dict(s.parameters or {}),
        created_by=s.created_by,
        created_at=to_utc_iso(s.created_at),
    )


def _run_out(run: ScenarioRun) -> ScenarioRunResponse:
    return ScenarioRunResponse(
        id=run.id,
        environment_id=run.environment_id,
        scenario_id=run.scenario_id,
        snapshot_id=run.snapshot_id,
        result_kind="scenario_result",
        disclaimer=run.result.get("disclaimer", RESULT_DISCLAIMER),
        actions=list(run.actions or []),
        engine_version=run.engine_version,
        ruleset_version=run.ruleset_version,
        input_sha256=run.input_sha256,
        result_sha256=run.result_sha256,
        result=run.result,
        status=run.status,
        duration_ms=run.duration_ms,
        created_by=run.created_by,
        created_at=to_utc_iso(run.created_at),
    )


@router.get("/environments/{env_id}/scenarios", response_model=list[ScenarioSummary])
def list_scenarios(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
) -> list[ScenarioSummary]:
    if get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    return [_scenario_out(s) for s in scn_svc.list_scenarios(db, env_id)]


@router.post(
    "/environments/{env_id}/scenarios",
    response_model=ScenarioSummary,
    status_code=status.HTTP_201_CREATED,
)
def create_scenario_endpoint(
    env_id: str,
    payload: ScenarioCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.SCENARIOS_RUN))],
) -> ScenarioSummary:
    try:
        sc = scn_svc.create_scenario(
            db,
            env_id=env_id,
            name=payload.name,
            description=payload.description,
            start_kind=payload.start_kind,
            start_key=payload.start_key,
            start_level=payload.start_level,
            targets=[t.model_dump() for t in payload.targets],
            max_depth=payload.max_depth,
            k_paths=payload.k_paths,
            max_expansions=payload.max_expansions,
            created_by=user.email,
            actor_user_id=user.id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return _scenario_out(sc)


@router.delete(
    "/environments/{env_id}/scenarios/{scenario_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scenario_endpoint(
    env_id: str,
    scenario_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.SCENARIOS_RUN))],
) -> Response:
    try:
        scn_svc.delete_scenario(
            db,
            env_id=env_id,
            scenario_id=scenario_id,
            actor_email=user.email,
            actor_user_id=user.id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/snapshots/{snapshot_id}/runs",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def run_scenario_endpoint(
    snapshot_id: str,
    payload: ScenarioRunCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.SCENARIOS_RUN))],
) -> ScenarioRunResponse:
    if (payload.scenario_id is None) == (payload.inline_scenario is None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Provide exactly one of scenario_id or inline_scenario.",
        )
    try:
        run = scn_svc.execute_scenario_run(
            db,
            snapshot_id=snapshot_id,
            created_by=user.email,
            actor_user_id=user.id,
            scenario_id=payload.scenario_id,
            inline_scenario=(
                payload.inline_scenario.model_dump() if payload.inline_scenario else None
            ),
            actions=[a.model_dump() for a in payload.actions],
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return _run_out(run)


@router.get("/environments/{env_id}/runs", response_model=list[ScenarioRunResponse])
def list_runs(
    env_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
    snapshot_id: str | None = Query(default=None, max_length=36),
    scenario_id: str | None = Query(default=None, max_length=36),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ScenarioRunResponse]:
    if get_environment(db, env_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found.")
    return [
        _run_out(r)
        for r in scn_svc.list_runs(
            db, env_id, snapshot_id=snapshot_id, scenario_id=scenario_id, limit=limit
        )
    ]


@router.get("/runs/compare", response_model=RunComparisonResponse)
def compare_runs_endpoint(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
    run_a_id: str = Query(min_length=1, max_length=36),
    run_b_id: str = Query(min_length=1, max_length=36),
) -> RunComparisonResponse:
    try:
        res = scn_svc.compare_scenario_runs(db, run_a_id=run_a_id, run_b_id=run_b_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return RunComparisonResponse(**res)


@router.get("/runs/{run_id}", response_model=ScenarioRunResponse)
def get_run(
    run_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
) -> ScenarioRunResponse:
    run = scn_svc.get_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    return _run_out(run)


@router.get("/snapshots/{snapshot_id}/attack-paths", response_model=AttackPathSweepResponse)
def get_snapshot_attack_paths(
    snapshot_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.SCENARIOS_READ))],
    start_kind: Literal["zone", "asset"] = Query(default="zone"),
    start_key: str | None = Query(default=None, max_length=128),
    start_level: Literal["user", "admin"] = Query(default="user"),
    target_mode: Literal["crown_jewels", "high_criticality", "all_assets"] = Query(
        default="crown_jewels"
    ),
    goal_level: Literal["user", "admin"] = Query(default="user"),
    k_paths: int = Query(default=5, ge=1, le=10),
    max_depth: int = Query(default=6, ge=1, le=10),
    max_expansions: int = Query(default=20000, ge=10, le=50000),
) -> AttackPathSweepResponse:
    try:
        res = scn_svc.analyze_snapshot_attack_paths(
            db,
            snapshot_id=snapshot_id,
            start_kind=start_kind,
            start_key=start_key,
            start_level=start_level,
            target_mode=target_mode,
            goal_level=goal_level,
            k_paths=k_paths,
            max_depth=max_depth,
            max_expansions=max_expansions,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return AttackPathSweepResponse(**res)
