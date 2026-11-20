"""Deterministic uniform-cost path search and heuristic path scoring."""

from __future__ import annotations

import heapq
import math
from collections import Counter

from chaoslab.analysis.canonical import round_float
from chaoslab.analysis.models import (
    AnalysisOutput,
    EnvironmentModel,
    ModeledPath,
    ModeledStep,
    ScenarioSpec,
    TargetAnalysisResult,
    TargetSpec,
)
from chaoslab.analysis.rules import generate_candidate_steps


def _grant_to_state(state: frozenset[str], gains: str) -> frozenset[str]:
    if gains.startswith("foothold:") and gains.endswith(":admin"):
        asset_key = gains.split(":", 2)[1]
        return state | frozenset({gains, f"foothold:{asset_key}:user"})
    return state | frozenset({gains})


def _initial_state(model: EnvironmentModel, spec: ScenarioSpec) -> frozenset[str]:
    if spec.start_kind == "zone":
        if spec.start_key not in model.zones_by_key:
            return frozenset()
        return frozenset({f"start:zone:{spec.start_key}"})
    if spec.start_kind == "asset":
        asset = model.assets_by_key.get(spec.start_key)
        if asset is None:
            return frozenset()
        if asset.type == "identity":
            return frozenset({f"start:asset:{asset.key}", f"identity:{asset.key}"})
        lvl = "admin" if spec.start_level == "admin" else "user"
        caps = {f"start:asset:{asset.key}", f"foothold:{asset.key}:{lvl}"}
        if lvl == "admin":
            caps.add(f"foothold:{asset.key}:user")
        return frozenset(caps)
    return frozenset()


def _goal_capability(model: EnvironmentModel, target: TargetSpec) -> str:
    asset = model.assets_by_key.get(target.asset_key)
    if asset is not None and asset.type == "identity":
        return f"identity:{target.asset_key}"
    lvl = "admin" if target.level == "admin" else "user"
    return f"foothold:{target.asset_key}:{lvl}"


def _step_satisfies(gains: str, cap: str) -> bool:
    if gains == cap:
        return True
    if gains.startswith("foothold:") and gains.endswith(":admin"):
        asset_key = gains.split(":", 2)[1]
        return cap == f"foothold:{asset_key}:user"
    return False


def _minimize_steps(
    steps: tuple[ModeledStep, ...],
    goal_cap: str,
    initial_state: frozenset[str],
) -> tuple[ModeledStep, ...]:
    """Keep only minimal causal steps: for each needed cap, pick the earliest step granting it."""
    if any(_step_satisfies(c, goal_cap) for c in initial_state):
        return ()
    kept_indices: set[int] = set()
    queue: list[tuple[str, int]] = [(goal_cap, len(steps))]
    processed: set[tuple[str, int]] = set()

    while queue:
        cap, limit_idx = queue.pop()
        if any(_step_satisfies(c, cap) for c in initial_state):
            continue
        provider_idx = None
        for idx in range(limit_idx):
            if _step_satisfies(steps[idx].gains, cap):
                provider_idx = idx
                break
        if provider_idx is None:
            continue
        if provider_idx not in kept_indices:
            kept_indices.add(provider_idx)
            for req in steps[provider_idx].required_capabilities:
                key = (req, provider_idx)
                if key not in processed:
                    processed.add(key)
                    queue.append(key)

    return tuple(steps[i] for i in sorted(kept_indices))


def _score_path(
    model: EnvironmentModel,
    target_key: str,
    goal_cap: str,
    steps: tuple[ModeledStep, ...],
) -> ModeledPath:
    likelihood = 1.0
    weighted = 1.0
    min_conf = 1.0
    for step in steps:
        likelihood *= step.likelihood
        weighted *= step.likelihood * step.confidence
        if step.confidence < min_conf:
            min_conf = step.confidence

    target_asset = model.assets_by_key.get(target_key)
    criticality = target_asset.criticality if target_asset is not None else 1
    impact = round_float(criticality / 5.0)
    modeled_score = round(100.0 * weighted * impact)
    path_key = " -> ".join(s.step_key for s in steps)

    return ModeledPath(
        path_key=path_key,
        target_key=target_key,
        goal_capability=goal_cap,
        modeled_score=modeled_score,
        path_likelihood=round_float(likelihood),
        path_confidence=round_float(min_conf),
        weighted_likelihood=round_float(weighted),
        impact=impact,
        low_confidence=min_conf < 0.5,
        steps=steps,
    )


def _search_single_target(
    model: EnvironmentModel,
    initial_state: frozenset[str],
    target: TargetSpec,
    max_depth: int,
    k_paths: int,
    max_expansions: int,
) -> TargetAnalysisResult:
    goal_cap = _goal_capability(model, target)
    if goal_cap in initial_state:
        return TargetAnalysisResult(
            target_key=target.asset_key,
            goal_capability=goal_cap,
            paths=(),
            search_truncated=False,
            expansions_used=0,
        )

    # Heap items: (cost, depth, step_keys_tuple, state, steps_tuple)
    heap: list[tuple[float, int, tuple[str, ...], frozenset[str], tuple[ModeledStep, ...]]] = [
        (0.0, 0, (), initial_state, ())
    ]
    expansions_by_state: Counter[frozenset[str]] = Counter()
    total_expansions = 0
    seen_minimized: set[tuple[str, ...]] = set()
    found_paths: list[ModeledPath] = []
    truncated = False

    while heap:
        if len(found_paths) >= k_paths:
            break
        if total_expansions >= max_expansions:
            truncated = True
            break

        cost, depth, step_keys, state, steps = heapq.heappop(heap)

        if goal_cap in state:
            min_steps = _minimize_steps(steps, goal_cap, initial_state)
            min_keys = tuple(s.step_key for s in min_steps)
            if min_steps and min_keys not in seen_minimized:
                seen_minimized.add(min_keys)
                found_paths.append(_score_path(model, target.asset_key, goal_cap, min_steps))
            continue

        if depth >= max_depth:
            continue

        if expansions_by_state[state] >= k_paths:
            continue
        expansions_by_state[state] += 1
        total_expansions += 1

        for step in generate_candidate_steps(model, state):
            weight = max(step.likelihood * step.confidence, 1e-12)
            step_cost = -math.log(weight)
            next_state = _grant_to_state(state, step.gains)
            if next_state == state:
                continue
            next_steps = steps + (step,)
            next_keys = step_keys + (step.step_key,)
            heapq.heappush(heap, (cost + step_cost, depth + 1, next_keys, next_state, next_steps))

    found_paths.sort(
        key=lambda p: (
            -p.modeled_score,
            -p.weighted_likelihood,
            len(p.steps),
            tuple(s.step_key for s in p.steps),
        )
    )
    return TargetAnalysisResult(
        target_key=target.asset_key,
        goal_capability=goal_cap,
        paths=tuple(found_paths[:k_paths]),
        search_truncated=truncated,
        expansions_used=total_expansions,
    )


def analyze_scenario(model: EnvironmentModel, spec: ScenarioSpec) -> AnalysisOutput:
    """Run deterministic k-best path search across all specified targets."""
    initial = _initial_state(model, spec)
    results: list[TargetAnalysisResult] = []
    all_paths: list[ModeledPath] = []
    any_truncated = False

    for target in spec.targets:
        res = _search_single_target(
            model=model,
            initial_state=initial,
            target=target,
            max_depth=spec.max_depth,
            k_paths=spec.k_paths,
            max_expansions=spec.max_expansions,
        )
        results.append(res)
        all_paths.extend(res.paths)
        if res.search_truncated:
            any_truncated = True

    all_paths.sort(
        key=lambda p: (
            -p.modeled_score,
            -p.weighted_likelihood,
            len(p.steps),
            p.target_key,
            tuple(s.step_key for s in p.steps),
        )
    )
    headline = max((p.modeled_score for p in all_paths), default=0)
    return AnalysisOutput(
        headline_score=headline,
        total_paths=len(all_paths),
        search_truncated=any_truncated,
        results_by_target=tuple(results),
        paths=tuple(all_paths),
        limits={
            "max_depth": spec.max_depth,
            "k_paths": spec.k_paths,
            "max_expansions": spec.max_expansions,
        },
    )
