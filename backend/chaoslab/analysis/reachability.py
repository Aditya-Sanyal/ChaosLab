"""Deterministic reachability evaluation over snapshot rules and zone policies."""

from __future__ import annotations

from dataclasses import dataclass

from chaoslab.analysis.models import EnvironmentModel


@dataclass(frozen=True)
class ReachabilityMatch:
    fact_key: str
    fact_kind: str  # self | reachability | zone_policy
    is_inferred: bool
    confidence: float
    evidence_keys: tuple[str, ...]
    detail: str
    assumption: str | None = None


def _position_zone(model: EnvironmentModel, position: tuple[str, str]) -> str | None:
    kind, key = position
    if kind == "zone":
        return key
    asset = model.assets_by_key.get(key)
    return asset.zone_key if asset is not None else None


def find_reachability(
    model: EnvironmentModel,
    position: tuple[str, str],
    target_asset_key: str,
    port: int | None,
) -> ReachabilityMatch | None:
    """Return the most specific deterministic reachability match, or None if unreachable."""
    target = model.assets_by_key.get(target_asset_key)
    if target is None or target.type == "identity":
        return None

    pos_kind, pos_key = position
    if pos_kind == "asset" and pos_key == target_asset_key:
        return ReachabilityMatch(
            fact_key=f"SELF:{target_asset_key}",
            fact_kind="self",
            is_inferred=False,
            confidence=1.0,
            evidence_keys=(),
            detail=f"Position on {target_asset_key} reaches itself locally",
            assumption=None,
        )

    pos_zone = _position_zone(model, position)
    tgt_zone = target.zone_key

    # Candidates as (specificity_rank, -confidence, fact_key, ReachabilityMatch)
    candidates: list[tuple[int, float, str, ReachabilityMatch]] = []

    for rule in model.reachability:
        if rule.source_kind == "asset":
            if not (pos_kind == "asset" and rule.source_key == pos_key):
                continue
        elif rule.source_kind == "zone":
            if pos_zone is None or rule.source_key != pos_zone:
                continue
        else:
            continue

        if rule.target_kind == "asset":
            if rule.target_key != target.key:
                continue
        elif rule.target_kind == "zone":
            if tgt_zone is None or rule.target_key != tgt_zone:
                continue
        else:
            continue

        if rule.ports and port is not None and port not in rule.ports:
            continue

        if rule.source_kind == "asset" and rule.target_kind == "asset":
            rank = 0
        elif rule.source_kind == "zone" and rule.target_kind == "zone":
            rank = 2
        else:
            rank = 1

        is_inferred = (
            rule.target_kind == "zone"
            or (pos_kind == "asset" and rule.source_kind == "zone")
        )
        port_desc = "*" if not rule.ports else ",".join(str(p) for p in rule.ports)
        assumption = (
            f"Reachability inferred from zone-wide rule {rule.key} "
            f"({rule.source_kind}:{rule.source_key} -> {rule.target_kind}:{rule.target_key} "
            f"ports {port_desc})."
            if is_inferred
            else None
        )
        match = ReachabilityMatch(
            fact_key=rule.key,
            fact_kind="reachability",
            is_inferred=is_inferred,
            confidence=rule.provenance.confidence,
            evidence_keys=rule.evidence_keys,
            detail=(
                f"{rule.key}: {rule.source_kind}:{rule.source_key} -> "
                f"{rule.target_kind}:{rule.target_key} ({rule.protocol}/{port_desc})"
            ),
            assumption=assumption,
        )
        candidates.append((rank, -rule.provenance.confidence, rule.key, match))

    if pos_zone is not None and tgt_zone is not None and pos_zone == tgt_zone:
        zone = model.zones_by_key.get(pos_zone)
        if zone is not None and zone.intra_zone_policy == "allow":
            fact_key = f"ZONE-INTRA:{zone.key}"
            match = ReachabilityMatch(
                fact_key=fact_key,
                fact_kind="zone_policy",
                is_inferred=True,
                confidence=zone.provenance.confidence,
                evidence_keys=(),
                detail=f"Intra-zone policy allow within {zone.key}",
                assumption=f"Same-zone reachability assumed per {zone.key} intra-zone policy.",
            )
            candidates.append((3, -zone.provenance.confidence, fact_key, match))

    if not candidates:
        return None

    candidates.sort(key=lambda c: (c[0], c[1], c[2]))
    return candidates[0][3]
