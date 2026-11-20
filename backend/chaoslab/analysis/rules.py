"""Rule catalogue (2026.11-r1) generating deterministic candidate steps."""

from __future__ import annotations

from chaoslab.analysis.canonical import round_float
from chaoslab.analysis.models import (
    ACTIVE_FINDING_STATUSES,
    DEFAULT_EXPLOITABILITY,
    AppliedControl,
    ControlModel,
    EnvironmentModel,
    FindingAssetModel,
    FindingModel,
    ModeledStep,
    Prerequisite,
)
from chaoslab.analysis.reachability import find_reachability


def _effective_finding_status(finding: FindingModel, fa: FindingAssetModel) -> str:
    return fa.status_override if fa.status_override is not None else finding.status


def _resolve_exploitability(finding: FindingModel) -> tuple[float, str | None]:
    if finding.exploitability is not None:
        return round_float(finding.exploitability), None
    val = DEFAULT_EXPLOITABILITY.get(finding.severity, 0.0)
    return val, (
        f"Exploitability default ({val:.2f}) used for severity {finding.severity}, not measured."
    )


def _apply_controls(
    controls: tuple[ControlModel, ...],
    rule_id: str,
    target_asset_keys: tuple[str, ...],
    port: int | None,
    base_likelihood: float,
) -> tuple[float, tuple[AppliedControl, ...], tuple[str, ...]]:
    likelihood = base_likelihood
    applied: list[AppliedControl] = []
    ev_keys: set[str] = set()
    target_set = set(target_asset_keys)

    for ctrl in controls:
        if ctrl.status != "active":
            continue
        if ctrl.asset_key not in target_set:
            continue
        if rule_id not in ctrl.affects_rules:
            continue
        if ctrl.ports and port is not None and port not in ctrl.ports:
            continue
        if ctrl.ports and port is None:
            continue
        likelihood *= ctrl.factor
        applied.append(
            AppliedControl(key=ctrl.key, name=ctrl.name, factor=round_float(ctrl.factor))
        )
        ev_keys.update(ctrl.evidence_keys)

    return round_float(likelihood), tuple(applied), tuple(sorted(ev_keys))


def _held_positions(model: EnvironmentModel, state: frozenset[str]) -> list[tuple[str, str]]:
    positions: list[tuple[str, str]] = []
    seen_assets: set[str] = set()
    for cap in sorted(state):
        if cap.startswith("start:zone:"):
            positions.append(("zone", cap.removeprefix("start:zone:")))
        elif cap.startswith("foothold:"):
            parts = cap.split(":", 2)
            if len(parts) == 3:
                asset_key = parts[1]
                if asset_key not in seen_assets and asset_key in model.assets_by_key:
                    seen_assets.add(asset_key)
                    positions.append(("asset", asset_key))
    return positions


def _position_label(pos: tuple[str, str]) -> str:
    return f"{pos[0]}:{pos[1]}"


def _position_cap(pos: tuple[str, str]) -> str:
    return f"start:zone:{pos[1]}" if pos[0] == "zone" else f"foothold:{pos[1]}:user"


def _is_untrusted_start_zone(model: EnvironmentModel, pos: tuple[str, str]) -> bool:
    if pos[0] != "zone":
        return False
    zone = model.zones_by_key.get(pos[1])
    return zone is not None and zone.trust_level == "untrusted"


def _effective_access_cap(asset_key: str, level: str) -> str:
    norm = "admin" if level == "admin" else "user"
    return f"foothold:{asset_key}:{norm}"


def generate_candidate_steps(
    model: EnvironmentModel,
    state: frozenset[str],
) -> list[ModeledStep]:
    """Generate all valid, unblocked ModeledSteps from the current capability state."""
    steps: list[ModeledStep] = []
    positions = _held_positions(model, state)

    # 1. R-EXP-REMOTE: network-reachable weakness from any held position (excluding self)
    for finding in model.findings:
        if finding.category != "remote_exploitable" or finding.requires_auth:
            continue
        base_l, expl_assumption = _resolve_exploitability(finding)
        if base_l <= 0.0:
            continue
        gains_level = "admin" if finding.grants == "admin" else "user"

        for fa in finding.affected_assets:
            if _effective_finding_status(finding, fa) not in ACTIVE_FINDING_STATUSES:
                continue
            target = model.assets_by_key.get(fa.asset_key)
            if target is None or target.type == "identity":
                continue
            gains = _effective_access_cap(target.key, gains_level)
            if gains in state:
                continue

            for pos in positions:
                if pos == ("asset", target.key):
                    continue
                reach = find_reachability(model, pos, target.key, fa.port)
                if reach is None:
                    continue
                likelihood, ctrls, ctrl_ev = _apply_controls(
                    model.controls, "R-EXP-REMOTE", (target.key,), fa.port, base_l
                )
                if likelihood <= 0.0:
                    continue

                req_cap = _position_cap(pos)
                conf = round_float(min(finding.provenance.confidence, reach.confidence))
                ref_label = "T1190" if _is_untrusted_start_zone(model, pos) else "T1210"
                assumptions: list[str] = []
                if expl_assumption:
                    assumptions.append(expl_assumption)
                if reach.assumption:
                    assumptions.append(reach.assumption)

                ev_all = tuple(
                    sorted(set(finding.evidence_keys) | set(reach.evidence_keys) | set(ctrl_ev))
                )
                port_tag = str(fa.port) if fa.port is not None else "any"
                pos_lbl = _position_label(pos)
                steps.append(
                    ModeledStep(
                        step_key=f"R-EXP-REMOTE|{pos_lbl}>{target.key}|{finding.key}:{port_tag}",
                        rule_id="R-EXP-REMOTE",
                        rule_name="Exploit network-reachable weakness",
                        rule_description=(
                            "Exploit a remote unauthenticated weakness over a reachable "
                            "network port."
                        ),
                        from_position=pos_lbl,
                        target_key=target.key,
                        gains=gains,
                        required_capabilities=(req_cap,),
                        prerequisites=(
                            Prerequisite("capability", req_cap, f"Attacker holds {req_cap}", 1.0),
                            Prerequisite(
                                "finding",
                                finding.key,
                                (
                                    f"{finding.key}: {finding.title} "
                                    f"({finding.severity}, port {port_tag})"
                                ),
                                round_float(finding.provenance.confidence),
                            ),
                            Prerequisite(
                                reach.fact_kind,
                                reach.fact_key,
                                reach.detail,
                                round_float(reach.confidence),
                            ),
                        ),
                        evidence_keys=ev_all,
                        controls_applied=ctrls,
                        base_likelihood=base_l,
                        likelihood=likelihood,
                        confidence=conf,
                        reference_labels=(ref_label,),
                        assumptions=tuple(assumptions),
                    )
                )

    # 2. R-EXP-LOCAL: escalate user -> admin on a foothold
    for finding in model.findings:
        if finding.category != "local_privesc":
            continue
        base_l, expl_assumption = _resolve_exploitability(finding)
        if base_l <= 0.0:
            continue
        for fa in finding.affected_assets:
            if _effective_finding_status(finding, fa) not in ACTIVE_FINDING_STATUSES:
                continue
            target = model.assets_by_key.get(fa.asset_key)
            if target is None or target.type == "identity":
                continue
            req_cap = f"foothold:{target.key}:user"
            gains = f"foothold:{target.key}:admin"
            if req_cap not in state or gains in state:
                continue
            likelihood, ctrls, ctrl_ev = _apply_controls(
                model.controls, "R-EXP-LOCAL", (target.key,), None, base_l
            )
            if likelihood <= 0.0:
                continue
            conf = round_float(finding.provenance.confidence)
            ev_all = tuple(sorted(set(finding.evidence_keys) | set(ctrl_ev)))
            assumptions = (expl_assumption,) if expl_assumption else ()
            steps.append(
                ModeledStep(
                    step_key=f"R-EXP-LOCAL|{target.key}|{finding.key}",
                    rule_id="R-EXP-LOCAL",
                    rule_name="Escalate privilege via local weakness",
                    rule_description="Escalate user foothold to admin privilege on the same asset.",
                    from_position=f"asset:{target.key}",
                    target_key=target.key,
                    gains=gains,
                    required_capabilities=(req_cap,),
                    prerequisites=(
                        Prerequisite("capability", req_cap, f"Attacker holds {req_cap}", 1.0),
                        Prerequisite(
                            "finding",
                            finding.key,
                            f"{finding.key}: {finding.title} ({finding.severity})",
                            conf,
                        ),
                    ),
                    evidence_keys=ev_all,
                    controls_applied=ctrls,
                    base_likelihood=base_l,
                    likelihood=likelihood,
                    confidence=conf,
                    reference_labels=("T1068",),
                    assumptions=assumptions,
                )
            )

    # 3. R-CRED-USE & 4. R-CRED-HARVEST
    for rel in model.relationships:
        if rel.type != "has_credential_for":
            continue
        src = model.assets_by_key.get(rel.source_asset_key)
        tgt = model.assets_by_key.get(rel.target_asset_key)
        if src is None or tgt is None:
            continue

        if tgt.type == "identity":
            # R-CRED-HARVEST
            req_level = str(rel.attributes.get("required_level", "admin"))
            req_cap = _effective_access_cap(src.key, req_level)
            gains = f"identity:{tgt.key}"
            if req_cap not in state or gains in state:
                continue
            base_l = 0.8
            likelihood, ctrls, ctrl_ev = _apply_controls(
                model.controls, "R-CRED-HARVEST", (src.key,), None, base_l
            )
            if likelihood <= 0.0:
                continue
            conf = round_float(rel.provenance.confidence)
            material = str(rel.attributes.get("material", "memory"))
            ref_label = "T1552" if material == "file" else "T1003"
            ev_all = tuple(sorted(set(rel.evidence_keys) | set(ctrl_ev)))
            steps.append(
                ModeledStep(
                    step_key=f"R-CRED-HARVEST|{src.key}>{tgt.key}|{rel.key}",
                    rule_id="R-CRED-HARVEST",
                    rule_name="Harvest identity credential from foothold",
                    rule_description="Obtain credentials for a non-host identity from a foothold.",
                    from_position=f"asset:{src.key}",
                    target_key=tgt.key,
                    gains=gains,
                    required_capabilities=(req_cap,),
                    prerequisites=(
                        Prerequisite("capability", req_cap, f"Attacker holds {req_cap}", 1.0),
                        Prerequisite(
                            "relationship",
                            rel.key,
                            f"{rel.key}: {src.key} has_credential_for {tgt.key} ({material})",
                            conf,
                        ),
                    ),
                    evidence_keys=ev_all,
                    controls_applied=ctrls,
                    base_likelihood=base_l,
                    likelihood=likelihood,
                    confidence=conf,
                    reference_labels=(ref_label,),
                    assumptions=(
                        "Credential presence is modeled without storing or testing secret values.",
                    ),
                )
            )
        else:
            # R-CRED-USE
            req_level = str(rel.attributes.get("required_level", "user"))
            access_level = str(rel.attributes.get("access_level", "user"))
            port_raw = rel.attributes.get("port")
            port = None if port_raw is None else int(port_raw)
            req_cap = _effective_access_cap(src.key, req_level)
            gains = _effective_access_cap(tgt.key, access_level)
            if req_cap not in state or gains in state:
                continue

            reach = find_reachability(model, ("asset", src.key), tgt.key, port)
            if reach is None:
                continue

            base_l = 0.9
            likelihood, ctrls, ctrl_ev = _apply_controls(
                model.controls, "R-CRED-USE", (tgt.key,), port, base_l
            )
            if likelihood <= 0.0:
                continue
            conf = round_float(min(rel.provenance.confidence, reach.confidence))
            assumptions = [
                "Credential presence is modeled without storing or testing secret values."
            ]
            if reach.assumption:
                assumptions.append(reach.assumption)
            ev_all = tuple(sorted(set(rel.evidence_keys) | set(reach.evidence_keys) | set(ctrl_ev)))
            steps.append(
                ModeledStep(
                    step_key=f"R-CRED-USE|{src.key}>{tgt.key}|{rel.key}",
                    rule_id="R-CRED-USE",
                    rule_name="Use credential material found on foothold",
                    rule_description=(
                        "Authenticate to a reachable asset using stored credential material."
                    ),
                    from_position=f"asset:{src.key}",
                    target_key=tgt.key,
                    gains=gains,
                    required_capabilities=(req_cap,),
                    prerequisites=(
                        Prerequisite("capability", req_cap, f"Attacker holds {req_cap}", 1.0),
                        Prerequisite(
                            "relationship",
                            rel.key,
                            f"{rel.key}: {src.key} has_credential_for {tgt.key}",
                            round_float(rel.provenance.confidence),
                        ),
                        Prerequisite(
                            reach.fact_kind,
                            reach.fact_key,
                            reach.detail,
                            round_float(reach.confidence),
                        ),
                    ),
                    evidence_keys=ev_all,
                    controls_applied=ctrls,
                    base_likelihood=base_l,
                    likelihood=likelihood,
                    confidence=conf,
                    reference_labels=("T1552.001", "T1078"),
                    assumptions=tuple(assumptions),
                )
            )

    # 5. R-IDENTITY-ACCESS: authenticate as captured identity
    for rel in model.relationships:
        if rel.type not in ("admin_of", "can_access"):
            continue
        identity = model.assets_by_key.get(rel.source_asset_key)
        tgt = model.assets_by_key.get(rel.target_asset_key)
        if identity is None or tgt is None or tgt.type == "identity":
            continue
        id_cap = f"identity:{identity.key}"
        if id_cap not in state:
            continue
        access_level = "admin" if rel.type == "admin_of" else "user"
        gains = _effective_access_cap(tgt.key, access_level)
        if gains in state:
            continue
        port_raw = rel.attributes.get("port")
        port = None if port_raw is None else int(port_raw)

        for pos in positions:
            reach = find_reachability(model, pos, tgt.key, port)
            if reach is None:
                continue
            base_l = 0.9
            likelihood, ctrls, ctrl_ev = _apply_controls(
                model.controls, "R-IDENTITY-ACCESS", (identity.key, tgt.key), port, base_l
            )
            if likelihood <= 0.0:
                continue
            pos_cap = _position_cap(pos)
            pos_lbl = _position_label(pos)
            conf = round_float(min(rel.provenance.confidence, reach.confidence))
            assumptions: list[str] = []
            if reach.assumption:
                assumptions.append(reach.assumption)
            ev_all = tuple(sorted(set(rel.evidence_keys) | set(reach.evidence_keys) | set(ctrl_ev)))
            steps.append(
                ModeledStep(
                    step_key=f"R-IDENTITY-ACCESS|{pos_lbl}+{identity.key}>{tgt.key}|{rel.key}",
                    rule_id="R-IDENTITY-ACCESS",
                    rule_name="Authenticate as captured identity",
                    rule_description=(
                        "Use a captured identity credential to access a reachable asset."
                    ),
                    from_position=pos_lbl,
                    target_key=tgt.key,
                    gains=gains,
                    required_capabilities=tuple(sorted({id_cap, pos_cap})),
                    prerequisites=(
                        Prerequisite("capability", id_cap, f"Attacker holds {id_cap}", 1.0),
                        Prerequisite(
                            "capability", pos_cap, f"Attacker reaches from {pos_lbl}", 1.0
                        ),
                        Prerequisite(
                            "relationship",
                            rel.key,
                            f"{rel.key}: {identity.key} {rel.type} {tgt.key}",
                            round_float(rel.provenance.confidence),
                        ),
                        Prerequisite(
                            reach.fact_kind,
                            reach.fact_key,
                            reach.detail,
                            round_float(reach.confidence),
                        ),
                    ),
                    evidence_keys=ev_all,
                    controls_applied=ctrls,
                    base_likelihood=base_l,
                    likelihood=likelihood,
                    confidence=conf,
                    reference_labels=("T1078",),
                    assumptions=tuple(assumptions),
                )
            )

    steps.sort(key=lambda s: s.step_key)
    return steps
