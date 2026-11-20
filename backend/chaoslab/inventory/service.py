"""Query services for environments, assets, topology graph, and findings."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from chaoslab.audit.service import record_event
from chaoslab.db.base import to_utc_iso, utcnow
from chaoslab.inventory.models import (
    Asset,
    Control,
    Environment,
    Evidence,
    EvidenceLink,
    Finding,
    FindingAsset,
    ImportBatch,
    ReachabilityRule,
    Relationship,
    Service,
    Zone,
)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_ACTIVE_STATUSES = {"open", "in_progress", "accepted_risk"}
_VALID_FINDING_STATUSES = frozenset(
    {"open", "in_progress", "accepted_risk", "remediated", "false_positive"}
)


def _provenance_dict(row: Any) -> dict[str, Any]:
    return {
        "origin": row.origin,
        "source": row.source,
        "observed_at": to_utc_iso(row.observed_at),
        "confidence": row.confidence,
        "import_batch_id": row.import_batch_id,
        "created_at": to_utc_iso(row.created_at),
        "updated_at": to_utc_iso(row.updated_at),
        "updated_by": row.updated_by,
    }


def _exposed_asset_keys(
    zones: list[Zone], assets: list[Asset], rules: list[ReachabilityRule]
) -> set[str]:
    untrusted_zones = {z.key for z in zones if z.trust_level == "untrusted"}
    zone_id_to_key = {z.id: z.key for z in zones}
    exposed: set[str] = set()
    for rule in rules:
        if rule.source_kind == "zone" and rule.source_key in untrusted_zones:
            if rule.target_kind == "asset":
                exposed.add(rule.target_key)
            elif rule.target_kind == "zone":
                for a in assets:
                    if a.zone_id and zone_id_to_key.get(a.zone_id) == rule.target_key:
                        exposed.add(a.key)
    return exposed


def list_environments(db: Session) -> list[Environment]:
    return list(db.execute(select(Environment).order_by(Environment.name.asc())).scalars().all())


def get_environment(db: Session, env_id: str) -> Environment | None:
    return db.get(Environment, env_id)


def create_environment(
    db: Session,
    *,
    name: str,
    description: str,
    actor_email: str,
    actor_user_id: str | None,
) -> Environment:
    clean_name = name.strip()
    existing = db.execute(
        select(Environment).where(Environment.name == clean_name)
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"Environment '{clean_name}' already exists.")
    env = Environment(name=clean_name, description=description.strip(), is_demo=False)
    db.add(env)
    db.flush()
    record_event(
        db,
        action="environment.created",
        subject_type="environment",
        subject_id=env.id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={"name": env.name},
    )
    db.commit()
    return env


def list_assets(
    db: Session,
    env_id: str,
    *,
    search: str | None = None,
    zone_key: str | None = None,
    asset_type: str | None = None,
    min_criticality: int | None = None,
    origin: str | None = None,
    internet_exposed: bool | None = None,
    has_findings: bool | None = None,
) -> list[dict[str, Any]]:
    zones = list(db.execute(select(Zone).where(Zone.environment_id == env_id)).scalars().all())
    zone_by_id = {z.id: z for z in zones}
    assets = list(
        db.execute(
            select(Asset)
            .where(Asset.environment_id == env_id)
            .options(selectinload(Asset.services))
            .order_by(Asset.key.asc())
        )
        .scalars()
        .all()
    )
    rules = list(
        db.execute(select(ReachabilityRule).where(ReachabilityRule.environment_id == env_id))
        .scalars()
        .all()
    )
    findings = list(
        db.execute(
            select(Finding)
            .where(Finding.environment_id == env_id)
            .options(selectinload(Finding.affected_links))
        )
        .scalars()
        .all()
    )

    exposed_keys = _exposed_asset_keys(zones, assets, rules)
    findings_by_asset: dict[str, list[Finding]] = {}
    for f in findings:
        for fa in f.affected_links:
            eff_status = fa.status_override or f.status
            if eff_status in _ACTIVE_STATUSES:
                findings_by_asset.setdefault(fa.asset_id, []).append(f)

    q = search.strip().lower() if search else None
    results: list[dict[str, Any]] = []
    for asset in assets:
        z_key = (
            zone_by_id[asset.zone_id].key
            if asset.zone_id and asset.zone_id in zone_by_id
            else None
        )
        if zone_key and z_key != zone_key:
            continue
        if asset_type and asset.type != asset_type:
            continue
        if min_criticality is not None and asset.criticality < min_criticality:
            continue
        if origin and asset.origin != origin:
            continue
        if q:
            haystack = " ".join(
                [asset.key, asset.name, asset.owner, asset.hostname or "", *asset.ip_addresses]
            ).lower()
            if q not in haystack:
                continue

        active_findings = findings_by_asset.get(asset.id, [])
        is_exposed = asset.key in exposed_keys
        if internet_exposed is not None and is_exposed != internet_exposed:
            continue
        if has_findings is not None and (len(active_findings) > 0) != has_findings:
            continue

        max_sev = None
        if active_findings:
            max_sev = max(active_findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)).severity

        results.append(
            {
                "id": asset.id,
                "key": asset.key,
                "name": asset.name,
                "type": asset.type,
                "zone_key": z_key,
                "criticality": asset.criticality,
                "crown_jewel": asset.criticality >= 5 or "crown_jewel" in (asset.tags or []),
                "owner": asset.owner,
                "hostname": asset.hostname,
                "ip_addresses": list(asset.ip_addresses or []),
                "os": asset.os,
                "tags": list(asset.tags or []),
                "internet_exposed": is_exposed,
                "service_count": len(asset.services),
                "finding_count": len(active_findings),
                "max_severity": max_sev,
                "provenance": _provenance_dict(asset),
            }
        )
    return results


def get_asset_detail(db: Session, env_id: str, asset_key: str) -> dict[str, Any] | None:
    asset = db.execute(
        select(Asset)
        .where(Asset.environment_id == env_id, Asset.key == asset_key)
        .options(selectinload(Asset.services), selectinload(Asset.zone))
    ).scalar_one_or_none()
    if asset is None:
        return None

    zones = list(db.execute(select(Zone).where(Zone.environment_id == env_id)).scalars().all())
    rules = list(
        db.execute(select(ReachabilityRule).where(ReachabilityRule.environment_id == env_id))
        .scalars()
        .all()
    )
    all_assets = list(
        db.execute(select(Asset).where(Asset.environment_id == env_id)).scalars().all()
    )
    asset_key_by_id = {a.id: a.key for a in all_assets}
    exposed_keys = _exposed_asset_keys(zones, all_assets, rules)

    rels = list(
        db.execute(
            select(Relationship).where(
                Relationship.environment_id == env_id,
                (Relationship.source_asset_id == asset.id)
                | (Relationship.target_asset_id == asset.id),
            )
        )
        .scalars()
        .all()
    )
    finding_links = list(
        db.execute(
            select(FindingAsset)
            .where(FindingAsset.asset_id == asset.id)
            .options(selectinload(FindingAsset.finding))
        )
        .scalars()
        .all()
    )
    controls = list(
        db.execute(
            select(Control).where(Control.environment_id == env_id, Control.asset_id == asset.id)
        )
        .scalars()
        .all()
    )

    subject_ids = {asset.id} | {r.id for r in rels} | {fl.finding.id for fl in finding_links}
    ev_links = list(
        db.execute(
            select(EvidenceLink).where(
                EvidenceLink.environment_id == env_id,
                EvidenceLink.subject_id.in_(subject_ids),
            )
        )
        .scalars()
        .all()
    )
    ev_ids = {el.evidence_id for el in ev_links}
    evidence_rows = (
        list(
            db.execute(select(Evidence).where(Evidence.id.in_(ev_ids)).order_by(Evidence.key.asc()))
            .scalars()
            .all()
        )
        if ev_ids
        else []
    )

    return {
        "id": asset.id,
        "key": asset.key,
        "name": asset.name,
        "type": asset.type,
        "zone_key": asset.zone.key if asset.zone else None,
        "zone_name": asset.zone.name if asset.zone else None,
        "criticality": asset.criticality,
        "crown_jewel": asset.criticality >= 5 or "crown_jewel" in (asset.tags or []),
        "owner": asset.owner,
        "hostname": asset.hostname,
        "ip_addresses": list(asset.ip_addresses or []),
        "os": asset.os,
        "tags": list(asset.tags or []),
        "description": asset.description,
        "internet_exposed": asset.key in exposed_keys,
        "provenance": _provenance_dict(asset),
        "services": [
            {
                "key": s.key,
                "port": s.port,
                "protocol": s.protocol,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "provenance": _provenance_dict(s),
            }
            for s in sorted(asset.services, key=lambda x: (x.port, x.key))
        ],
        "relationships": [
            {
                "key": r.key,
                "direction": "outbound" if r.source_asset_id == asset.id else "inbound",
                "source_asset_key": asset_key_by_id.get(r.source_asset_id, ""),
                "target_asset_key": asset_key_by_id.get(r.target_asset_id, ""),
                "type": r.type,
                "attributes": dict(r.attributes or {}),
                "provenance": _provenance_dict(r),
            }
            for r in sorted(rels, key=lambda x: x.key)
        ],
        "findings": [
            {
                "key": fl.finding.key,
                "title": fl.finding.title,
                "category": fl.finding.category,
                "severity": fl.finding.severity,
                "status": fl.status_override or fl.finding.status,
                "port": fl.port,
                "cwe": fl.finding.cwe,
                "cve": fl.finding.cve,
                "remediation_notes": fl.finding.remediation_notes,
                "provenance": _provenance_dict(fl.finding),
            }
            for fl in sorted(finding_links, key=lambda x: x.finding.key)
        ],
        "controls": [
            {
                "key": c.key,
                "name": c.name,
                "type": c.type,
                "affects_rules": list(c.affects_rules or []),
                "ports": list(c.ports or []),
                "factor": c.factor,
                "status": c.status,
                "provenance": _provenance_dict(c),
            }
            for c in sorted(controls, key=lambda x: x.key)
        ],
        "evidence": [
            {
                "key": ev.key,
                "kind": ev.kind,
                "title": ev.title,
                "excerpt": ev.excerpt,
                "sha256": ev.sha256,
                "provenance": _provenance_dict(ev),
            }
            for ev in evidence_rows
        ],
    }


def get_topology_graph(db: Session, env_id: str) -> dict[str, Any] | None:
    env = db.get(Environment, env_id)
    if env is None:
        return None
    zones = list(
        db.execute(select(Zone).where(Zone.environment_id == env_id).order_by(Zone.key.asc()))
        .scalars()
        .all()
    )
    assets = list_assets(db, env_id)
    all_asset_rows = list(
        db.execute(select(Asset).where(Asset.environment_id == env_id)).scalars().all()
    )
    asset_key_by_id = {a.id: a.key for a in all_asset_rows}

    rules = list(
        db.execute(
            select(ReachabilityRule)
            .where(ReachabilityRule.environment_id == env_id)
            .order_by(ReachabilityRule.key.asc())
        )
        .scalars()
        .all()
    )
    rels = list(
        db.execute(
            select(Relationship)
            .where(Relationship.environment_id == env_id)
            .order_by(Relationship.key.asc())
        )
        .scalars()
        .all()
    )

    return {
        "environment": {
            "id": env.id,
            "name": env.name,
            "description": env.description,
            "is_demo": env.is_demo,
        },
        "zones": [
            {
                "key": z.key,
                "name": z.name,
                "trust_level": z.trust_level,
                "intra_zone_policy": z.intra_zone_policy,
                "cidrs": list(z.cidrs or []),
            }
            for z in zones
        ],
        "assets": assets,
        "reachability_edges": [
            {
                "key": r.key,
                "source_kind": r.source_kind,
                "source_key": r.source_key,
                "target_kind": r.target_kind,
                "target_key": r.target_key,
                "ports": list(r.ports or []),
                "protocol": r.protocol,
                "description": r.description,
                "inferred_zone_flow": r.source_kind == "zone" and r.target_kind == "zone",
                "confidence": r.confidence,
            }
            for r in rules
        ],
        "relationship_edges": [
            {
                "key": rel.key,
                "source_asset_key": asset_key_by_id.get(rel.source_asset_id, ""),
                "target_asset_key": asset_key_by_id.get(rel.target_asset_id, ""),
                "type": rel.type,
                "attributes": dict(rel.attributes or {}),
                "confidence": rel.confidence,
            }
            for rel in rels
        ],
    }


def list_findings(
    db: Session,
    env_id: str,
    *,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    assets = list(db.execute(select(Asset).where(Asset.environment_id == env_id)).scalars().all())
    asset_key_by_id = {a.id: a.key for a in assets}
    findings = list(
        db.execute(
            select(Finding)
            .where(Finding.environment_id == env_id)
            .options(selectinload(Finding.affected_links))
            .order_by(Finding.key.asc())
        )
        .scalars()
        .all()
    )
    ev_links = list(
        db.execute(
            select(EvidenceLink).where(
                EvidenceLink.environment_id == env_id,
                EvidenceLink.subject_type == "finding",
            )
        )
        .scalars()
        .all()
    )
    ev_rows = list(
        db.execute(select(Evidence).where(Evidence.environment_id == env_id)).scalars().all()
    )
    ev_key_by_id = {e.id: e.key for e in ev_rows}
    ev_by_finding: dict[str, list[str]] = {}
    for link in ev_links:
        if link.evidence_id in ev_key_by_id:
            ev_by_finding.setdefault(link.subject_id, []).append(ev_key_by_id[link.evidence_id])

    q = search.strip().lower() if search else None
    out: list[dict[str, Any]] = []
    for f in findings:
        if severity and f.severity != severity:
            continue
        if status and f.status != status:
            continue
        if category and f.category != category:
            continue
        if q:
            haystack = " ".join(
                [f.key, f.title, f.description, f.cwe or "", f.cve or ""]
            ).lower()
            if q not in haystack:
                continue
        out.append(
            {
                "id": f.id,
                "key": f.key,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "cwe": f.cwe,
                "cve": f.cve,
                "exploitability": f.exploitability,
                "grants": f.grants,
                "requires_auth": f.requires_auth,
                "description": f.description,
                "remediation_notes": f.remediation_notes,
                "affected_assets": [
                    {
                        "asset_key": asset_key_by_id.get(fa.asset_id, ""),
                        "port": fa.port,
                        "status_override": fa.status_override,
                    }
                    for fa in f.affected_links
                ],
                "evidence_keys": sorted(ev_by_finding.get(f.id, [])),
                "status_history_count": len(f.status_history or []),
                "provenance": _provenance_dict(f),
            }
        )
    return out


def get_finding_detail(db: Session, env_id: str, finding_key: str) -> dict[str, Any] | None:
    finding = db.execute(
        select(Finding)
        .where(Finding.environment_id == env_id, Finding.key == finding_key)
        .options(selectinload(Finding.affected_links))
    ).scalar_one_or_none()
    if finding is None:
        return None

    assets = list(
        db.execute(
            select(Asset)
            .where(Asset.environment_id == env_id)
            .options(selectinload(Asset.zone))
        )
        .scalars()
        .all()
    )
    asset_by_id = {a.id: a for a in assets}

    ev_links = list(
        db.execute(
            select(EvidenceLink).where(
                EvidenceLink.environment_id == env_id,
                EvidenceLink.subject_type == "finding",
                EvidenceLink.subject_id == finding.id,
            )
        )
        .scalars()
        .all()
    )
    ev_ids = {el.evidence_id for el in ev_links}
    evidence_rows = (
        list(
            db.execute(select(Evidence).where(Evidence.id.in_(ev_ids)).order_by(Evidence.key.asc()))
            .scalars()
            .all()
        )
        if ev_ids
        else []
    )

    return {
        "id": finding.id,
        "key": finding.key,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "status": finding.status,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "exploitability": finding.exploitability,
        "grants": finding.grants,
        "requires_auth": finding.requires_auth,
        "description": finding.description,
        "remediation_notes": finding.remediation_notes,
        "status_history": list(finding.status_history or []),
        "affected_assets": [
            {
                "asset_key": asset_by_id[fa.asset_id].key if fa.asset_id in asset_by_id else "",
                "asset_name": asset_by_id[fa.asset_id].name if fa.asset_id in asset_by_id else "",
                "zone_key": (
                    asset_by_id[fa.asset_id].zone.key
                    if fa.asset_id in asset_by_id and asset_by_id[fa.asset_id].zone
                    else None
                ),
                "port": fa.port,
                "status_override": fa.status_override,
                "effective_status": fa.status_override or finding.status,
            }
            for fa in sorted(
                finding.affected_links,
                key=lambda x: (
                    asset_by_id[x.asset_id].key if x.asset_id in asset_by_id else "",
                    x.port or -1,
                ),
            )
        ],
        "evidence": [
            {
                "key": ev.key,
                "kind": ev.kind,
                "title": ev.title,
                "excerpt": ev.excerpt,
                "sha256": ev.sha256,
                "provenance": _provenance_dict(ev),
            }
            for ev in evidence_rows
        ],
        "provenance": _provenance_dict(finding),
    }


def update_finding(
    db: Session,
    *,
    env_id: str,
    finding_key: str,
    status: str | None = None,
    remediation_notes: str | None = None,
    comment: str | None = None,
    asset_status_overrides: list[dict[str, Any]] | None = None,
    actor_email: str,
    actor_user_id: str | None,
) -> dict[str, Any] | None:
    finding = db.execute(
        select(Finding)
        .where(Finding.environment_id == env_id, Finding.key == finding_key)
        .options(selectinload(Finding.affected_links))
    ).scalar_one_or_none()
    if finding is None:
        return None

    if status is not None and status not in _VALID_FINDING_STATUSES:
        raise ValueError(
            f"Invalid status '{status}'. Allowed: {', '.join(sorted(_VALID_FINDING_STATUSES))}."
        )

    if asset_status_overrides is not None:
        for ovr in asset_status_overrides:
            st = ovr.get("status_override")
            if st is not None and st not in _VALID_FINDING_STATUSES:
                raise ValueError(
                    f"Invalid status_override '{st}'. Allowed: "
                    f"{', '.join(sorted(_VALID_FINDING_STATUSES))}."
                )

    old_status = finding.status
    status_changed = False
    override_changed = False
    now_iso = to_utc_iso(utcnow())

    if status is not None and status != old_status:
        finding.status = status
        status_changed = True
        history_entry = {
            "at": now_iso,
            "actor": actor_email,
            "from_status": old_status,
            "to_status": status,
            "comment": (comment or "").strip(),
        }
        finding.status_history = [*list(finding.status_history or []), history_entry]
    elif comment and comment.strip() and status is not None:
        history_entry = {
            "at": now_iso,
            "actor": actor_email,
            "from_status": old_status,
            "to_status": old_status,
            "comment": comment.strip(),
        }
        finding.status_history = [*list(finding.status_history or []), history_entry]

    if remediation_notes is not None:
        finding.remediation_notes = remediation_notes

    if asset_status_overrides is not None:
        assets = list(
            db.execute(select(Asset).where(Asset.environment_id == env_id)).scalars().all()
        )
        asset_id_by_key = {a.key: a.id for a in assets}
        for ovr in asset_status_overrides:
            a_key = ovr["asset_key"]
            a_id = asset_id_by_key.get(a_key)
            if a_id is None:
                raise ValueError(f"Asset '{a_key}' not found in environment.")
            target_port = ovr.get("port")
            matched = [
                fa
                for fa in finding.affected_links
                if fa.asset_id == a_id and (target_port is None or fa.port == target_port)
            ]
            if not matched:
                raise ValueError(f"Asset '{a_key}' is not linked to finding '{finding_key}'.")
            for fa in matched:
                if fa.status_override != ovr.get("status_override"):
                    fa.status_override = ovr.get("status_override")
                    override_changed = True

    finding.updated_by = actor_email
    audit_action = (
        "finding.status_changed" if (status_changed or override_changed) else "finding.updated"
    )
    record_event(
        db,
        action=audit_action,
        subject_type="finding",
        subject_id=finding.id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={
            "environment_id": env_id,
            "finding_key": finding.key,
            "from_status": old_status,
            "to_status": finding.status,
            "override_changed": override_changed,
            "comment": (comment or "").strip(),
        },
    )
    db.commit()
    return get_finding_detail(db, env_id, finding_key)


def get_environment_overview(db: Session, env_id: str) -> dict[str, Any] | None:
    from chaoslab.scenarios.models import ScenarioRun
    from chaoslab.snapshots.models import Snapshot

    env = db.get(Environment, env_id)
    if env is None:
        return None

    zones = list(
        db.execute(select(Zone).where(Zone.environment_id == env_id).order_by(Zone.key.asc()))
        .scalars()
        .all()
    )
    assets = list_assets(db, env_id)
    findings = list(
        db.execute(select(Finding).where(Finding.environment_id == env_id)).scalars().all()
    )
    controls = list(
        db.execute(select(Control).where(Control.environment_id == env_id)).scalars().all()
    )
    service_count = int(
        db.execute(
            select(func.count(Service.id)).where(Service.environment_id == env_id)
        ).scalar_one()
    )
    rel_count = int(
        db.execute(
            select(func.count(Relationship.id)).where(Relationship.environment_id == env_id)
        ).scalar_one()
    )
    rr_count = int(
        db.execute(
            select(func.count(ReachabilityRule.id)).where(ReachabilityRule.environment_id == env_id)
        ).scalar_one()
    )

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_findings = 0
    for f in findings:
        if f.status in _ACTIVE_STATUSES:
            open_findings += 1
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1

    zone_stats: list[dict[str, Any]] = []
    for z in zones:
        z_assets = [a for a in assets if a["zone_key"] == z.key]
        zone_stats.append(
            {
                "key": z.key,
                "name": z.name,
                "trust_level": z.trust_level,
                "intra_zone_policy": z.intra_zone_policy,
                "asset_count": len(z_assets),
                "exposed_count": sum(1 for a in z_assets if a["internet_exposed"]),
                "active_finding_count": sum(a["finding_count"] for a in z_assets),
            }
        )

    latest_snap = db.execute(
        select(Snapshot)
        .where(Snapshot.environment_id == env_id)
        .order_by(Snapshot.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    latest_run = db.execute(
        select(ScenarioRun)
        .where(ScenarioRun.environment_id == env_id)
        .order_by(ScenarioRun.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    recent_batches = list(
        db.execute(
            select(ImportBatch)
            .where(ImportBatch.environment_id == env_id)
            .order_by(ImportBatch.created_at.desc())
            .limit(5)
        )
        .scalars()
        .all()
    )

    latest_run_summary = None
    if latest_run is not None:
        sec = latest_run.result.get("modified") or latest_run.result.get("baseline") or {}
        latest_run_summary = {
            "id": latest_run.id,
            "snapshot_id": latest_run.snapshot_id,
            "headline_score": sec.get("headline_score", 0),
            "total_paths": sec.get("total_paths", 0),
            "result_sha256": latest_run.result_sha256,
            "created_by": latest_run.created_by,
            "created_at": to_utc_iso(latest_run.created_at),
        }

    return {
        "environment": {
            "id": env.id,
            "name": env.name,
            "description": env.description,
            "is_demo": env.is_demo,
            "created_at": to_utc_iso(env.created_at),
        },
        "counts": {
            "zones": len(zones),
            "assets": len(assets),
            "crown_jewels": sum(1 for a in assets if a["crown_jewel"]),
            "internet_exposed": sum(1 for a in assets if a["internet_exposed"]),
            "services": service_count,
            "relationships": rel_count,
            "reachability_rules": rr_count,
            "findings_open": open_findings,
            "findings_total": len(findings),
            "controls_active": sum(1 for c in controls if c.status == "active"),
            "controls_proposed": sum(1 for c in controls if c.status == "proposed"),
        },
        "findings_by_severity": sev_counts,
        "zones_breakdown": zone_stats,
        "latest_snapshot": (
            {
                "id": latest_snap.id,
                "environment_id": latest_snap.environment_id,
                "label": latest_snap.label,
                "sha256": latest_snap.sha256,
                "counts": dict(latest_snap.counts or {}),
                "created_by": latest_snap.created_by,
                "created_at": to_utc_iso(latest_snap.created_at),
            }
            if latest_snap is not None
            else None
        ),
        "latest_run": latest_run_summary,
        "recent_imports": [
            {
                "id": b.id,
                "environment_id": b.environment_id,
                "format": b.format,
                "filename": b.filename,
                "sha256": b.sha256,
                "size_bytes": b.size_bytes,
                "status": b.status,
                "counts": dict(b.counts or {}),
                "error_count": len(b.errors or []),
                "created_by": b.created_by,
                "created_at": to_utc_iso(b.created_at),
            }
            for b in recent_batches
        ],
    }
