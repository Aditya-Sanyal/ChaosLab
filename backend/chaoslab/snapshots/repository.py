"""GraphRepository interface and relational SQL snapshot implementation."""

from __future__ import annotations

from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from chaoslab.analysis.canonical import sha256_canonical
from chaoslab.analysis.models import EnvironmentModel
from chaoslab.audit.service import record_event
from chaoslab.db.base import to_utc_iso
from chaoslab.inventory.models import (
    Asset,
    Control,
    Environment,
    Evidence,
    EvidenceLink,
    Finding,
    ReachabilityRule,
    Relationship,
    Service,
    Zone,
)
from chaoslab.snapshots.models import Snapshot


class GraphRepository(Protocol):
    def load_snapshot(self, snapshot_id: str) -> EnvironmentModel: ...

    def create_snapshot(
        self,
        environment_id: str,
        created_by: str,
        *,
        label: str | None = None,
        actor_user_id: str | None = None,
    ) -> Snapshot: ...


def build_environment_document(
    db: Session, environment_id: str
) -> tuple[Environment, dict[str, Any], dict[str, int]]:
    """Build canonical sorted JSON representation and counts for an environment."""
    env = db.get(Environment, environment_id)
    if env is None:
        raise LookupError(f"Environment {environment_id} not found")

    zones = list(
        db.execute(
            select(Zone).where(Zone.environment_id == environment_id).order_by(Zone.key.asc())
        )
        .scalars()
        .all()
    )
    zone_key_by_id = {z.id: z.key for z in zones}

    assets = list(
        db.execute(
            select(Asset).where(Asset.environment_id == environment_id).order_by(Asset.key.asc())
        )
        .scalars()
        .all()
    )
    asset_key_by_id = {a.id: a.key for a in assets}

    services = list(
        db.execute(
            select(Service)
            .where(Service.environment_id == environment_id)
            .order_by(Service.key.asc())
        )
        .scalars()
        .all()
    )
    relationships = list(
        db.execute(
            select(Relationship)
            .where(Relationship.environment_id == environment_id)
            .order_by(Relationship.key.asc())
        )
        .scalars()
        .all()
    )
    reachability = list(
        db.execute(
            select(ReachabilityRule)
            .where(ReachabilityRule.environment_id == environment_id)
            .order_by(ReachabilityRule.key.asc())
        )
        .scalars()
        .all()
    )
    findings = list(
        db.execute(
            select(Finding)
            .where(Finding.environment_id == environment_id)
            .options(selectinload(Finding.affected_links))
            .order_by(Finding.key.asc())
        )
        .scalars()
        .all()
    )
    controls = list(
        db.execute(
            select(Control)
            .where(Control.environment_id == environment_id)
            .order_by(Control.key.asc())
        )
        .scalars()
        .all()
    )
    evidence_rows = list(
        db.execute(
            select(Evidence)
            .where(Evidence.environment_id == environment_id)
            .order_by(Evidence.key.asc())
        )
        .scalars()
        .all()
    )
    ev_key_by_id = {e.id: e.key for e in evidence_rows}

    ev_links = list(
        db.execute(
            select(EvidenceLink).where(EvidenceLink.environment_id == environment_id)
        )
        .scalars()
        .all()
    )
    ev_keys_by_subject: dict[str, set[str]] = {}
    for link in ev_links:
        ev_key = ev_key_by_id.get(link.evidence_id)
        if ev_key:
            ev_keys_by_subject.setdefault(link.subject_id, set()).add(ev_key)

    def _prov(row: Any) -> dict[str, Any]:
        return {
            "origin": row.origin,
            "source": row.source,
            "observed_at": to_utc_iso(row.observed_at),
            "confidence": row.confidence,
        }

    document: dict[str, Any] = {
        "schema_version": 1,
        "environment": {
            "name": env.name,
        },
        "zones": [
            {
                "key": z.key,
                "name": z.name,
                "trust_level": z.trust_level,
                "intra_zone_policy": z.intra_zone_policy,
                "cidrs": sorted(z.cidrs or []),
                **_prov(z),
            }
            for z in zones
        ],
        "assets": [
            {
                "key": a.key,
                "name": a.name,
                "type": a.type,
                "zone_key": zone_key_by_id.get(a.zone_id) if a.zone_id else None,
                "criticality": a.criticality,
                "owner": a.owner,
                "hostname": a.hostname,
                "ip_addresses": sorted(a.ip_addresses or []),
                "os": a.os,
                "tags": sorted(a.tags or []),
                "description": a.description,
                "evidence_keys": sorted(ev_keys_by_subject.get(a.id, set())),
                **_prov(a),
            }
            for a in assets
        ],
        "services": [
            {
                "key": s.key,
                "asset_key": asset_key_by_id.get(s.asset_id, ""),
                "port": s.port,
                "protocol": s.protocol,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                **_prov(s),
            }
            for s in services
        ],
        "relationships": [
            {
                "key": r.key,
                "source_asset_key": asset_key_by_id.get(r.source_asset_id, ""),
                "target_asset_key": asset_key_by_id.get(r.target_asset_id, ""),
                "type": r.type,
                "attributes": dict(r.attributes or {}),
                "evidence_keys": sorted(ev_keys_by_subject.get(r.id, set())),
                **_prov(r),
            }
            for r in relationships
        ],
        "reachability": [
            {
                "key": rr.key,
                "source_kind": rr.source_kind,
                "source_key": rr.source_key,
                "target_kind": rr.target_kind,
                "target_key": rr.target_key,
                "ports": sorted(int(p) for p in (rr.ports or [])),
                "protocol": rr.protocol,
                "description": rr.description,
                "evidence_keys": sorted(ev_keys_by_subject.get(rr.id, set())),
                **_prov(rr),
            }
            for rr in reachability
        ],
        "findings": [
            {
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
                "affected_assets": sorted(
                    [
                        {
                            "asset_key": asset_key_by_id.get(fa.asset_id, ""),
                            "port": fa.port,
                            "status_override": fa.status_override,
                        }
                        for fa in f.affected_links
                    ],
                    key=lambda x: (x["asset_key"], x["port"] or -1),
                ),
                "evidence_keys": sorted(ev_keys_by_subject.get(f.id, set())),
                **_prov(f),
            }
            for f in findings
        ],
        "controls": [
            {
                "key": c.key,
                "name": c.name,
                "type": c.type,
                "asset_key": asset_key_by_id.get(c.asset_id, ""),
                "affects_rules": sorted(c.affects_rules or []),
                "ports": sorted(int(p) for p in (c.ports or [])),
                "factor": c.factor,
                "status": c.status,
                "evidence_keys": sorted(ev_keys_by_subject.get(c.id, set())),
                **_prov(c),
            }
            for c in controls
        ],
        "evidence": [
            {
                "key": e.key,
                "kind": e.kind,
                "title": e.title,
                "excerpt": e.excerpt,
                "sha256": e.sha256,
                **_prov(e),
            }
            for e in evidence_rows
        ],
    }
    counts = {
        "zones": len(zones),
        "assets": len(assets),
        "services": len(services),
        "relationships": len(relationships),
        "reachability": len(reachability),
        "findings": len(findings),
        "controls": len(controls),
        "evidence": len(evidence_rows),
    }
    return env, document, counts


class SqlGraphRepository:
    """Relational implementation storing frozen snapshots as canonical JSON."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def load_snapshot(self, snapshot_id: str) -> EnvironmentModel:
        snap = self._db.get(Snapshot, snapshot_id)
        if snap is None:
            raise LookupError(f"Snapshot {snapshot_id} not found")
        doc = {
            **snap.document,
            "environment": {
                **snap.document.get("environment", {}),
                "id": snap.environment_id,
            },
        }
        return EnvironmentModel.from_snapshot_dict(doc)

    def create_snapshot(
        self,
        environment_id: str,
        created_by: str,
        *,
        label: str | None = None,
        actor_user_id: str | None = None,
    ) -> Snapshot:
        _env, document, counts = build_environment_document(self._db, environment_id)
        doc_sha = sha256_canonical(document)
        existing_count = len(
            self._db.execute(
                select(Snapshot.id).where(Snapshot.environment_id == environment_id)
            ).all()
        )
        snap = Snapshot(
            environment_id=environment_id,
            label=label or f"Snapshot #{existing_count + 1}",
            sha256=doc_sha,
            document=document,
            counts=counts,
            created_by=created_by,
        )
        self._db.add(snap)
        self._db.flush()

        record_event(
            self._db,
            action="snapshot.created",
            subject_type="snapshot",
            subject_id=snap.id,
            actor_user_id=actor_user_id,
            actor_email=created_by,
            details={"environment_id": environment_id, "sha256": doc_sha, "label": snap.label},
        )
        self._db.commit()
        return snap
