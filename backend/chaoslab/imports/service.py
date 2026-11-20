"""Import validation, atomic idempotent upserts, and formula-safe exports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from chaoslab.audit.service import record_event
from chaoslab.config import Settings
from chaoslab.db.base import new_id, to_utc_iso, utcnow
from chaoslab.imports.csv_parser import csv_safe_cell, parse_csv_table
from chaoslab.imports.json_parser import parse_json_bundle
from chaoslab.imports.limits import UploadLimitError, sanitize_filename, validate_upload_bytes
from chaoslab.imports.nmap_parser import parse_nmap_xml
from chaoslab.imports.schemas import NormalizedBundle
from chaoslab.imports.validators import ENTITY_ORDER
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
from chaoslab.snapshots.repository import build_environment_document

_ENTITY_MODEL_MAP: dict[str, type[Any]] = {
    "zones": Zone,
    "assets": Asset,
    "services": Service,
    "relationships": Relationship,
    "reachability": ReachabilityRule,
    "findings": Finding,
    "controls": Control,
    "evidence": Evidence,
}


def _existing_keys_by_entity(db: Session, env_id: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entity, model_cls in _ENTITY_MODEL_MAP.items():
        rows = list(
            db.execute(select(model_cls).where(model_cls.environment_id == env_id))
            .scalars()
            .all()
        )
        result[entity] = {row.key: row for row in rows}
    return result


def _validate_cross_references(
    bundle: NormalizedBundle,
    existing: dict[str, dict[str, Any]],
) -> None:
    known_zones = set(existing["zones"]) | {z["key"] for z in bundle.zones}
    known_assets = set(existing["assets"]) | {a["key"] for a in bundle.assets}
    known_evidence = set(existing["evidence"]) | {e["key"] for e in bundle.evidence}

    def _check_evidence(entity: str, row: int, keys: list[str]) -> None:
        for ek in keys:
            if ek not in known_evidence:
                bundle.add_error(
                    entity=entity,
                    row=row,
                    field="evidence_keys",
                    code="unknown_reference",
                    message=f"Referenced evidence '{ek}' does not exist in bundle or environment.",
                )

    for idx, asset in enumerate(bundle.assets, start=1):
        zk = asset.get("zone_key")
        if zk is not None and zk not in known_zones:
            bundle.add_error(
                entity="assets",
                row=idx,
                field="zone_key",
                code="unknown_reference",
                message=f"Asset '{asset['key']}' references unknown zone '{zk}'.",
            )
        _check_evidence("assets", idx, asset.get("evidence_keys", []))

    for idx, svc in enumerate(bundle.services, start=1):
        ak = svc["asset_key"]
        if ak not in known_assets:
            bundle.add_error(
                entity="services",
                row=idx,
                field="asset_key",
                code="unknown_reference",
                message=f"Service '{svc['key']}' references unknown asset '{ak}'.",
            )

    for idx, rel in enumerate(bundle.relationships, start=1):
        for col in ("source_asset_key", "target_asset_key"):
            ak = rel[col]
            if ak not in known_assets:
                bundle.add_error(
                    entity="relationships",
                    row=idx,
                    field=col,
                    code="unknown_reference",
                    message=f"Relationship '{rel['key']}' references unknown asset '{ak}'.",
                )
        _check_evidence("relationships", idx, rel.get("evidence_keys", []))

    for idx, rr in enumerate(bundle.reachability, start=1):
        for kind_col, key_col in (("source_kind", "source_key"), ("target_kind", "target_key")):
            kind = rr[kind_col]
            key = rr[key_col]
            pool = known_zones if kind == "zone" else known_assets
            if key not in pool:
                bundle.add_error(
                    entity="reachability",
                    row=idx,
                    field=key_col,
                    code="unknown_reference",
                    message=f"Reachability '{rr['key']}' references unknown {kind} '{key}'.",
                )
        _check_evidence("reachability", idx, rr.get("evidence_keys", []))

    for idx, f in enumerate(bundle.findings, start=1):
        for aa in f.get("affected_assets", []):
            ak = aa["asset_key"]
            if ak not in known_assets:
                bundle.add_error(
                    entity="findings",
                    row=idx,
                    field="affected_assets",
                    code="unknown_reference",
                    message=f"Finding '{f['key']}' references unknown asset '{ak}'.",
                )
        _check_evidence("findings", idx, f.get("evidence_keys", []))

    for idx, ctrl in enumerate(bundle.controls, start=1):
        ak = ctrl["asset_key"]
        if ak not in known_assets:
            bundle.add_error(
                entity="controls",
                row=idx,
                field="asset_key",
                code="unknown_reference",
                message=f"Control '{ctrl['key']}' references unknown asset '{ak}'.",
            )
        _check_evidence("controls", idx, ctrl.get("evidence_keys", []))


def _compute_plan_counts(
    bundle: NormalizedBundle,
    existing: dict[str, dict[str, Any]],
) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for entity, items in bundle.all_records().items():
        if not items:
            continue
        existing_map = existing[entity]
        created = sum(1 for item in items if item["key"] not in existing_map)
        updated = len(items) - created
        counts[entity] = {"created": created, "updated": updated}
    return counts


def _set_provenance(row: Any, item: dict[str, Any], batch_id: str, actor_email: str) -> None:
    row.origin = item["origin"]
    row.source = item["source"]
    row.observed_at = item["observed_at"]
    row.confidence = item["confidence"]
    row.import_batch_id = batch_id
    row.updated_by = actor_email


def _replace_evidence_links(
    db: Session,
    *,
    env_id: str,
    subject_type: str,
    subject_id: str,
    evidence_keys: list[str],
    ev_by_key: dict[str, Evidence],
) -> None:
    db.execute(
        delete(EvidenceLink).where(
            EvidenceLink.environment_id == env_id,
            EvidenceLink.subject_type == subject_type,
            EvidenceLink.subject_id == subject_id,
        )
    )
    for ek in sorted(set(evidence_keys)):
        ev = ev_by_key[ek]
        db.add(
            EvidenceLink(
                environment_id=env_id,
                evidence_id=ev.id,
                subject_type=subject_type,
                subject_id=subject_id,
            )
        )


def _apply_upserts(
    db: Session,
    *,
    env_id: str,
    bundle: NormalizedBundle,
    existing: dict[str, dict[str, Any]],
    batch_id: str,
    actor_email: str,
) -> None:
    ev_by_key: dict[str, Evidence] = dict(existing["evidence"])
    for item in bundle.evidence:
        row = ev_by_key.get(item["key"])
        if row is None:
            row = Evidence(
                environment_id=env_id,
                key=item["key"],
                kind=item["kind"],
                title=item["title"],
                excerpt=item["excerpt"],
                sha256=item["sha256"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            ev_by_key[row.key] = row
        else:
            row.kind = item["kind"]
            row.title = item["title"]
            row.excerpt = item["excerpt"]
            row.sha256 = item["sha256"]
            _set_provenance(row, item, batch_id, actor_email)

    zone_by_key: dict[str, Zone] = dict(existing["zones"])
    for item in bundle.zones:
        row = zone_by_key.get(item["key"])
        if row is None:
            row = Zone(
                environment_id=env_id,
                key=item["key"],
                name=item["name"],
                trust_level=item["trust_level"],
                intra_zone_policy=item["intra_zone_policy"],
                cidrs=item["cidrs"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            zone_by_key[row.key] = row
        else:
            row.name = item["name"]
            row.trust_level = item["trust_level"]
            row.intra_zone_policy = item["intra_zone_policy"]
            row.cidrs = item["cidrs"]
            _set_provenance(row, item, batch_id, actor_email)

    asset_by_key: dict[str, Asset] = dict(existing["assets"])
    for item in bundle.assets:
        z_id = zone_by_key[item["zone_key"]].id if item.get("zone_key") else None
        row = asset_by_key.get(item["key"])
        if row is None:
            row = Asset(
                environment_id=env_id,
                zone_id=z_id,
                key=item["key"],
                name=item["name"],
                type=item["type"],
                criticality=item["criticality"],
                owner=item["owner"],
                hostname=item["hostname"],
                ip_addresses=item["ip_addresses"],
                os=item["os"],
                tags=item["tags"],
                description=item["description"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            asset_by_key[row.key] = row
        else:
            row.zone_id = z_id
            row.name = item["name"]
            row.type = item["type"]
            row.criticality = item["criticality"]
            row.owner = item["owner"]
            row.hostname = item["hostname"]
            row.ip_addresses = item["ip_addresses"]
            row.os = item["os"]
            row.tags = item["tags"]
            row.description = item["description"]
            _set_provenance(row, item, batch_id, actor_email)
        _replace_evidence_links(
            db,
            env_id=env_id,
            subject_type="asset",
            subject_id=row.id,
            evidence_keys=item.get("evidence_keys", []),
            ev_by_key=ev_by_key,
        )

    svc_by_key: dict[str, Service] = dict(existing["services"])
    for item in bundle.services:
        a_id = asset_by_key[item["asset_key"]].id
        row = svc_by_key.get(item["key"])
        if row is None:
            row = Service(
                environment_id=env_id,
                asset_id=a_id,
                key=item["key"],
                port=item["port"],
                protocol=item["protocol"],
                name=item["name"],
                product=item["product"],
                version=item["version"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            svc_by_key[row.key] = row
        else:
            row.asset_id = a_id
            row.port = item["port"]
            row.protocol = item["protocol"]
            row.name = item["name"]
            row.product = item["product"]
            row.version = item["version"]
            _set_provenance(row, item, batch_id, actor_email)

    rr_by_key: dict[str, ReachabilityRule] = dict(existing["reachability"])
    for item in bundle.reachability:
        row = rr_by_key.get(item["key"])
        if row is None:
            row = ReachabilityRule(
                environment_id=env_id,
                key=item["key"],
                source_kind=item["source_kind"],
                source_key=item["source_key"],
                target_kind=item["target_kind"],
                target_key=item["target_key"],
                ports=item["ports"],
                protocol=item["protocol"],
                description=item["description"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            rr_by_key[row.key] = row
        else:
            row.source_kind = item["source_kind"]
            row.source_key = item["source_key"]
            row.target_kind = item["target_kind"]
            row.target_key = item["target_key"]
            row.ports = item["ports"]
            row.protocol = item["protocol"]
            row.description = item["description"]
            _set_provenance(row, item, batch_id, actor_email)
        _replace_evidence_links(
            db,
            env_id=env_id,
            subject_type="reachability",
            subject_id=row.id,
            evidence_keys=item.get("evidence_keys", []),
            ev_by_key=ev_by_key,
        )

    rel_by_key: dict[str, Relationship] = dict(existing["relationships"])
    for item in bundle.relationships:
        src_id = asset_by_key[item["source_asset_key"]].id
        tgt_id = asset_by_key[item["target_asset_key"]].id
        row = rel_by_key.get(item["key"])
        if row is None:
            row = Relationship(
                environment_id=env_id,
                key=item["key"],
                source_asset_id=src_id,
                target_asset_id=tgt_id,
                type=item["type"],
                attributes=item["attributes"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            rel_by_key[row.key] = row
        else:
            row.source_asset_id = src_id
            row.target_asset_id = tgt_id
            row.type = item["type"]
            row.attributes = item["attributes"]
            _set_provenance(row, item, batch_id, actor_email)
        _replace_evidence_links(
            db,
            env_id=env_id,
            subject_type="relationship",
            subject_id=row.id,
            evidence_keys=item.get("evidence_keys", []),
            ev_by_key=ev_by_key,
        )

    finding_by_key: dict[str, Finding] = dict(existing["findings"])
    for item in bundle.findings:
        row = finding_by_key.get(item["key"])
        if row is None:
            row = Finding(
                environment_id=env_id,
                key=item["key"],
                title=item["title"],
                category=item["category"],
                severity=item["severity"],
                status=item["status"],
                cwe=item["cwe"],
                cve=item["cve"],
                exploitability=item["exploitability"],
                grants=item["grants"],
                requires_auth=item["requires_auth"],
                description=item["description"],
                remediation_notes=item["remediation_notes"],
                status_history=[],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            finding_by_key[row.key] = row
        else:
            row.title = item["title"]
            row.category = item["category"]
            row.severity = item["severity"]
            row.status = item["status"]
            row.cwe = item["cwe"]
            row.cve = item["cve"]
            row.exploitability = item["exploitability"]
            row.grants = item["grants"]
            row.requires_auth = item["requires_auth"]
            row.description = item["description"]
            row.remediation_notes = item["remediation_notes"]
            _set_provenance(row, item, batch_id, actor_email)

        db.execute(delete(FindingAsset).where(FindingAsset.finding_id == row.id))
        for aa in item.get("affected_assets", []):
            db.add(
                FindingAsset(
                    finding_id=row.id,
                    asset_id=asset_by_key[aa["asset_key"]].id,
                    port=aa.get("port"),
                    status_override=aa.get("status_override"),
                )
            )
        _replace_evidence_links(
            db,
            env_id=env_id,
            subject_type="finding",
            subject_id=row.id,
            evidence_keys=item.get("evidence_keys", []),
            ev_by_key=ev_by_key,
        )

    ctrl_by_key: dict[str, Control] = dict(existing["controls"])
    for item in bundle.controls:
        a_id = asset_by_key[item["asset_key"]].id
        row = ctrl_by_key.get(item["key"])
        if row is None:
            row = Control(
                environment_id=env_id,
                key=item["key"],
                name=item["name"],
                type=item["type"],
                asset_id=a_id,
                affects_rules=item["affects_rules"],
                ports=item["ports"],
                factor=item["factor"],
                status=item["status"],
                origin=item["origin"],
                source=item["source"],
                observed_at=item["observed_at"],
                confidence=item["confidence"],
                import_batch_id=batch_id,
                updated_by=actor_email,
            )
            db.add(row)
            db.flush()
            ctrl_by_key[row.key] = row
        else:
            row.name = item["name"]
            row.type = item["type"]
            row.asset_id = a_id
            row.affects_rules = item["affects_rules"]
            row.ports = item["ports"]
            row.factor = item["factor"]
            row.status = item["status"]
            _set_provenance(row, item, batch_id, actor_email)
        _replace_evidence_links(
            db,
            env_id=env_id,
            subject_type="control",
            subject_id=row.id,
            evidence_keys=item.get("evidence_keys", []),
            ev_by_key=ev_by_key,
        )


def process_import(
    db: Session,
    *,
    env_id: str,
    fmt: str,
    raw_bytes: bytes,
    filename: str | None,
    actor_email: str,
    actor_user_id: str | None,
    commit: bool,
    settings: Settings,
    entity_type: str | None = None,
    vantage_zone_key: str = "internet",
    target_zone_key: str = "dmz",
) -> dict[str, Any]:
    """Validate (dry-run) or commit an import file without storing raw upload bytes."""
    env = db.get(Environment, env_id)
    if env is None:
        raise LookupError(f"Environment {env_id} not found")

    safe_name = sanitize_filename(filename)
    file_sha = hashlib.sha256(raw_bytes).hexdigest()
    now = utcnow()
    bundle = NormalizedBundle()
    existing = _existing_keys_by_entity(db, env_id)

    try:
        safe_name, text = validate_upload_bytes(
            raw_bytes, filename, max_bytes=settings.max_upload_bytes
        )
    except UploadLimitError as exc:
        bundle.add_error(
            entity="upload",
            row=None,
            field="file",
            code=exc.code,
            message=exc.message,
        )
        text = None

    if text is not None:
        if fmt == "json":
            bundle = parse_json_bundle(
                text,
                safe_filename=safe_name,
                default_observed_at=now,
                max_rows=settings.max_import_rows,
            )
        elif fmt == "csv":
            if not entity_type:
                bundle.add_error(
                    entity="csv",
                    row=None,
                    field="entity_type",
                    code="missing_required",
                    message="CSV imports require 'entity_type'.",
                )
            else:
                bundle = parse_csv_table(
                    text,
                    entity_type=entity_type,
                    safe_filename=safe_name,
                    default_observed_at=now,
                    max_rows=settings.max_import_rows,
                )
        elif fmt == "nmap_xml":
            if vantage_zone_key not in existing["zones"]:
                bundle.add_error(
                    entity="nmap_xml",
                    row=None,
                    field="vantage_zone_key",
                    code="unknown_reference",
                    message=f"Vantage zone '{vantage_zone_key}' does not exist in environment.",
                )
            if target_zone_key not in existing["zones"]:
                bundle.add_error(
                    entity="nmap_xml",
                    row=None,
                    field="target_zone_key",
                    code="unknown_reference",
                    message=f"Target zone '{target_zone_key}' does not exist in environment.",
                )
            if not bundle.errors:
                bundle = parse_nmap_xml(
                    text,
                    safe_filename=safe_name,
                    vantage_zone_key=vantage_zone_key,
                    target_zone_key=target_zone_key,
                    default_observed_at=now,
                    max_rows=settings.max_import_rows,
                )
        else:
            bundle.add_error(
                entity="upload",
                row=None,
                field="format",
                code="unsupported_format",
                message=f"Unsupported import format '{fmt}'. Use json, csv, or nmap_xml.",
            )

    if not bundle.errors:
        _validate_cross_references(bundle, existing)

    counts = _compute_plan_counts(bundle, existing) if not bundle.errors else {}
    has_errors = len(bundle.errors) > 0
    batch_status = "rejected" if has_errors else ("committed" if commit else "validated")
    batch_id = new_id()

    if commit and not has_errors:
        _apply_upserts(
            db,
            env_id=env_id,
            bundle=bundle,
            existing=existing,
            batch_id=batch_id,
            actor_email=actor_email,
        )

    batch = ImportBatch(
        id=batch_id,
        environment_id=env_id,
        format=fmt,
        filename=safe_name,
        sha256=file_sha,
        size_bytes=len(raw_bytes),
        status=batch_status,
        counts=counts,
        errors=[e.to_dict() for e in bundle.errors],
        created_by=actor_email,
    )
    db.add(batch)
    db.flush()

    audit_action = f"import.{batch_status}"
    record_event(
        db,
        action=audit_action,
        subject_type="import_batch",
        subject_id=batch.id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={
            "environment_id": env_id,
            "format": fmt,
            "filename": safe_name,
            "sha256": file_sha,
            "status": batch_status,
            "error_count": len(bundle.errors),
            "counts": counts,
        },
    )
    db.commit()

    return {
        "batch_id": batch.id,
        "environment_id": env_id,
        "format": fmt,
        "filename": safe_name,
        "sha256": file_sha,
        "size_bytes": len(raw_bytes),
        "status": batch_status,
        "counts": counts,
        "errors": [e.to_dict() for e in bundle.errors],
        "warnings": [w.to_dict() for w in bundle.warnings],
        "created_by": actor_email,
        "created_at": to_utc_iso(batch.created_at),
    }


def list_import_batches(db: Session, env_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    rows = list(
        db.execute(
            select(ImportBatch)
            .where(ImportBatch.environment_id == env_id)
            .order_by(ImportBatch.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
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
        for b in rows
    ]


def export_environment_json(
    db: Session,
    *,
    env_id: str,
    actor_email: str,
    actor_user_id: str | None,
) -> dict[str, Any]:
    _env, document, counts = build_environment_document(db, env_id)
    record_event(
        db,
        action="inventory.exported",
        subject_type="environment",
        subject_id=env_id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={"format": "json", "counts": counts},
    )
    db.commit()
    return document


def export_entity_csv(
    db: Session,
    *,
    env_id: str,
    entity_type: str,
    actor_email: str,
    actor_user_id: str | None,
) -> str:
    if entity_type not in ENTITY_ORDER:
        raise ValueError(f"Unsupported entity '{entity_type}'. Allowed: {', '.join(ENTITY_ORDER)}.")
    _env, document, _counts = build_environment_document(db, env_id)
    records = document.get(entity_type, [])

    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")

    columns_by_entity: dict[str, list[str]] = {
        "zones": [
            "key", "name", "trust_level", "intra_zone_policy", "cidrs",
            "origin", "source", "observed_at", "confidence",
        ],
        "assets": [
            "key", "name", "type", "zone_key", "criticality", "owner", "hostname",
            "ip_addresses", "os", "tags", "description", "evidence_keys",
            "origin", "source", "observed_at", "confidence",
        ],
        "services": [
            "key", "asset_key", "port", "protocol", "name", "product", "version",
            "origin", "source", "observed_at", "confidence",
        ],
        "relationships": [
            "key", "source_asset_key", "target_asset_key", "type", "attributes",
            "evidence_keys", "origin", "source", "observed_at", "confidence",
        ],
        "reachability": [
            "key", "source_kind", "source_key", "target_kind", "target_key", "ports",
            "protocol", "description", "evidence_keys",
            "origin", "source", "observed_at", "confidence",
        ],
        "findings": [
            "key", "title", "category", "severity", "status", "cwe", "cve",
            "exploitability", "grants", "requires_auth", "description",
            "remediation_notes", "affected_assets", "evidence_keys",
            "origin", "source", "observed_at", "confidence",
        ],
        "controls": [
            "key", "name", "type", "asset_key", "affects_rules", "ports", "factor",
            "status", "evidence_keys", "origin", "source", "observed_at", "confidence",
        ],
        "evidence": [
            "key", "kind", "title", "excerpt",
            "origin", "source", "observed_at", "confidence",
        ],
    }

    cols = columns_by_entity[entity_type]
    writer.writerow(cols)

    for rec in records:
        row_cells: list[str] = []
        for col in cols:
            val = rec.get(col)
            if col in ("cidrs", "ip_addresses", "tags", "evidence_keys", "affects_rules", "ports"):
                joined = ";".join(str(x) for x in (val or []))
                row_cells.append(csv_safe_cell(joined))
            elif col == "attributes":
                row_cells.append(csv_safe_cell(json.dumps(val or {}, sort_keys=True)))
            elif col == "affected_assets":
                tokens = [
                    f"{aa['asset_key']}:{aa['port']}" if aa.get("port") else aa["asset_key"]
                    for aa in (val or [])
                ]
                row_cells.append(csv_safe_cell(";".join(tokens)))
            else:
                row_cells.append(csv_safe_cell(val))
        writer.writerow(row_cells)

    record_event(
        db,
        action="inventory.exported",
        subject_type="environment",
        subject_id=env_id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={"format": "csv", "entity": entity_type, "row_count": len(records)},
    )
    db.commit()
    return out.getvalue()
