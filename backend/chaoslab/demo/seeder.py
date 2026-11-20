"""Idempotent synthetic demo seeder (Meridian Freight + local dev users)."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from chaoslab.audit.service import record_event
from chaoslab.auth.models import User
from chaoslab.auth.service import create_user
from chaoslab.inventory.models import (
    Asset,
    Control,
    Environment,
    Evidence,
    EvidenceLink,
    Finding,
    FindingAsset,
    ReachabilityRule,
    Relationship,
    Service,
    Zone,
)
from chaoslab.scenarios.models import Scenario
from chaoslab.snapshots.repository import SqlGraphRepository

_FIXTURE_PATH = Path(__file__).with_name("meridian_freight.json")


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _seed_demo_users(db: Session) -> list[User]:
    specs = [
        (
            "admin@meridian.example",
            "Morgan Hayes (Admin)",
            os.environ.get("CHAOSLAB_DEMO_ADMIN_PASSWORD", "ChaosAdmin!2026"),
            "admin",
        ),
        (
            "analyst@meridian.example",
            "Avery Chen (Analyst)",
            os.environ.get("CHAOSLAB_DEMO_ANALYST_PASSWORD", "ChaosAnalyst!2026"),
            "analyst",
        ),
        (
            "viewer@meridian.example",
            "Samira Patel (Viewer)",
            os.environ.get("CHAOSLAB_DEMO_VIEWER_PASSWORD", "ChaosViewer!2026"),
            "viewer",
        ),
    ]
    users: list[User] = []
    for email, display_name, password, role in specs:
        existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if existing is None:
            user = create_user(
                db,
                email=email,
                display_name=display_name,
                password=password,
                role=role,
            )
            users.append(user)
        else:
            users.append(existing)
    db.commit()
    return users


def seed_demo(db: Session) -> dict[str, Any]:
    """Load synthetic demo accounts, Meridian Freight environment, Snapshot #1, and scenarios."""
    users = _seed_demo_users(db)
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    env_spec = data["environment"]

    existing_env = db.execute(
        select(Environment).where(Environment.name == env_spec["name"])
    ).scalar_one_or_none()
    if existing_env is not None:
        return {"environment_id": existing_env.id, "seeded": False}

    default_prov = data["default_provenance"]
    default_obs = _parse_iso(default_prov["observed_at"])

    def _prov(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "origin": item.get("origin", default_prov["origin"]),
            "source": item.get("source", default_prov["source"]),
            "observed_at": _parse_iso(item["observed_at"])
            if "observed_at" in item
            else default_obs,
            "confidence": float(item.get("confidence", default_prov["confidence"])),
            "updated_by": "seed-demo",
        }

    env = Environment(
        name=env_spec["name"],
        description=env_spec["description"],
        is_demo=bool(env_spec.get("is_demo", True)),
    )
    db.add(env)
    db.flush()

    ev_by_key: dict[str, Evidence] = {}
    for ev_item in data["evidence"]:
        ev = Evidence(
            environment_id=env.id,
            key=ev_item["key"],
            kind=ev_item["kind"],
            title=ev_item["title"],
            excerpt=ev_item["excerpt"],
            sha256=hashlib.sha256(ev_item["excerpt"].encode("utf-8")).hexdigest(),
            **_prov(ev_item),
        )
        db.add(ev)
        ev_by_key[ev.key] = ev
    db.flush()

    def _link_evidence(subject_type: str, subject_id: str, keys: list[str]) -> None:
        for ev_key in keys:
            ev = ev_by_key[ev_key]
            db.add(
                EvidenceLink(
                    environment_id=env.id,
                    evidence_id=ev.id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                )
            )

    zone_by_key: dict[str, Zone] = {}
    for z_item in data["zones"]:
        z = Zone(
            environment_id=env.id,
            key=z_item["key"],
            name=z_item["name"],
            trust_level=z_item["trust_level"],
            intra_zone_policy=z_item["intra_zone_policy"],
            cidrs=z_item.get("cidrs", []),
            **_prov(z_item),
        )
        db.add(z)
        zone_by_key[z.key] = z
    db.flush()

    asset_by_key: dict[str, Asset] = {}
    for a_item in data["assets"]:
        z_id = zone_by_key[a_item["zone_key"]].id if a_item.get("zone_key") else None
        asset = Asset(
            environment_id=env.id,
            zone_id=z_id,
            key=a_item["key"],
            name=a_item["name"],
            type=a_item["type"],
            criticality=int(a_item["criticality"]),
            owner=a_item["owner"],
            hostname=a_item.get("hostname"),
            ip_addresses=a_item.get("ip_addresses", []),
            os=a_item.get("os"),
            tags=a_item.get("tags", []),
            description=a_item.get("description", ""),
            **_prov(a_item),
        )
        db.add(asset)
        db.flush()
        asset_by_key[asset.key] = asset
        _link_evidence("asset", asset.id, a_item.get("evidence_keys", []))

    for s_item in data["services"]:
        db.add(
            Service(
                environment_id=env.id,
                asset_id=asset_by_key[s_item["asset_key"]].id,
                key=s_item["key"],
                port=int(s_item["port"]),
                protocol=s_item.get("protocol", "tcp"),
                name=s_item["name"],
                product=s_item.get("product"),
                version=s_item.get("version"),
                **_prov(s_item),
            )
        )

    for rr_item in data["reachability"]:
        rr = ReachabilityRule(
            environment_id=env.id,
            key=rr_item["key"],
            source_kind=rr_item["source_kind"],
            source_key=rr_item["source_key"],
            target_kind=rr_item["target_kind"],
            target_key=rr_item["target_key"],
            ports=rr_item.get("ports", []),
            protocol=rr_item.get("protocol", "tcp"),
            description=rr_item.get("description", ""),
            **_prov(rr_item),
        )
        db.add(rr)
        db.flush()
        _link_evidence("reachability", rr.id, rr_item.get("evidence_keys", []))

    for rel_item in data["relationships"]:
        rel = Relationship(
            environment_id=env.id,
            key=rel_item["key"],
            source_asset_id=asset_by_key[rel_item["source_asset_key"]].id,
            target_asset_id=asset_by_key[rel_item["target_asset_key"]].id,
            type=rel_item["type"],
            attributes=rel_item.get("attributes", {}),
            **_prov(rel_item),
        )
        db.add(rel)
        db.flush()
        _link_evidence("relationship", rel.id, rel_item.get("evidence_keys", []))

    for f_item in data["findings"]:
        f = Finding(
            environment_id=env.id,
            key=f_item["key"],
            title=f_item["title"],
            category=f_item["category"],
            severity=f_item["severity"],
            status=f_item["status"],
            cwe=f_item.get("cwe"),
            cve=f_item.get("cve"),
            exploitability=f_item.get("exploitability"),
            grants=f_item.get("grants", "user"),
            requires_auth=bool(f_item.get("requires_auth", False)),
            description=f_item.get("description", ""),
            remediation_notes=f_item.get("remediation_notes", ""),
            status_history=[],
            **_prov(f_item),
        )
        db.add(f)
        db.flush()
        for fa in f_item["affected_assets"]:
            db.add(
                FindingAsset(
                    finding_id=f.id,
                    asset_id=asset_by_key[fa["asset_key"]].id,
                    port=fa.get("port"),
                    status_override=fa.get("status_override"),
                )
            )
        _link_evidence("finding", f.id, f_item.get("evidence_keys", []))

    for c_item in data["controls"]:
        ctrl = Control(
            environment_id=env.id,
            key=c_item["key"],
            name=c_item["name"],
            type=c_item["type"],
            asset_id=asset_by_key[c_item["asset_key"]].id,
            affects_rules=c_item.get("affects_rules", []),
            ports=c_item.get("ports"),
            factor=float(c_item["factor"]),
            status=c_item["status"],
            **_prov(c_item),
        )
        db.add(ctrl)
        db.flush()
        _link_evidence("control", ctrl.id, c_item.get("evidence_keys", []))

    admin_user = next((u for u in users if u.role == "admin"), users[0])
    for sc_item in data["scenarios"]:
        db.add(
            Scenario(
                environment_id=env.id,
                name=sc_item["name"],
                description=sc_item.get("description", ""),
                start_kind=sc_item["start_kind"],
                start_key=sc_item["start_key"],
                start_level=sc_item.get("start_level", "user"),
                targets=sc_item["targets"],
                parameters=sc_item.get("parameters", {}),
                created_by=admin_user.email,
            )
        )

    record_event(
        db,
        action="environment.seeded",
        subject_type="environment",
        subject_id=env.id,
        actor_user_id=admin_user.id,
        actor_email=admin_user.email,
        details={"name": env.name, "assets": len(asset_by_key)},
    )
    db.commit()

    repo = SqlGraphRepository(db)
    snapshot = repo.create_snapshot(
        env.id,
        created_by=admin_user.email,
        actor_user_id=admin_user.id,
        label="Snapshot #1 (initial Meridian Freight baseline)",
    )
    return {
        "environment_id": env.id,
        "snapshot_id": snapshot.id,
        "snapshot_sha256": snapshot.sha256,
        "seeded": True,
    }
