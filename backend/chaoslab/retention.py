"""Data retention sweeps respecting snapshot references and audit hash-chain integrity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from chaoslab.audit.models import AuditEvent
from chaoslab.audit.service import record_event
from chaoslab.auth.models import UserSession
from chaoslab.config import Settings
from chaoslab.db.base import to_utc_iso, utcnow
from chaoslab.scenarios.models import ScenarioRun
from chaoslab.snapshots.models import Snapshot


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def run_retention(
    db: Session,
    *,
    settings: Settings,
    now: datetime | None = None,
    dry_run: bool = True,
    snapshots_days: int | None = None,
    runs_days: int | None = None,
    sessions_grace_days: int | None = None,
    audit_days: int | None = None,
    actor: str = "cli:retention",
) -> dict[str, Any]:
    """Identify or purge aged records without breaking kept runs or the live audit chain."""
    eff_snapshots_days = (
        settings.retention_snapshots_days if snapshots_days is None else int(snapshots_days)
    )
    eff_runs_days = settings.retention_runs_days if runs_days is None else int(runs_days)
    eff_sessions_days = (
        settings.retention_sessions_grace_days
        if sessions_grace_days is None
        else int(sessions_grace_days)
    )
    eff_audit_days = settings.retention_audit_days if audit_days is None else int(audit_days)

    for label, val in (
        ("snapshots_days", eff_snapshots_days),
        ("runs_days", eff_runs_days),
        ("sessions_grace_days", eff_sessions_days),
        ("audit_days", eff_audit_days),
    ):
        if val < 0:
            raise ValueError(f"{label} must be >= 0.")

    now_utc = _as_utc(now) if now is not None else utcnow()
    sessions_cutoff = now_utc - timedelta(days=eff_sessions_days)
    runs_cutoff = now_utc - timedelta(days=eff_runs_days)
    snapshots_cutoff = now_utc - timedelta(days=eff_snapshots_days)
    audit_cutoff = now_utc - timedelta(days=eff_audit_days)

    all_sessions = list(db.execute(select(UserSession)).scalars().all())
    expired_sessions = [s for s in all_sessions if _as_utc(s.expires_at) < sessions_cutoff]

    # Evaluate scenario runs BEFORE snapshots so snapshots only referenced by purged runs
    # become eligible for cleanup, while snapshots referenced by kept runs stay protected.
    all_runs = list(db.execute(select(ScenarioRun)).scalars().all())
    expired_runs: list[ScenarioRun] = []
    protected_snapshot_ids: set[str] = set()
    for run in all_runs:
        if _as_utc(run.created_at) < runs_cutoff:
            expired_runs.append(run)
        else:
            protected_snapshot_ids.add(run.snapshot_id)

    all_snapshots = list(db.execute(select(Snapshot)).scalars().all())
    aged_snapshots = [s for s in all_snapshots if _as_utc(s.created_at) < snapshots_cutoff]
    deletable_snapshots = [s for s in aged_snapshots if s.id not in protected_snapshot_ids]
    protected_old_snapshots = [s for s in aged_snapshots if s.id in protected_snapshot_ids]

    all_audit_timestamps = list(db.execute(select(AuditEvent.at)).scalars().all())
    audit_ready_count = sum(1 for ts in all_audit_timestamps if _as_utc(ts) < audit_cutoff)

    counts = {
        "sessions": len(expired_sessions),
        "scenario_runs": len(expired_runs),
        "snapshots": len(deletable_snapshots),
        "snapshots_protected_by_runs": len(protected_old_snapshots),
        "audit_events_ready_for_archive": audit_ready_count,
    }
    policy_days = {
        "snapshots": eff_snapshots_days,
        "scenario_runs": eff_runs_days,
        "sessions_grace": eff_sessions_days,
        "audit_archive": eff_audit_days,
    }

    if not dry_run:
        for sess in expired_sessions:
            db.delete(sess)
        for run in expired_runs:
            db.delete(run)
        db.flush()
        for snap in deletable_snapshots:
            db.delete(snap)
        db.flush()

        record_event(
            db,
            action="retention.executed",
            subject_type="retention",
            subject_id="policy",
            actor_email=actor,
            details={"policy_days": policy_days, "counts": counts},
        )
        db.commit()

    return {
        "dry_run": dry_run,
        "as_of": to_utc_iso(now_utc),
        "policy_days": policy_days,
        "counts": counts,
        "audit_chain_preserved": True,
    }
