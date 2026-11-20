"""Audit event creation and hash-chain verification."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from chaoslab.audit.models import AuditEvent
from chaoslab.db.base import to_utc_iso, utcnow

GENESIS_HASH = "GENESIS"


def _compute_event_hash(
    *,
    seq: int,
    at: datetime,
    actor_user_id: str | None,
    actor_email: str | None,
    action: str,
    subject_type: str,
    subject_id: str,
    details: dict[str, Any],
    prev_hash: str,
) -> str:
    payload = {
        "seq": seq,
        "at": to_utc_iso(at),
        "actor_user_id": actor_user_id,
        "actor_email": actor_email,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "details": details,
        "prev_hash": prev_hash,
    }
    raw = prev_hash + "|" + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def record_event(
    db: Session,
    *,
    action: str,
    subject_type: str,
    subject_id: str,
    actor_user_id: str | None = None,
    actor_email: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append an immutable hash-chained audit event within the current transaction."""
    last = db.execute(
        select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)
    ).scalar_one_or_none()
    seq = 1 if last is None else last.seq + 1
    prev_hash = GENESIS_HASH if last is None else last.hash
    at = utcnow()
    clean_details = dict(details or {})

    event_hash = _compute_event_hash(
        seq=seq,
        at=at,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        action=action,
        subject_type=subject_type,
        subject_id=subject_id,
        details=clean_details,
        prev_hash=prev_hash,
    )
    event = AuditEvent(
        seq=seq,
        at=at,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        action=action,
        subject_type=subject_type,
        subject_id=subject_id,
        details=clean_details,
        prev_hash=prev_hash,
        hash=event_hash,
    )
    db.add(event)
    db.flush()
    return event


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_events(
    db: Session,
    *,
    action: str | None = None,
    actor: str | None = None,
    subject_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AuditEvent], int]:
    stmt = select(AuditEvent)
    count_stmt = select(func.count(AuditEvent.seq))

    filters = []
    if action and action.strip():
        filters.append(AuditEvent.action == action.strip())
    if actor and actor.strip():
        pat = f"%{_escape_like(actor.strip().lower())}%"
        filters.append(func.lower(func.coalesce(AuditEvent.actor_email, "")).like(pat, escape="\\"))
    if subject_type and subject_type.strip():
        filters.append(AuditEvent.subject_type == subject_type.strip())
    if since is not None:
        filters.append(AuditEvent.at >= _as_utc(since))
    if until is not None:
        filters.append(AuditEvent.at <= _as_utc(until))
    if search and search.strip():
        pat = f"%{_escape_like(search.strip().lower())}%"
        filters.append(
            or_(
                func.lower(AuditEvent.action).like(pat, escape="\\"),
                func.lower(func.coalesce(AuditEvent.actor_email, "")).like(pat, escape="\\"),
                func.lower(AuditEvent.subject_type).like(pat, escape="\\"),
                func.lower(AuditEvent.subject_id).like(pat, escape="\\"),
            )
        )

    for cond in filters:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = int(db.execute(count_stmt).scalar_one())
    items = list(
        db.execute(stmt.order_by(AuditEvent.seq.desc()).offset(offset).limit(limit)).scalars().all()
    )
    return items, total


def verify_chain(db: Session) -> dict[str, Any]:
    """Recompute every audit event hash from GENESIS to verify tamper-evidence."""
    events = list(db.execute(select(AuditEvent).order_by(AuditEvent.seq.asc())).scalars().all())
    expected_prev = GENESIS_HASH
    checked = 0

    for ev in events:
        if ev.prev_hash != expected_prev:
            return {"valid": False, "checked_count": checked, "first_broken_seq": ev.seq}
        expected_hash = _compute_event_hash(
            seq=ev.seq,
            at=ev.at,
            actor_user_id=ev.actor_user_id,
            actor_email=ev.actor_email,
            action=ev.action,
            subject_type=ev.subject_type,
            subject_id=ev.subject_id,
            details=ev.details or {},
            prev_hash=ev.prev_hash,
        )
        if ev.hash != expected_hash:
            return {"valid": False, "checked_count": checked, "first_broken_seq": ev.seq}
        expected_prev = ev.hash
        checked += 1

    return {"valid": True, "checked_count": checked, "first_broken_seq": None}
