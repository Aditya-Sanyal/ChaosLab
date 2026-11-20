"""SQLAlchemy declarative base, UUID keys, UTC helpers, and provenance mixin."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    """Return a new UUID4 string primary key."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(UTC)


def to_utc_iso(dt: datetime | None) -> str | None:
    """Normalize aware or SQLite-naive datetimes to canonical UTC ISO 8601 strings."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.isoformat().replace("+00:00", "Z")


class Base(DeclarativeBase):
    """Declarative base for all CHAOS LAB tables."""


class ProvenanceMixin:
    """Standard provenance fields required on every inventory fact."""

    origin: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    import_batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
