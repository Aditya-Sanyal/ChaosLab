"""SQLAlchemy models for scenarios and recorded offline simulation runs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from chaoslab.db.base import Base, new_id, utcnow


class Scenario(Base):
    __tablename__ = "scenarios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    start_kind: Mapped[str] = mapped_column(String(16), nullable=False)  # zone | asset
    start_key: Mapped[str] = mapped_column(String(128), nullable=False)
    start_level: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    targets: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    parameters: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scenario_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scenarios.id", ondelete="SET NULL"), nullable=True, index=True
    )
    snapshot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
