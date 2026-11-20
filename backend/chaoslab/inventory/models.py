"""SQLAlchemy models for environments, inventory, findings, controls, and evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from chaoslab.db.base import Base, ProvenanceMixin, new_id, utcnow


class Environment(Base):
    __tablename__ = "environments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ImportBatch(Base):
    __tablename__ = "import_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    errors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class Zone(Base, ProvenanceMixin):
    __tablename__ = "zones"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_zones_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False)
    intra_zone_policy: Mapped[str] = mapped_column(String(16), nullable=False, default="allow")
    cidrs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class Asset(Base, ProvenanceMixin):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_assets_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    zone_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("zones.id", ondelete="SET NULL"), nullable=True, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="unassigned")
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    os: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    zone: Mapped[Zone | None] = relationship()
    services: Mapped[list[Service]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Service(Base, ProvenanceMixin):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_services_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="services")


class Relationship(Base, ProvenanceMixin):
    __tablename__ = "relationships"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_relationships_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    source_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ReachabilityRule(Base, ProvenanceMixin):
    __tablename__ = "reachability_rules"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_reachability_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)  # zone | asset
    source_key: Mapped[str] = mapped_column(String(128), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)  # zone | asset
    target_key: Mapped[str] = mapped_column(String(128), nullable=False)
    ports: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class Finding(Base, ProvenanceMixin):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_findings_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exploitability: Mapped[float | None] = mapped_column(Float, nullable=True)
    grants: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    requires_auth: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status_history: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    affected_links: Mapped[list[FindingAsset]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingAsset(Base):
    __tablename__ = "finding_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_override: Mapped[str | None] = mapped_column(String(32), nullable=True)

    finding: Mapped[Finding] = relationship(back_populates="affected_links")
    asset: Mapped[Asset] = relationship()


class Control(Base, ProvenanceMixin):
    __tablename__ = "controls"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_controls_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    affects_rules: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    ports: Mapped[list[int] | None] = mapped_column(JSON, nullable=True)
    factor: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")


class Evidence(Base, ProvenanceMixin):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("environment_id", "key", name="uq_evidence_env_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class EvidenceLink(Base):
    __tablename__ = "evidence_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
