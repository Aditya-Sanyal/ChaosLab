"""Initial CHAOS LAB schema (users, sessions, audit, inventory, snapshots, scenarios).

Revision ID: 0001_initial
Revises: None
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def _provenance_columns() -> list[sa.Column]:
    return [
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("import_batch_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_sha256", sa.String(length=64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_token_sha256", "sessions", ["token_sha256"], unique=True)

    op.create_table(
        "audit_events",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_user_id", sa.String(length=36), nullable=True),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("subject_type", sa.String(length=64), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])

    op.create_table(
        "environments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "import_batches",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("errors", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_import_batches_environment_id", "import_batches", ["environment_id"])

    op.create_table(
        "zones",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("trust_level", sa.String(length=32), nullable=False),
        sa.Column("intra_zone_policy", sa.String(length=16), nullable=False),
        sa.Column("cidrs", sa.JSON(), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_zones_env_key"),
    )
    op.create_index("ix_zones_environment_id", "zones", ["environment_id"])

    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "zone_id",
            sa.String(length=36),
            sa.ForeignKey("zones.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("criticality", sa.Integer(), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_addresses", sa.JSON(), nullable=False),
        sa.Column("os", sa.String(length=128), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_assets_env_key"),
    )
    op.create_index("ix_assets_environment_id", "assets", ["environment_id"])
    op.create_index("ix_assets_zone_id", "assets", ["zone_id"])

    op.create_table(
        "services",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=128), nullable=True),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_services_env_key"),
    )
    op.create_index("ix_services_environment_id", "services", ["environment_id"])
    op.create_index("ix_services_asset_id", "services", ["asset_id"])

    op.create_table(
        "relationships",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column(
            "source_asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_relationships_env_key"),
    )
    op.create_index("ix_relationships_environment_id", "relationships", ["environment_id"])
    op.create_index("ix_relationships_source_asset_id", "relationships", ["source_asset_id"])
    op.create_index("ix_relationships_target_asset_id", "relationships", ["target_asset_id"])

    op.create_table(
        "reachability_rules",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("source_kind", sa.String(length=16), nullable=False),
        sa.Column("source_key", sa.String(length=128), nullable=False),
        sa.Column("target_kind", sa.String(length=16), nullable=False),
        sa.Column("target_key", sa.String(length=128), nullable=False),
        sa.Column("ports", sa.JSON(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_reachability_env_key"),
    )
    op.create_index(
        "ix_reachability_rules_environment_id", "reachability_rules", ["environment_id"]
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("cwe", sa.String(length=64), nullable=True),
        sa.Column("cve", sa.String(length=64), nullable=True),
        sa.Column("exploitability", sa.Float(), nullable=True),
        sa.Column("grants", sa.String(length=16), nullable=False),
        sa.Column("requires_auth", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation_notes", sa.Text(), nullable=False),
        sa.Column("status_history", sa.JSON(), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_findings_env_key"),
    )
    op.create_index("ix_findings_environment_id", "findings", ["environment_id"])

    op.create_table(
        "finding_assets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("status_override", sa.String(length=32), nullable=True),
    )
    op.create_index("ix_finding_assets_finding_id", "finding_assets", ["finding_id"])
    op.create_index("ix_finding_assets_asset_id", "finding_assets", ["asset_id"])

    op.create_table(
        "controls",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("affects_rules", sa.JSON(), nullable=False),
        sa.Column("ports", sa.JSON(), nullable=True),
        sa.Column("factor", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_controls_env_key"),
    )
    op.create_index("ix_controls_environment_id", "controls", ["environment_id"])
    op.create_index("ix_controls_asset_id", "controls", ["asset_id"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("excerpt", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        *_provenance_columns(),
        sa.UniqueConstraint("environment_id", "key", name="uq_evidence_env_key"),
    )
    op.create_index("ix_evidence_environment_id", "evidence", ["environment_id"])

    op.create_table(
        "evidence_links",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.String(length=36),
            sa.ForeignKey("evidence.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=36), nullable=False),
    )
    op.create_index("ix_evidence_links_environment_id", "evidence_links", ["environment_id"])
    op.create_index("ix_evidence_links_evidence_id", "evidence_links", ["evidence_id"])
    op.create_index("ix_evidence_links_subject_id", "evidence_links", ["subject_id"])

    op.create_table(
        "snapshots",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_snapshots_environment_id", "snapshots", ["environment_id"])
    op.create_index("ix_snapshots_sha256", "snapshots", ["sha256"])

    op.create_table(
        "scenarios",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("start_kind", sa.String(length=16), nullable=False),
        sa.Column("start_key", sa.String(length=128), nullable=False),
        sa.Column("start_level", sa.String(length=16), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scenarios_environment_id", "scenarios", ["environment_id"])

    op.create_table(
        "scenario_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "environment_id",
            sa.String(length=36),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scenario_id",
            sa.String(length=36),
            sa.ForeignKey("scenarios.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "snapshot_id",
            sa.String(length=36),
            sa.ForeignKey("snapshots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("ruleset_version", sa.String(length=32), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("result_sha256", sa.String(length=64), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scenario_runs_environment_id", "scenario_runs", ["environment_id"])
    op.create_index("ix_scenario_runs_scenario_id", "scenario_runs", ["scenario_id"])
    op.create_index("ix_scenario_runs_snapshot_id", "scenario_runs", ["snapshot_id"])


def downgrade() -> None:
    for table in [
        "scenario_runs",
        "scenarios",
        "snapshots",
        "evidence_links",
        "evidence",
        "controls",
        "finding_assets",
        "findings",
        "reachability_rules",
        "relationships",
        "services",
        "assets",
        "zones",
        "import_batches",
        "environments",
        "audit_events",
        "sessions",
        "users",
    ]:
        op.drop_table(table)
