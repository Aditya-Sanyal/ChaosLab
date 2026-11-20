"""Shared field validation and record normalization for JSON and CSV imports."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from chaoslab.imports.schemas import NormalizedBundle
from chaoslab.imports.secrets_guard import scan_record_for_secrets

MAX_EXCERPT_BYTES = 8192

ENTITY_ORDER: tuple[str, ...] = (
    "zones",
    "assets",
    "services",
    "relationships",
    "reachability",
    "findings",
    "controls",
    "evidence",
)

VALID_ORIGINS = frozenset({"imported", "manual", "inferred"})
VALID_TRUST_LEVELS = frozenset({"untrusted", "low", "medium", "high"})
VALID_INTRA_POLICIES = frozenset({"allow", "deny"})
VALID_ASSET_TYPES = frozenset(
    {
        "server",
        "workstation",
        "network_device",
        "cloud_resource",
        "data_store",
        "application",
        "identity",
    }
)
VALID_PROTOCOLS = frozenset({"tcp", "udp", "any"})
VALID_REL_TYPES = frozenset(
    {"has_credential_for", "admin_of", "can_access", "depends_on", "hosts", "connects_to"}
)
VALID_ENDPOINT_KINDS = frozenset({"zone", "asset"})
VALID_FINDING_CATEGORIES = frozenset(
    {
        "remote_exploitable",
        "local_privesc",
        "credential_exposure",
        "misconfiguration",
        "informational",
    }
)
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_FINDING_STATUSES = frozenset(
    {"open", "in_progress", "accepted_risk", "remediated", "false_positive"}
)
VALID_GRANTS = frozenset({"user", "admin"})
VALID_CONTROL_TYPES = frozenset({"waf", "mfa", "edr", "segmentation", "other"})
VALID_CONTROL_STATUSES = frozenset({"active", "proposed"})
VALID_EVIDENCE_KINDS = frozenset(
    {"scanner_output", "config_excerpt", "firewall_export", "manual_note", "import_record"}
)


def parse_utc_timestamp(
    raw: Any,
    *,
    default: datetime,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
) -> datetime:
    if raw is None or str(raw).strip() == "":
        return default
    if isinstance(raw, datetime):
        return raw.astimezone(UTC) if raw.tzinfo else raw.replace(tzinfo=UTC)
    text = str(raw).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        bundle.add_error(
            entity=entity,
            row=row,
            field="observed_at",
            code="invalid_timestamp",
            message=f"Invalid ISO-8601 timestamp '{text}'.",
        )
        return default


def validate_enum(
    val: Any,
    *,
    allowed: frozenset[str],
    default: str | None,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
    field: str,
) -> str:
    if val is None or str(val).strip() == "":
        if default is not None:
            return default
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="missing_required",
            message=f"Field '{field}' is required.",
        )
        return ""
    s = str(val).strip()
    if s not in allowed:
        opts = ", ".join(sorted(allowed))
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="invalid_enum",
            message=f"Invalid '{field}' value '{s}'. Allowed: {opts}.",
        )
        return ""
    return s


def validate_int(
    val: Any,
    *,
    min_val: int,
    max_val: int,
    default: int | None,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
    field: str,
) -> int | None:
    if val is None or str(val).strip() == "":
        if default is not None:
            return default
        return None
    if isinstance(val, bool):
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="invalid_integer",
            message=f"Field '{field}' must be an integer.",
        )
        return None
    try:
        num = int(val)
    except (TypeError, ValueError):
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="invalid_integer",
            message=f"Field '{field}' value '{val}' is not an integer.",
        )
        return None
    if num < min_val or num > max_val:
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="out_of_range",
            message=f"Field '{field}'={num} must be between {min_val} and {max_val}.",
        )
        return None
    return num


def validate_float(
    val: Any,
    *,
    min_val: float,
    max_val: float,
    default: float | None,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
    field: str,
) -> float | None:
    if val is None or str(val).strip() == "":
        return default
    if isinstance(val, bool):
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="invalid_number",
            message=f"Field '{field}' must be a number.",
        )
        return None
    try:
        num = float(val)
    except (TypeError, ValueError):
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="invalid_number",
            message=f"Field '{field}' value '{val}' is not a valid number.",
        )
        return None
    if num < min_val or num > max_val:
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="out_of_range",
            message=f"Field '{field}'={num} must be between {min_val} and {max_val}.",
        )
        return None
    return num


def validate_bool(
    val: Any,
    *,
    default: bool,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
    field: str,
) -> bool:
    if val is None or str(val).strip() == "":
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    bundle.add_error(
        entity=entity,
        row=row,
        field=field,
        code="invalid_boolean",
        message=f"Field '{field}' value '{val}' must be true or false.",
    )
    return default


def require_str(
    record: dict[str, Any],
    field: str,
    *,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
    max_len: int = 255,
) -> str:
    raw = record.get(field)
    if raw is None or str(raw).strip() == "":
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="missing_required",
            message=f"Field '{field}' is required.",
        )
        return ""
    s = str(raw).strip()
    if len(s) > max_len:
        bundle.add_error(
            entity=entity,
            row=row,
            field=field,
            code="too_long",
            message=f"Field '{field}' exceeds max length {max_len}.",
        )
        return ""
    return s


def _parse_provenance(
    record: dict[str, Any],
    *,
    default_source: str,
    default_observed_at: datetime,
    bundle: NormalizedBundle,
    entity: str,
    row: int | None,
) -> dict[str, Any]:
    origin = validate_enum(
        record.get("origin"),
        allowed=VALID_ORIGINS,
        default="imported",
        bundle=bundle,
        entity=entity,
        row=row,
        field="origin",
    )
    src_raw = record.get("source")
    source = str(src_raw).strip() if src_raw and str(src_raw).strip() else default_source
    observed_at = parse_utc_timestamp(
        record.get("observed_at"),
        default=default_observed_at,
        bundle=bundle,
        entity=entity,
        row=row,
    )
    conf = validate_float(
        record.get("confidence"),
        min_val=0.0,
        max_val=1.0,
        default=0.8,
        bundle=bundle,
        entity=entity,
        row=row,
        field="confidence",
    )
    return {
        "origin": origin or "imported",
        "source": source[:255],
        "observed_at": observed_at,
        "confidence": conf if conf is not None else 0.8,
    }


def _opt_str(record: dict[str, Any], field: str) -> str | None:
    val = record.get(field)
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def normalize_entity_record(
    entity: str,
    record: dict[str, Any],
    *,
    row: int | None,
    default_source: str,
    default_observed_at: datetime,
    bundle: NormalizedBundle,
) -> dict[str, Any] | None:
    """Validate and normalize one record across any of the 8 entity collections."""
    sec_issues = scan_record_for_secrets(record, entity=entity, row=row)
    bundle.errors.extend(sec_issues)

    err_before = len(bundle.errors)
    key = require_str(record, "key", bundle=bundle, entity=entity, row=row, max_len=128)
    prov = _parse_provenance(
        record,
        default_source=default_source,
        default_observed_at=default_observed_at,
        bundle=bundle,
        entity=entity,
        row=row,
    )

    out: dict[str, Any] = {"key": key, **prov}

    if entity == "zones":
        out["name"] = require_str(record, "name", bundle=bundle, entity=entity, row=row)
        out["trust_level"] = validate_enum(
            record.get("trust_level"),
            allowed=VALID_TRUST_LEVELS,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="trust_level",
        )
        out["intra_zone_policy"] = validate_enum(
            record.get("intra_zone_policy"),
            allowed=VALID_INTRA_POLICIES,
            default="allow",
            bundle=bundle,
            entity=entity,
            row=row,
            field="intra_zone_policy",
        )
        out["cidrs"] = [str(c).strip() for c in (record.get("cidrs") or []) if str(c).strip()]

    elif entity == "assets":
        out["name"] = require_str(record, "name", bundle=bundle, entity=entity, row=row)
        out["type"] = validate_enum(
            record.get("type"),
            allowed=VALID_ASSET_TYPES,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="type",
        )
        out["zone_key"] = _opt_str(record, "zone_key")
        out["criticality"] = (
            validate_int(
                record.get("criticality"),
                min_val=1,
                max_val=5,
                default=3,
                bundle=bundle,
                entity=entity,
                row=row,
                field="criticality",
            )
            or 3
        )
        out["owner"] = _opt_str(record, "owner") or "unassigned"
        out["hostname"] = _opt_str(record, "hostname")
        out["ip_addresses"] = [
            str(ip).strip() for ip in (record.get("ip_addresses") or []) if str(ip).strip()
        ]
        out["os"] = _opt_str(record, "os")
        out["tags"] = [str(t).strip() for t in (record.get("tags") or []) if str(t).strip()]
        out["description"] = str(record.get("description") or "").strip()
        out["evidence_keys"] = [
            str(ek).strip() for ek in (record.get("evidence_keys") or []) if str(ek).strip()
        ]

    elif entity == "services":
        out["asset_key"] = require_str(
            record, "asset_key", bundle=bundle, entity=entity, row=row, max_len=128
        )
        port_raw = record.get("port")
        if port_raw is None or str(port_raw).strip() == "":
            bundle.add_error(
                entity=entity,
                row=row,
                field="port",
                code="missing_required",
                message="Field 'port' is required.",
            )
            port = None
        else:
            port = validate_int(
                port_raw,
                min_val=1,
                max_val=65535,
                default=None,
                bundle=bundle,
                entity=entity,
                row=row,
                field="port",
            )
        out["port"] = port or 0
        out["protocol"] = validate_enum(
            record.get("protocol"),
            allowed=VALID_PROTOCOLS,
            default="tcp",
            bundle=bundle,
            entity=entity,
            row=row,
            field="protocol",
        )
        out["name"] = require_str(
            record, "name", bundle=bundle, entity=entity, row=row, max_len=128
        )
        out["product"] = _opt_str(record, "product")
        out["version"] = _opt_str(record, "version")

    elif entity == "relationships":
        out["source_asset_key"] = require_str(
            record, "source_asset_key", bundle=bundle, entity=entity, row=row, max_len=128
        )
        out["target_asset_key"] = require_str(
            record, "target_asset_key", bundle=bundle, entity=entity, row=row, max_len=128
        )
        out["type"] = validate_enum(
            record.get("type"),
            allowed=VALID_REL_TYPES,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="type",
        )
        attrs = record.get("attributes")
        if attrs is None:
            attrs = {}
        elif not isinstance(attrs, dict):
            bundle.add_error(
                entity=entity,
                row=row,
                field="attributes",
                code="invalid_type",
                message="Field 'attributes' must be a JSON object.",
            )
            attrs = {}
        out["attributes"] = attrs
        out["evidence_keys"] = [
            str(ek).strip() for ek in (record.get("evidence_keys") or []) if str(ek).strip()
        ]

    elif entity == "reachability":
        out["source_kind"] = validate_enum(
            record.get("source_kind"),
            allowed=VALID_ENDPOINT_KINDS,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="source_kind",
        )
        out["source_key"] = require_str(
            record, "source_key", bundle=bundle, entity=entity, row=row, max_len=128
        )
        out["target_kind"] = validate_enum(
            record.get("target_kind"),
            allowed=VALID_ENDPOINT_KINDS,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="target_kind",
        )
        out["target_key"] = require_str(
            record, "target_key", bundle=bundle, entity=entity, row=row, max_len=128
        )
        ports_out: list[int] = []
        for idx, p in enumerate(record.get("ports") or []):
            parsed_p = validate_int(
                p,
                min_val=1,
                max_val=65535,
                default=None,
                bundle=bundle,
                entity=entity,
                row=row,
                field=f"ports[{idx}]",
            )
            if parsed_p is not None:
                ports_out.append(parsed_p)
        out["ports"] = sorted(set(ports_out))
        out["protocol"] = validate_enum(
            record.get("protocol"),
            allowed=VALID_PROTOCOLS,
            default="tcp",
            bundle=bundle,
            entity=entity,
            row=row,
            field="protocol",
        )
        out["description"] = str(record.get("description") or "").strip()
        out["evidence_keys"] = [
            str(ek).strip() for ek in (record.get("evidence_keys") or []) if str(ek).strip()
        ]

    elif entity == "findings":
        out["title"] = require_str(record, "title", bundle=bundle, entity=entity, row=row)
        out["category"] = validate_enum(
            record.get("category"),
            allowed=VALID_FINDING_CATEGORIES,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="category",
        )
        out["severity"] = validate_enum(
            record.get("severity"),
            allowed=VALID_SEVERITIES,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="severity",
        )
        out["status"] = validate_enum(
            record.get("status"),
            allowed=VALID_FINDING_STATUSES,
            default="open",
            bundle=bundle,
            entity=entity,
            row=row,
            field="status",
        )
        out["cwe"] = _opt_str(record, "cwe")
        out["cve"] = _opt_str(record, "cve")
        out["exploitability"] = validate_float(
            record.get("exploitability"),
            min_val=0.0,
            max_val=1.0,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="exploitability",
        )
        out["grants"] = validate_enum(
            record.get("grants"),
            allowed=VALID_GRANTS,
            default="user",
            bundle=bundle,
            entity=entity,
            row=row,
            field="grants",
        )
        out["requires_auth"] = validate_bool(
            record.get("requires_auth"),
            default=False,
            bundle=bundle,
            entity=entity,
            row=row,
            field="requires_auth",
        )
        out["description"] = str(record.get("description") or "").strip()
        out["remediation_notes"] = str(record.get("remediation_notes") or "").strip()

        affected_out: list[dict[str, Any]] = []
        raw_affected = record.get("affected_assets") or []
        if not isinstance(raw_affected, list):
            bundle.add_error(
                entity=entity,
                row=row,
                field="affected_assets",
                code="invalid_type",
                message="Field 'affected_assets' must be a list.",
            )
            raw_affected = []
        for idx, item in enumerate(raw_affected):
            if not isinstance(item, dict):
                bundle.add_error(
                    entity=entity,
                    row=row,
                    field=f"affected_assets[{idx}]",
                    code="invalid_type",
                    message="Each affected_assets entry must be an object.",
                )
                continue
            a_key = require_str(
                item,
                "asset_key",
                bundle=bundle,
                entity=entity,
                row=row,
                max_len=128,
            )
            a_port = validate_int(
                item.get("port"),
                min_val=1,
                max_val=65535,
                default=None,
                bundle=bundle,
                entity=entity,
                row=row,
                field=f"affected_assets[{idx}].port",
            )
            st_ovr = _opt_str(item, "status_override")
            if st_ovr is not None:
                st_ovr = validate_enum(
                    st_ovr,
                    allowed=VALID_FINDING_STATUSES,
                    default=None,
                    bundle=bundle,
                    entity=entity,
                    row=row,
                    field=f"affected_assets[{idx}].status_override",
                )
            affected_out.append(
                {"asset_key": a_key, "port": a_port, "status_override": st_ovr}
            )
        out["affected_assets"] = affected_out
        out["evidence_keys"] = [
            str(ek).strip() for ek in (record.get("evidence_keys") or []) if str(ek).strip()
        ]

    elif entity == "controls":
        out["name"] = require_str(record, "name", bundle=bundle, entity=entity, row=row)
        out["type"] = validate_enum(
            record.get("type"),
            allowed=VALID_CONTROL_TYPES,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="type",
        )
        out["asset_key"] = require_str(
            record, "asset_key", bundle=bundle, entity=entity, row=row, max_len=128
        )
        out["affects_rules"] = [
            str(r).strip() for r in (record.get("affects_rules") or []) if str(r).strip()
        ]
        raw_ports = record.get("ports")
        if raw_ports is None or raw_ports == []:
            out["ports"] = None
        else:
            ports_out = []
            for idx, p in enumerate(raw_ports):
                parsed_p = validate_int(
                    p,
                    min_val=1,
                    max_val=65535,
                    default=None,
                    bundle=bundle,
                    entity=entity,
                    row=row,
                    field=f"ports[{idx}]",
                )
                if parsed_p is not None:
                    ports_out.append(parsed_p)
            out["ports"] = sorted(set(ports_out))
        factor = validate_float(
            record.get("factor"),
            min_val=0.0,
            max_val=1.0,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="factor",
        )
        if factor is None and record.get("factor") in (None, ""):
            bundle.add_error(
                entity=entity,
                row=row,
                field="factor",
                code="missing_required",
                message="Field 'factor' (0.0 to 1.0) is required.",
            )
        out["factor"] = factor if factor is not None else 1.0
        out["status"] = validate_enum(
            record.get("status"),
            allowed=VALID_CONTROL_STATUSES,
            default="proposed",
            bundle=bundle,
            entity=entity,
            row=row,
            field="status",
        )
        out["evidence_keys"] = [
            str(ek).strip() for ek in (record.get("evidence_keys") or []) if str(ek).strip()
        ]

    elif entity == "evidence":
        out["kind"] = validate_enum(
            record.get("kind"),
            allowed=VALID_EVIDENCE_KINDS,
            default=None,
            bundle=bundle,
            entity=entity,
            row=row,
            field="kind",
        )
        out["title"] = require_str(record, "title", bundle=bundle, entity=entity, row=row)
        excerpt = require_str(
            record,
            "excerpt",
            bundle=bundle,
            entity=entity,
            row=row,
            max_len=MAX_EXCERPT_BYTES,
        )
        if len(excerpt.encode("utf-8")) > MAX_EXCERPT_BYTES:
            bundle.add_error(
                entity=entity,
                row=row,
                field="excerpt",
                code="too_long",
                message=f"Evidence excerpt exceeds {MAX_EXCERPT_BYTES} bytes.",
            )
        out["excerpt"] = excerpt
        out["sha256"] = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()

    if len(bundle.errors) > err_before:
        return None
    return out
