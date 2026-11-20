"""CSV table parser (all 8 entities) and formula-injection-safe CSV serializer."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

from chaoslab.imports.schemas import NormalizedBundle
from chaoslab.imports.validators import ENTITY_ORDER, normalize_entity_record

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

REQUIRED_CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    "zones": ("key", "name", "trust_level"),
    "assets": ("key", "name", "type"),
    "services": ("key", "asset_key", "port", "name"),
    "relationships": ("key", "source_asset_key", "target_asset_key", "type"),
    "reachability": ("key", "source_kind", "source_key", "target_kind", "target_key"),
    "findings": ("key", "title", "category", "severity"),
    "controls": ("key", "name", "type", "asset_key", "factor"),
    "evidence": ("key", "kind", "title", "excerpt"),
}


def csv_safe_cell(value: Any) -> str:
    """Neutralize spreadsheet formula prefixes (=, +, -, @, tab, CR) on export."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _split_list(raw: str | None) -> list[str]:
    if not raw or not raw.strip():
        return []
    return [part.strip() for part in raw.split(";") if part.strip()]


def _csv_row_to_record(
    entity: str,
    raw_row: dict[str, Any],
    *,
    row_num: int,
    bundle: NormalizedBundle,
) -> dict[str, Any]:
    record: dict[str, Any] = {k.strip(): v for k, v in raw_row.items() if k is not None}

    for list_col in ("cidrs", "ip_addresses", "tags", "evidence_keys", "affects_rules", "ports"):
        if list_col in record and isinstance(record[list_col], str):
            record[list_col] = _split_list(record[list_col])

    if entity == "relationships" and isinstance(record.get("attributes"), str):
        attr_text = record["attributes"].strip()
        if not attr_text:
            record["attributes"] = {}
        else:
            try:
                parsed_attrs = json.loads(attr_text)
                if not isinstance(parsed_attrs, dict):
                    bundle.add_error(
                        entity=entity,
                        row=row_num,
                        field="attributes",
                        code="invalid_type",
                        message="CSV 'attributes' must decode to a JSON object.",
                    )
                    record["attributes"] = {}
                else:
                    record["attributes"] = parsed_attrs
            except json.JSONDecodeError as exc:
                bundle.add_error(
                    entity=entity,
                    row=row_num,
                    field="attributes",
                    code="invalid_json",
                    message=f"Invalid JSON in 'attributes': {exc.msg}",
                )
                record["attributes"] = {}

    if entity == "findings" and isinstance(record.get("affected_assets"), str):
        parsed_affected: list[dict[str, Any]] = []
        for token in _split_list(record["affected_assets"]):
            if ":" in token:
                a_key, port_str = token.rsplit(":", 1)
                parsed_affected.append({"asset_key": a_key.strip(), "port": port_str.strip()})
            else:
                parsed_affected.append({"asset_key": token, "port": None})
        record["affected_assets"] = parsed_affected

    return record


def parse_csv_table(
    text: str,
    *,
    entity_type: str,
    safe_filename: str,
    default_observed_at: datetime,
    max_rows: int,
) -> NormalizedBundle:
    bundle = NormalizedBundle()
    if entity_type not in ENTITY_ORDER:
        bundle.add_error(
            entity="csv",
            row=None,
            field="entity_type",
            code="unsupported_entity_type",
            message=(
                f"Unsupported CSV entity_type '{entity_type}'. "
                f"Allowed: {', '.join(ENTITY_ORDER)}."
            ),
        )
        return bundle

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        bundle.add_error(
            entity=entity_type,
            row=1,
            field="header",
            code="missing_header",
            message="CSV file is missing a header row.",
        )
        return bundle

    headers = {h.strip() for h in reader.fieldnames if h is not None}
    missing = [col for col in REQUIRED_CSV_COLUMNS[entity_type] if col not in headers]
    if missing:
        bundle.add_error(
            entity=entity_type,
            row=1,
            field="header",
            code="missing_columns",
            message=f"Missing required CSV column(s): {', '.join(missing)}.",
        )
        return bundle

    default_source = f"csv:{safe_filename}"
    target_list = getattr(bundle, entity_type)
    seen_keys: set[str] = set()
    data_rows = 0

    for row_num, raw_row in enumerate(reader, start=2):
        if None in raw_row:
            bundle.add_error(
                entity=entity_type,
                row=row_num,
                field=None,
                code="extra_columns",
                message="Row has more columns than the CSV header.",
            )
            continue
        if all(not str(v or "").strip() for v in raw_row.values()):
            continue

        data_rows += 1
        if data_rows > max_rows:
            bundle.add_error(
                entity=entity_type,
                row=row_num,
                field=None,
                code="too_many_rows",
                message=f"CSV row count exceeds maximum allowed {max_rows} rows.",
            )
            return bundle

        record = _csv_row_to_record(entity_type, raw_row, row_num=row_num, bundle=bundle)
        normalized = normalize_entity_record(
            entity_type,
            record,
            row=row_num,
            default_source=default_source,
            default_observed_at=default_observed_at,
            bundle=bundle,
        )
        if normalized is not None:
            k = normalized["key"]
            if k in seen_keys:
                bundle.add_error(
                    entity=entity_type,
                    row=row_num,
                    field="key",
                    code="duplicate_key",
                    message=f"Duplicate key '{k}' in CSV.",
                )
                continue
            seen_keys.add(k)
            target_list.append(normalized)

    if data_rows == 0 and not bundle.errors:
        bundle.add_error(
            entity=entity_type,
            row=1,
            field=None,
            code="no_data_rows",
            message="CSV file contains a header but no data rows.",
        )

    return bundle
