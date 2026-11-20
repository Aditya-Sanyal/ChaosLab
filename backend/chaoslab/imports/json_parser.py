"""JSON bundle parser matching CHAOS LAB canonical snapshot schema (v1)."""

from __future__ import annotations

import json
from datetime import datetime

from chaoslab.imports.schemas import NormalizedBundle
from chaoslab.imports.validators import ENTITY_ORDER, normalize_entity_record


def parse_json_bundle(
    text: str,
    *,
    safe_filename: str,
    default_observed_at: datetime,
    max_rows: int,
) -> NormalizedBundle:
    bundle = NormalizedBundle()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        bundle.add_error(
            entity="bundle",
            row=exc.lineno,
            field="json",
            code="invalid_json",
            message=f"Malformed JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
        )
        return bundle

    if not isinstance(payload, dict):
        bundle.add_error(
            entity="bundle",
            row=1,
            field="root",
            code="invalid_type",
            message="JSON root must be an object containing entity arrays (zones, assets, etc.).",
        )
        return bundle

    schema_ver = payload.get("schema_version")
    if schema_ver is not None and schema_ver != 1:
        bundle.add_error(
            entity="bundle",
            row=1,
            field="schema_version",
            code="unsupported_schema_version",
            message=f"Unsupported schema_version '{schema_ver}'; expected 1.",
        )
        return bundle

    total_rows = 0
    seen_any_collection = False
    default_source = f"json:{safe_filename}"

    for entity in ENTITY_ORDER:
        if entity not in payload:
            continue
        seen_any_collection = True
        items = payload[entity]
        if not isinstance(items, list):
            bundle.add_error(
                entity=entity,
                row=None,
                field=entity,
                code="invalid_type",
                message=f"'{entity}' must be a JSON array.",
            )
            continue

        total_rows += len(items)
        if total_rows > max_rows:
            bundle.add_error(
                entity=entity,
                row=None,
                field=entity,
                code="too_many_rows",
                message=f"Total records exceed maximum allowed {max_rows} rows.",
            )
            return bundle

        target_list = getattr(bundle, entity)
        seen_keys: set[str] = set()
        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                bundle.add_error(
                    entity=entity,
                    row=idx,
                    field=None,
                    code="invalid_type",
                    message=f"Item {idx} in '{entity}' must be a JSON object.",
                )
                continue
            normalized = normalize_entity_record(
                entity,
                item,
                row=idx,
                default_source=default_source,
                default_observed_at=default_observed_at,
                bundle=bundle,
            )
            if normalized is not None:
                k = normalized["key"]
                if k in seen_keys:
                    bundle.add_error(
                        entity=entity,
                        row=idx,
                        field="key",
                        code="duplicate_key",
                        message=f"Duplicate key '{k}' in '{entity}' import.",
                    )
                    continue
                seen_keys.add(k)
                target_list.append(normalized)

    if not seen_any_collection:
        bundle.add_error(
            entity="bundle",
            row=1,
            field="root",
            code="empty_bundle",
            message=(
                "JSON object contained no recognized collections "
                f"({', '.join(ENTITY_ORDER)})."
            ),
        )

    return bundle
