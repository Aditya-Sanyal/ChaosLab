"""Reject secret-looking column names and credential payloads on import."""

from __future__ import annotations

import re
from typing import Any

from chaoslab.imports.schemas import ImportIssue

FORBIDDEN_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "private_key",
        "access_token",
        "auth_token",
        "refresh_token",
        "client_secret",
        "bearer_token",
    }
)

_SECRET_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub personal access token"),
    (
        re.compile(r"(?i)\b(password|passwd|secret_key|api_key|client_secret)\s*[:=]\s*\S+"),
        "inline credential assignment",
    ),
)


def _scan_value(
    val: Any,
    *,
    entity: str,
    row: int | None,
    field: str,
    issues: list[ImportIssue],
) -> None:
    if isinstance(val, dict):
        for k, v in val.items():
            key_norm = str(k).strip().lower()
            if key_norm in FORBIDDEN_FIELD_NAMES and str(v or "").strip():
                issues.append(
                    ImportIssue(
                        severity="error",
                        entity=entity,
                        row=row,
                        field=f"{field}.{k}" if field else str(k),
                        code="secret_rejected",
                        message=(
                            f"Field '{k}' looks like a credential value. "
                            "CHAOS LAB models credential presence only and forbids storing secrets."
                        ),
                    )
                )
            else:
                _scan_value(
                    v,
                    entity=entity,
                    row=row,
                    field=f"{field}.{k}" if field else str(k),
                    issues=issues,
                )
    elif isinstance(val, list):
        for idx, item in enumerate(val):
            _scan_value(item, entity=entity, row=row, field=f"{field}[{idx}]", issues=issues)
    elif isinstance(val, str):
        for pat, desc in _SECRET_VALUE_PATTERNS:
            if pat.search(val):
                issues.append(
                    ImportIssue(
                        severity="error",
                        entity=entity,
                        row=row,
                        field=field,
                        code="secret_rejected",
                        message=(
                            f"Value in '{field}' matches a forbidden {desc}. "
                            "Redact secrets before importing."
                        ),
                    )
                )
                break


def scan_record_for_secrets(
    record: dict[str, Any],
    *,
    entity: str,
    row: int | None,
) -> list[ImportIssue]:
    issues: list[ImportIssue] = []
    for k, v in record.items():
        key_norm = str(k).strip().lower()
        if key_norm in FORBIDDEN_FIELD_NAMES and str(v or "").strip():
            issues.append(
                ImportIssue(
                    severity="error",
                    entity=entity,
                    row=row,
                    field=str(k),
                    code="secret_rejected",
                    message=(
                        f"Column/field '{k}' is forbidden. "
                        "CHAOS LAB never stores passwords, tokens, or private keys."
                    ),
                )
            )
            continue
        _scan_value(v, entity=entity, row=row, field=str(k), issues=issues)
    return issues
