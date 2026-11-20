"""Shared intermediate dataclasses for validated import bundles and issues."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportIssue:
    severity: str  # error | warning
    entity: str
    row: int | None
    field: str | None
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "entity": self.entity,
            "row": self.row,
            "field": self.field,
            "code": self.code,
            "message": self.message,
        }


@dataclass
class NormalizedBundle:
    zones: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    reachability: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ImportIssue] = field(default_factory=list)
    warnings: list[ImportIssue] = field(default_factory=list)

    def add_error(
        self,
        *,
        entity: str,
        row: int | None,
        field: str | None,
        code: str,
        message: str,
    ) -> None:
        self.errors.append(ImportIssue("error", entity, row, field, code, message))

    def add_warning(
        self,
        *,
        entity: str,
        row: int | None,
        field: str | None,
        code: str,
        message: str,
    ) -> None:
        self.warnings.append(ImportIssue("warning", entity, row, field, code, message))

    def all_records(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "zones": self.zones,
            "assets": self.assets,
            "services": self.services,
            "relationships": self.relationships,
            "reachability": self.reachability,
            "findings": self.findings,
            "controls": self.controls,
            "evidence": self.evidence,
        }
