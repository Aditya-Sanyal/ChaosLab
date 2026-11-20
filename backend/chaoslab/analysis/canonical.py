"""Deterministic canonical JSON serialization and SHA-256 hashing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def round_float(value: float, digits: int = 6) -> float:
    """Round float deterministically and normalize negative zero."""
    rounded = round(float(value), digits)
    return 0.0 if rounded == 0.0 else rounded


def normalize_for_canonical(obj: Any) -> Any:
    """Convert dataclasses, tuples, enums, and floats into canonical JSON-ready values."""
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return normalize_for_canonical(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): normalize_for_canonical(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize_for_canonical(item) for item in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return round_float(obj)
    return obj


def canonical_json(obj: Any) -> str:
    """Serialize any supported object as canonical sorted compact JSON."""
    normalized = normalize_for_canonical(obj)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_canonical(obj: Any) -> str:
    """Compute SHA-256 hex digest of canonical JSON representation."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
