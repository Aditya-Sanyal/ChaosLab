"""AST purity verification for chaoslab.analysis (stdlib allow-list, zero I/O)."""

from __future__ import annotations

import ast
from pathlib import Path

ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "collections",
        "dataclasses",
        "enum",
        "functools",
        "hashlib",
        "heapq",
        "itertools",
        "json",
        "math",
        "typing",
    }
)

FORBIDDEN_CALLS = frozenset({"open", "exec", "eval", "__import__", "compile", "input"})


def test_analysis_package_imports_only_allowlisted_stdlib() -> None:
    analysis_dir = Path(__file__).resolve().parent.parent / "chaoslab" / "analysis"
    py_files = sorted(analysis_dir.rglob("*.py"))
    assert py_files, "Expected Python modules in chaoslab/analysis"

    for path in py_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert (
                        top in ALLOWED_STDLIB or alias.name.startswith("chaoslab.analysis")
                    ), f"Forbidden import {alias.name} in {path.name}"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                assert (
                    top in ALLOWED_STDLIB or mod.startswith("chaoslab.analysis")
                ), f"Forbidden from-import {mod} in {path.name}"
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert (
                    node.func.id not in FORBIDDEN_CALLS
                ), f"Forbidden builtin call {node.func.id} in {path.name}"
