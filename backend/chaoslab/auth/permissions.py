"""Canonical RBAC roles and permissions matrix (docs/architecture.md §4)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class Permission(StrEnum):
    INVENTORY_READ = "inventory:read"
    INVENTORY_WRITE = "inventory:write"
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"
    IMPORTS_WRITE = "imports:write"
    SNAPSHOTS_CREATE = "snapshots:create"
    SCENARIOS_READ = "scenarios:read"
    SCENARIOS_RUN = "scenarios:run"
    REPORTS_READ = "reports:read"
    REPORTS_EXPORT = "reports:export"
    AUDIT_READ = "audit:read"
    ADMIN_USERS = "admin:users"
    ADMIN_SETTINGS = "admin:settings"
    ENVIRONMENTS_MANAGE = "environments:manage"


_VIEWER_PERMS: frozenset[Permission] = frozenset(
    {
        Permission.INVENTORY_READ,
        Permission.FINDINGS_READ,
        Permission.SCENARIOS_READ,
        Permission.REPORTS_READ,
    }
)

_ANALYST_PERMS: frozenset[Permission] = _VIEWER_PERMS | frozenset(
    {
        Permission.INVENTORY_WRITE,
        Permission.FINDINGS_WRITE,
        Permission.IMPORTS_WRITE,
        Permission.SNAPSHOTS_CREATE,
        Permission.SCENARIOS_RUN,
        Permission.REPORTS_EXPORT,
        Permission.AUDIT_READ,
    }
)

_ADMIN_PERMS: frozenset[Permission] = _ANALYST_PERMS | frozenset(
    {
        Permission.ADMIN_USERS,
        Permission.ADMIN_SETTINGS,
        Permission.ENVIRONMENTS_MANAGE,
    }
)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: _VIEWER_PERMS,
    Role.ANALYST: _ANALYST_PERMS,
    Role.ADMIN: _ADMIN_PERMS,
}


def has_permission(role: str, permission: Permission) -> bool:
    try:
        parsed = Role(role)
    except ValueError:
        return False
    return permission in ROLE_PERMISSIONS[parsed]
