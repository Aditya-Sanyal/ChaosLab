"""Hygiene checks ensuring synthetic fixtures never carry real IPs, domains, or secrets."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

_ALLOWED_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("10.20.0.0/16"),
    ipaddress.ip_network("0.0.0.0/0"),
]

_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(password|secret_key|api_key)\s*="),
]


def test_meridian_freight_fixture_uses_synthetic_ranges_and_no_secrets() -> None:
    fixture = (
        Path(__file__).resolve().parent.parent / "chaoslab" / "demo" / "meridian_freight.json"
    )
    raw_text = fixture.read_text(encoding="utf-8")
    for pat in _SECRET_PATTERNS:
        assert not pat.search(raw_text), f"Secret-like pattern matched in fixture: {pat.pattern}"

    data = json.loads(raw_text)
    for asset in data["assets"]:
        hostname = asset.get("hostname")
        if hostname:
            assert hostname.endswith(".example"), f"Non-.example hostname: {hostname}"
        for ip_str in asset.get("ip_addresses", []):
            ip = ipaddress.ip_address(ip_str)
            assert any(ip in net for net in _ALLOWED_NETS[:4]), (
                f"Asset {asset['key']} IP {ip_str} outside RFC 5737 / RFC 1918 10.20.0.0/16"
            )
