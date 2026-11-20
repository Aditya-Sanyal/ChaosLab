"""Read-only Nmap XML (-oX) parser hardened with defusedxml."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as std_et
from datetime import UTC, datetime

from defusedxml.common import DefusedXmlException, DTDForbidden
from defusedxml.ElementTree import DefusedXMLParser

from chaoslab.imports.schemas import NormalizedBundle

_SAFE_KEY_RE = re.compile(r"[^a-z0-9-]+")


class _StrictNmapXMLParser(DefusedXMLParser):
    """Allow bare <!DOCTYPE nmaprun> emitted by Nmap while rejecting any DTD subset or entities."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.parser.StartDoctypeDeclHandler = self._check_doctype

    def _check_doctype(
        self, name: str, sysid: str | None, pubid: str | None, has_subset: int
    ) -> None:
        if sysid is not None or pubid is not None or has_subset or name != "nmaprun":
            raise DTDForbidden(name, sysid, pubid)


def _parse_nmap_xml_tree(text: str) -> std_et.Element:
    builder = std_et.TreeBuilder()
    parser = _StrictNmapXMLParser(
        target=builder,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    )
    parser.feed(text)
    return parser.close()


def _slug_asset_key(hostname: str | None, ip_addr: str) -> str:
    if hostname:
        head = hostname.split(".", 1)[0].lower()
        cleaned = _SAFE_KEY_RE.sub("-", head).strip("-")
        if cleaned:
            return cleaned[:64]
    ip_slug = _SAFE_KEY_RE.sub("-", ip_addr.lower()).strip("-")
    return f"host-{ip_slug}"[:64]


def parse_nmap_xml(
    text: str,
    *,
    safe_filename: str,
    vantage_zone_key: str,
    target_zone_key: str,
    default_observed_at: datetime,
    max_rows: int,
) -> NormalizedBundle:
    """Parse an existing Nmap XML file into assets, services, reachability, and evidence."""
    bundle = NormalizedBundle()
    try:
        root = _parse_nmap_xml_tree(text)
    except DefusedXmlException as exc:
        bundle.add_error(
            entity="nmap_xml",
            row=None,
            field="xml",
            code="unsafe_xml",
            message=f"Rejected unsafe XML construct ({type(exc).__name__}).",
        )
        return bundle
    except std_et.ParseError as exc:
        bundle.add_error(
            entity="nmap_xml",
            row=exc.position[0] if exc.position else None,
            field="xml",
            code="invalid_xml",
            message=f"Malformed XML: {exc}",
        )
        return bundle

    if root.tag != "nmaprun":
        bundle.add_error(
            entity="nmap_xml",
            row=1,
            field="root",
            code="invalid_nmap_root",
            message=f"Expected <nmaprun> root element, got <{root.tag}>.",
        )
        return bundle

    observed_at = default_observed_at
    start_raw = root.attrib.get("start")
    if start_raw:
        try:
            observed_at = datetime.fromtimestamp(int(start_raw), tz=UTC)
        except ValueError:
            bundle.add_warning(
                entity="nmap_xml",
                row=1,
                field="start",
                code="invalid_scan_timestamp",
                message=f"Could not parse nmaprun start='{start_raw}'; using import time.",
            )

    source = f"nmap:{safe_filename}"
    hosts = root.findall("host")
    if len(hosts) > max_rows:
        bundle.add_error(
            entity="nmap_xml",
            row=None,
            field="host",
            code="too_many_rows",
            message=f"Host count {len(hosts)} exceeds limit {max_rows}.",
        )
        return bundle

    seen_asset_keys: set[str] = set()
    up_count = 0

    for idx, host_el in enumerate(hosts, start=1):
        status_el = host_el.find("status")
        if status_el is not None and status_el.attrib.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find("address")
        if addr_el is None or not addr_el.attrib.get("addr"):
            bundle.add_warning(
                entity="assets",
                row=idx,
                field="address",
                code="missing_address",
                message=f"Skipped host #{idx} with no address element.",
            )
            continue

        ip_addr = addr_el.attrib["addr"].strip()
        hostname_el = host_el.find("hostnames/hostname")
        hostname = (
            hostname_el.attrib.get("name", "").strip()
            if hostname_el is not None and hostname_el.attrib.get("name")
            else None
        )
        os_el = host_el.find("os/osmatch")
        os_name = os_el.attrib.get("name", "").strip() if os_el is not None else None

        base_key = _slug_asset_key(hostname, ip_addr)
        asset_key = base_key
        if asset_key in seen_asset_keys:
            asset_key = f"{base_key}-{idx}"[:64]
        seen_asset_keys.add(asset_key)
        up_count += 1

        open_ports: list[int] = []
        service_summaries: list[str] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            port_str = port_el.attrib.get("portid", "")
            proto = port_el.attrib.get("protocol", "tcp").lower()
            try:
                port_num = int(port_str)
            except ValueError:
                continue
            if not (1 <= port_num <= 65535):
                continue

            svc_el = port_el.find("service")
            svc_name = (
                svc_el.attrib.get("name", "unknown").strip()
                if svc_el is not None
                else "unknown"
            )
            product = svc_el.attrib.get("product") if svc_el is not None else None
            version = svc_el.attrib.get("version") if svc_el is not None else None
            method = svc_el.attrib.get("method", "table") if svc_el is not None else "table"
            svc_conf = 0.90 if method == "probed" else 0.65

            open_ports.append(port_num)
            desc_parts = [f"{port_num}/{proto}", svc_name]
            if product:
                desc_parts.append(product)
            if version:
                desc_parts.append(version)
            service_summaries.append(" ".join(desc_parts))

            bundle.services.append(
                {
                    "key": f"SVC-{asset_key}-{proto}-{port_num}"[:128],
                    "asset_key": asset_key,
                    "port": port_num,
                    "protocol": proto if proto in ("tcp", "udp") else "tcp",
                    "name": svc_name[:128] or "unknown",
                    "product": product[:255] if product else None,
                    "version": version[:128] if version else None,
                    "origin": "imported",
                    "source": source,
                    "observed_at": observed_at,
                    "confidence": svc_conf,
                }
            )

        ev_key = f"EV-NMAP-{asset_key}"[:128]
        excerpt = (
            f"Host {ip_addr}"
            + (f" ({hostname})" if hostname else "")
            + f" observed from vantage zone '{vantage_zone_key}': "
            + (
                ", ".join(service_summaries)
                if service_summaries
                else "host up, no open ports listed"
            )
        )[:8192]
        bundle.evidence.append(
            {
                "key": ev_key,
                "kind": "scanner_output",
                "title": f"Nmap scan observation for {asset_key}",
                "excerpt": excerpt,
                "sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
                "origin": "imported",
                "source": source,
                "observed_at": observed_at,
                "confidence": 0.85,
            }
        )

        bundle.assets.append(
            {
                "key": asset_key,
                "name": hostname or ip_addr,
                "type": "server",
                "zone_key": target_zone_key,
                "criticality": 3,
                "owner": "unassigned",
                "hostname": hostname,
                "ip_addresses": [ip_addr],
                "os": os_name,
                "tags": ["nmap_discovered"],
                "description": f"Imported from Nmap XML ({safe_filename}).",
                "evidence_keys": [ev_key],
                "origin": "imported",
                "source": source,
                "observed_at": observed_at,
                "confidence": 0.85,
            }
        )

        if open_ports:
            sorted_ports = sorted(set(open_ports))
            bundle.reachability.append(
                {
                    "key": f"RR-NMAP-{vantage_zone_key}-{asset_key}"[:128],
                    "source_kind": "zone",
                    "source_key": vantage_zone_key,
                    "target_kind": "asset",
                    "target_key": asset_key,
                    "ports": sorted_ports,
                    "protocol": "tcp",
                    "description": (
                        f"Reachability observed from '{vantage_zone_key}' in {safe_filename}."
                    ),
                    "evidence_keys": [ev_key],
                    "origin": "imported",
                    "source": source,
                    "observed_at": observed_at,
                    "confidence": 0.85,
                }
            )

    if up_count == 0 and not bundle.errors:
        bundle.add_warning(
            entity="nmap_xml",
            row=None,
            field="host",
            code="no_up_hosts",
            message="Nmap XML contained zero 'up' hosts with addresses.",
        )

    return bundle
