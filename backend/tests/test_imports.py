"""Integration tests for JSON/CSV/Nmap XML imports, safety checks, parity, and overview."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from chaoslab.imports.limits import UploadLimitError, validate_upload_bytes

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "imports"
CSRF = {"X-Requested-With": "chaoslab"}


def _login(client: TestClient, email: str, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200


def test_json_export_import_round_trip_preserves_snapshot_hash(
    client: TestClient, seeded_app
) -> None:
    demo_env_id = seeded_app.state.seed_info["environment_id"]
    demo_snap_sha = seeded_app.state.seed_info["snapshot_sha256"]

    _login(client, "admin@meridian.example", "ChaosAdmin!2026")

    # 1. Export Meridian Freight as canonical JSON bundle
    exp_resp = client.get(f"/api/environments/{demo_env_id}/export/json")
    assert exp_resp.status_code == 200
    bundle_bytes = exp_resp.content
    bundle_json = json.loads(bundle_bytes)
    assert bundle_json["schema_version"] == 1
    assert len(bundle_json["assets"]) == 15

    # 2. Duplicate environment name must return 409; import into a fresh env & demo env below.
    dup = client.post(
        "/api/environments",
        headers=CSRF,
        json={"name": "Meridian Freight (synthetic demo)"},
    )
    assert dup.status_code == 409

    # Re-import exported JSON into demo env (dry-run -> commit)
    val = client.post(
        f"/api/environments/{demo_env_id}/imports/validate",
        headers=CSRF,
        data={"format": "json"},
        files={"file": ("meridian_export.json", bundle_bytes, "application/json")},
    )
    assert val.status_code == 200
    assert val.json()["status"] == "validated"
    assert val.json()["errors"] == []
    assert val.json()["counts"]["assets"] == {"created": 0, "updated": 15}

    com = client.post(
        f"/api/environments/{demo_env_id}/imports/commit",
        headers=CSRF,
        data={"format": "json"},
        files={"file": ("meridian_export.json", bundle_bytes, "application/json")},
    )
    assert com.status_code == 200
    assert com.json()["status"] == "committed"

    snap2 = client.post(
        f"/api/environments/{demo_env_id}/snapshots",
        headers=CSRF,
        json={"label": "Post-Roundtrip"},
    )
    assert snap2.status_code == 201
    assert snap2.json()["sha256"] == demo_snap_sha

    # 3. Verify fresh environment receives all 8 entity collections cleanly
    new_env = client.post(
        "/api/environments",
        headers=CSRF,
        json={"name": "Meridian Clone", "description": "Round-trip clone"},
    )
    assert new_env.status_code == 201
    new_env_id = new_env.json()["id"]

    clone_com = client.post(
        f"/api/environments/{new_env_id}/imports/commit",
        headers=CSRF,
        data={"format": "json"},
        files={"file": ("clone.json", bundle_bytes, "application/json")},
    )
    assert clone_com.status_code == 200
    assert clone_com.json()["counts"]["assets"] == {"created": 15, "updated": 0}
    assert clone_com.json()["counts"]["findings"] == {"created": 5, "updated": 0}

    verify = client.get("/api/audit/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True


def test_csv_imports_across_all_entities_and_formula_safe_export(client: TestClient) -> None:
    _login(client, "admin@meridian.example", "ChaosAdmin!2026")
    env_resp = client.post(
        "/api/environments",
        headers=CSRF,
        json={"name": "CSV Import Lab"},
    )
    assert env_resp.status_code == 201
    env_id = env_resp.json()["id"]

    csv_payloads = [
        (
            "evidence",
            "key,kind,title,excerpt\n"
            "EV-1,manual_note,=SUM(1+1) note,Observed port open on gateway\n",
        ),
        (
            "zones",
            "key,name,trust_level,intra_zone_policy,cidrs\n"
            "internet,Internet,untrusted,allow,0.0.0.0/0\n"
            "dmz,DMZ,low,deny,203.0.113.0/24\n",
        ),
        (
            "assets",
            "key,name,type,zone_key,criticality,owner,ip_addresses,evidence_keys\n"
            "gw-1,=CMD('calc'),server,dmz,4,NetOps,203.0.113.9,EV-1\n"
            "gw-2,Secondary GW,server,dmz,3,NetOps,203.0.113.10,\n",
        ),
        (
            "services",
            "key,asset_key,port,protocol,name\nSVC-1,gw-1,443,tcp,https\n",
        ),
        (
            "reachability",
            "key,source_kind,source_key,target_kind,target_key,ports,protocol\n"
            "RR-1,zone,internet,asset,gw-1,443,tcp\n",
        ),
        (
            "relationships",
            "key,source_asset_key,target_asset_key,type,attributes\n"
            'REL-1,gw-1,gw-2,connects_to,"{""port"": 443}"\n',
        ),
        (
            "findings",
            "key,title,category,severity,affected_assets,evidence_keys\n"
            "F-1,Open gateway flaw,remote_exploitable,high,gw-1:443,EV-1\n",
        ),
        (
            "controls",
            "key,name,type,asset_key,affects_rules,ports,factor,status\n"
            "C-1,WAF,waf,gw-1,R-EXP-REMOTE,443,0.5,active\n",
        ),
    ]

    for ent, text in csv_payloads:
        r = client.post(
            f"/api/environments/{env_id}/imports/commit",
            headers=CSRF,
            data={"format": "csv", "entity_type": ent},
            files={"file": (f"{ent}.csv", text.encode("utf-8"), "text/csv")},
        )
        assert r.status_code == 200, (ent, r.text)
        assert r.json()["status"] == "committed"

    # CSV export must neutralize formula prefixes (=, +, -, @)
    csv_exp = client.get(f"/api/environments/{env_id}/export/csv", params={"entity": "assets"})
    assert csv_exp.status_code == 200
    assert "'=CMD('calc')" in csv_exp.text


def test_import_validation_errors_and_security_rejections(
    client: TestClient, seeded_app
) -> None:
    demo_env_id = seeded_app.state.seed_info["environment_id"]
    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")

    # 1. CSV row/field validation errors (line 3 has invalid criticality and unknown zone)
    bad_csv = (
        "key,name,type,zone_key,criticality\n"
        "ok-1,Valid Host,server,dmz,3\n"
        "bad-1,Bad Host,not_a_type,missing_zone,99\n"
    )
    r_bad_csv = client.post(
        f"/api/environments/{demo_env_id}/imports/validate",
        headers=CSRF,
        data={"format": "csv", "entity_type": "assets"},
        files={"file": ("bad.csv", bad_csv.encode("utf-8"), "text/csv")},
    )
    assert r_bad_csv.status_code == 200
    body = r_bad_csv.json()
    assert body["status"] == "rejected"
    rows = {e["row"] for e in body["errors"]}
    fields = {e["field"] for e in body["errors"]}
    assert 3 in rows
    assert {"type", "criticality"} <= fields

    # Commit on rejected CSV returns 422 and commits nothing
    r_bad_com = client.post(
        f"/api/environments/{demo_env_id}/imports/commit",
        headers=CSRF,
        data={"format": "csv", "entity_type": "assets"},
        files={"file": ("bad.csv", bad_csv.encode("utf-8"), "text/csv")},
    )
    assert r_bad_com.status_code == 422

    # 2. XXE & Billion Laughs XML rejected
    for fname in ("malicious_xxe.xml", "malicious_billion_laughs.xml"):
        xml_bytes = (FIXTURES_DIR / fname).read_bytes()
        rx = client.post(
            f"/api/environments/{demo_env_id}/imports/validate",
            headers=CSRF,
            data={"format": "nmap_xml", "vantage_zone_key": "internet", "target_zone_key": "dmz"},
            files={"file": (fname, xml_bytes, "application/xml")},
        )
        assert rx.status_code == 200
        assert rx.json()["status"] == "rejected"
        assert rx.json()["errors"][0]["code"] == "unsafe_xml"

    # External SYSTEM DTD without entities also rejected
    ext_dtd = b'<!DOCTYPE nmaprun SYSTEM "http://127.0.0.1:9/evil.dtd"><nmaprun/>'
    r_ext = client.post(
        f"/api/environments/{demo_env_id}/imports/validate",
        headers=CSRF,
        data={"format": "nmap_xml", "vantage_zone_key": "internet", "target_zone_key": "dmz"},
        files={"file": ("ext.xml", ext_dtd, "application/xml")},
    )
    assert r_ext.json()["errors"][0]["code"] == "unsafe_xml"

    # 3. Secret column & secret literal rejection
    secret_csv = "key,name,type,password\na-1,Host,server,hunter2\n"
    r_sec_csv = client.post(
        f"/api/environments/{demo_env_id}/imports/validate",
        headers=CSRF,
        data={"format": "csv", "entity_type": "assets"},
        files={"file": ("sec.csv", secret_csv.encode("utf-8"), "text/csv")},
    )
    assert r_sec_csv.json()["errors"][0]["code"] == "secret_rejected"

    secret_json = json.dumps(
        {
            "schema_version": 1,
            "evidence": [
                {
                    "key": "EV-SEC",
                    "kind": "config_excerpt",
                    "title": "Leaked key",
                    "excerpt": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n",
                }
            ],
        }
    ).encode("utf-8")
    r_sec_json = client.post(
        f"/api/environments/{demo_env_id}/imports/validate",
        headers=CSRF,
        data={"format": "json"},
        files={"file": ("sec.json", secret_json, "application/json")},
    )
    assert r_sec_json.json()["errors"][0]["code"] == "secret_rejected"

    # 4. ZIP archive magic bytes rejected
    r_zip = client.post(
        f"/api/environments/{demo_env_id}/imports/validate",
        headers=CSRF,
        data={"format": "json"},
        files={"file": ("bomb.zip", b"PK\x03\x04fakezipdata", "application/zip")},
    )
    assert r_zip.json()["errors"][0]["code"] == "archive_rejected"

    # 5. Size cap enforcement unit check
    try:
        validate_upload_bytes(b"x" * 200, "big.json", max_bytes=100)
        raise AssertionError("Expected UploadLimitError")
    except UploadLimitError as exc:
        assert exc.code == "file_too_large"


def test_nmap_xml_import_end_to_end_and_offline_scenario(client: TestClient) -> None:
    _login(client, "admin@meridian.example", "ChaosAdmin!2026")
    env_id = client.post(
        "/api/environments",
        headers=CSRF,
        json={"name": "Nmap Scan Lab"},
    ).json()["id"]

    # Seed internet + dmz zones via CSV
    zones_csv = (
        "key,name,trust_level,intra_zone_policy\n"
        "internet,Internet,untrusted,allow\n"
        "dmz,DMZ,low,deny\n"
    )
    assert (
        client.post(
            f"/api/environments/{env_id}/imports/commit",
            headers=CSRF,
            data={"format": "csv", "entity_type": "zones"},
            files={"file": ("zones.csv", zones_csv.encode("utf-8"), "text/csv")},
        ).status_code
        == 200
    )

    nmap_bytes = (FIXTURES_DIR / "valid_nmap.xml").read_bytes()
    imp = client.post(
        f"/api/environments/{env_id}/imports/commit",
        headers=CSRF,
        data={"format": "nmap_xml", "vantage_zone_key": "internet", "target_zone_key": "dmz"},
        files={"file": ("valid_nmap.xml", nmap_bytes, "application/xml")},
    )
    assert imp.status_code == 200
    rep = imp.json()
    assert rep["status"] == "committed"
    assert rep["counts"]["assets"]["created"] == 2
    assert rep["counts"]["services"]["created"] == 3  # closed port 22 on edge-gw excluded
    assert rep["counts"]["reachability"]["created"] == 2
    assert rep["counts"]["evidence"]["created"] == 2

    # Check service confidence calibration (probed 0.90 vs table 0.65)
    detail = client.get(f"/api/environments/{env_id}/assets/edge-gw").json()
    assert detail["provenance"]["origin"] == "imported"
    assert detail["provenance"]["source"] == "nmap:valid_nmap.xml"
    assert detail["provenance"]["import_batch_id"] == rep["batch_id"]
    svc_conf = {s["port"]: s["provenance"]["confidence"] for s in detail["services"]}
    assert svc_conf[443] == 0.90
    assert svc_conf[8080] == 0.65

    # Add a finding on edge-gw:443, freeze snapshot, and run offline simulation
    f_csv = (
        "key,title,category,severity,affected_assets\n"
        "F-GW-1,Exposed admin console,remote_exploitable,critical,edge-gw:443\n"
    )
    assert (
        client.post(
            f"/api/environments/{env_id}/imports/commit",
            headers=CSRF,
            data={"format": "csv", "entity_type": "findings"},
            files={"file": ("findings.csv", f_csv.encode("utf-8"), "text/csv")},
        ).status_code
        == 200
    )

    snap_id = client.post(
        f"/api/environments/{env_id}/snapshots",
        headers=CSRF,
        json={"label": "Nmap + Finding Snapshot"},
    ).json()["id"]

    run_resp = client.post(
        f"/api/snapshots/{snap_id}/runs",
        headers=CSRF,
        json={
            "inline_scenario": {
                "name": "Internet to imported Nmap edge-gw",
                "start_kind": "zone",
                "start_key": "internet",
                "targets": [{"asset_key": "edge-gw", "level": "user"}],
            }
        },
    )
    assert run_resp.status_code == 201
    step0 = run_resp.json()["result"]["baseline"]["paths"][0]["steps"][0]
    assert run_resp.json()["result"]["baseline"]["total_paths"] == 1
    assert "EV-NMAP-edge-gw" in step0["evidence_keys"]


def test_overview_expanded_filters_and_import_rbac(client: TestClient, seeded_app) -> None:
    env_id = seeded_app.state.seed_info["environment_id"]

    # Viewer: can read overview & filtered assets; denied import & create env
    _login(client, "viewer@meridian.example", "ChaosViewer!2026")
    ov = client.get(f"/api/environments/{env_id}/overview")
    assert ov.status_code == 200
    assert ov.json()["counts"]["assets"] == 15
    assert ov.json()["counts"]["crown_jewels"] == 4  # db-01, dc-01, bkt-backups, id-it-admin
    assert ov.json()["counts"]["internet_exposed"] == 3

    exposed = client.get(
        f"/api/environments/{env_id}/assets", params={"internet_exposed": True}
    ).json()
    assert {a["key"] for a in exposed} == {"web-01", "vpn-01", "mail-01"}

    with_findings = client.get(
        f"/api/environments/{env_id}/assets", params={"has_findings": True}
    ).json()
    assert {a["key"] for a in with_findings} == {"web-01", "vpn-01", "app-01", "ws-101"}

    manual_only = client.get(
        f"/api/environments/{env_id}/assets", params={"origin": "manual"}
    ).json()
    assert {a["key"] for a in manual_only} == {"id-svc-orders"}

    assert (
        client.post(
            f"/api/environments/{env_id}/imports/validate",
            headers=CSRF,
            data={"format": "json"},
            files={"file": ("x.json", b"{}", "application/json")},
        ).status_code
        == 403
    )
    assert client.post("/api/environments", headers=CSRF, json={"name": "Nope"}).status_code == 403
    client.post("/api/auth/logout", headers=CSRF)

    # Analyst: can export & validate imports; denied creating environments
    _login(client, "analyst@meridian.example", "ChaosAnalyst!2026")
    assert client.post("/api/environments", headers=CSRF, json={"name": "Nope"}).status_code == 403
    assert client.get(f"/api/environments/{env_id}/imports").status_code == 200
