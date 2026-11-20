# CHAOS LAB: Import & Export Formats

All imports validate against strict limits and schemas in a **dry-run** pass before anything is committed to working inventory.

> **Safety & Offline Guarantee:** CHAOS LAB parses files you already possess. Importing an
> Nmap XML file never launches Nmap or sends packets. Secret values (passwords, API tokens,
> private keys) are rejected on upload—credential relationships model existence only.

---

## 1. Upload Safety Limits & Protections

| Control | Default | Behavior |
|---|---|---|
| Max upload size | `10 MB` (`CHAOSLAB_MAX_UPLOAD_BYTES`) | Files larger than 10 MB are rejected |
| Max records / rows | `50,000` (`CHAOSLAB_MAX_IMPORT_ROWS`) | Imports exceeding the row cap are rejected |
| Encoding | UTF-8 (`utf-8` / `utf-8-sig`) | Binary blobs or invalid UTF-8 rejected |
| Archives | Disallowed | `.zip`, `.gz`, `.rar`, `.7z` signatures rejected |
| XML security | `defusedxml` (`forbid_dtd`, `forbid_entities`, `forbid_external`) | XXE and entity expansion (Billion Laughs) blocked |
| Secret guard | Column & regex scan | Columns like `password`/`api_key` or PEM/AWS/token literals rejected |
| CSV export formula guard | Neutralized | Cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` are prefixed with `'` |

---

## 2. JSON Bundle Format (`format=json`)

The JSON bundle matches CHAOS LAB's canonical snapshot document schema (`schema_version: 1`).
Exporting an environment (`GET /api/environments/{env_id}/export/json`) and importing it back
preserves every key and provenance attribute (`origin`, `source`, `observed_at`, `confidence`),
yielding an identical snapshot SHA-256.

```json
{
  "schema_version": 1,
  "zones": [
    {
      "key": "dmz",
      "name": "DMZ",
      "trust_level": "low",
      "intra_zone_policy": "deny",
      "cidrs": ["203.0.113.0/24"],
      "origin": "imported",
      "source": "json:dmz.json",
      "observed_at": "2026-11-18T14:00:00Z",
      "confidence": 0.95
    }
  ],
  "assets": [],
  "services": [],
  "relationships": [],
  "reachability": [],
  "findings": [],
  "controls": [],
  "evidence": []
}
```

Any omitted collection defaults to `[]`. If provenance fields (`origin`, `source`,
`observed_at`, `confidence`) are omitted on a record, defaults are `origin="imported"`,
`source="json:<filename>"`, `observed_at=<upload UTC time>`, and `confidence=0.8`.

---

## 3. CSV Table Formats (`format=csv`)

Specify `entity_type` alongside the CSV upload (`zones`, `assets`, `services`,
`relationships`, `reachability`, `findings`, `controls`, `evidence`).

- Multi-value fields use `;` as delimiter (e.g. `10.20.1.10;10.20.1.11` or `80;443`).
- Optional provenance columns accepted on every CSV type: `origin`, `source`, `observed_at`,
  `confidence`.
- Line numbers in validation errors match 1-based file lines (header = line `1`, first data
  row = line `2`).

### `zones`
Required: `key,name,trust_level` (`untrusted|low|medium|high`)  
Optional: `intra_zone_policy` (`allow|deny`, default `allow`), `cidrs` (`;` list)

### `assets`
Required: `key,name,type` (`server|workstation|network_device|cloud_resource|data_store|application|identity`)  
Optional: `zone_key,criticality` (`1..5`, default `3`), `owner,hostname,ip_addresses,os,tags,description,evidence_keys`

### `services`
Required: `key,asset_key,port,name` (`port` `1..65535`)  
Optional: `protocol` (`tcp|udp`), `product,version`

### `relationships`
Required: `key,source_asset_key,target_asset_key,type` (`has_credential_for|admin_of|can_access|depends_on|hosts|connects_to`)  
Optional: `attributes` (JSON object string, e.g. `{"port":5432}`), `evidence_keys`

### `reachability`
Required: `key,source_kind,source_key,target_kind,target_key` (`zone|asset`)  
Optional: `ports` (`;` list of ports, empty = `*`), `protocol`, `description`, `evidence_keys`

### `findings`
Required: `key,title,category,severity`  
- `category`: `remote_exploitable|local_privesc|credential_exposure|misconfiguration|informational`
- `severity`: `critical|high|medium|low|info`  
Optional: `status` (`open|in_progress|accepted_risk|remediated|false_positive`), `cwe,cve,exploitability,grants` (`user|admin`), `requires_auth` (`true|false`), `description,remediation_notes,affected_assets` (`;` list of `asset_key` or `asset_key:port`), `evidence_keys`

### `controls`
Required: `key,name,type,asset_key,factor` (`type`: `waf|mfa|edr|segmentation|other`, `factor`: `0.0..1.0`)  
Optional: `affects_rules` (`;` list, e.g. `R-EXP-REMOTE;R-IDENTITY-ACCESS`), `ports` (`;` list), `status` (`active|proposed`), `evidence_keys`

### `evidence`
Required: `key,kind,title,excerpt` (`kind`: `scanner_output|config_excerpt|firewall_export|manual_note|import_record`; `excerpt` `<= 8192` bytes)

---

## 4. Nmap XML Format (`format=nmap_xml`)

Accepts standard Nmap XML (`-oX`) output files produced externally. Uses `defusedxml` with DTD
and external entity expansion disabled.

| Nmap XML Element | CHAOS LAB Entity | Provenance & Notes |
|---|---|---|
| `<nmaprun start="...">` | `observed_at` | Epoch converted to UTC ISO timestamp |
| `<host>` (`state="up"`) | `Asset` (placed in `target_zone_key`) | Key from hostname prefix or `host-<ip>`; `origin="imported"`, `source="nmap:<file>"`, `confidence=0.85` |
| `<port>` (`state="open"`) | `Service` | `confidence=0.90` when `service@method="probed"`, `0.65` when `method="table"` |
| Open ports per host | `Evidence` + `ReachabilityRule` | `RR-NMAP-<vantage>-<asset>` from `zone:<vantage_zone_key>` to `asset:<asset_key>` |
