"""Render deterministic, auto-escaped Markdown and HTML reports for scenario runs."""

from __future__ import annotations

import hashlib
import html
from typing import Any, Literal

from sqlalchemy.orm import Session

from chaoslab.analysis import RESULT_DISCLAIMER
from chaoslab.audit.service import record_event
from chaoslab.db.base import to_utc_iso
from chaoslab.inventory.models import Environment
from chaoslab.scenarios.models import ScenarioRun
from chaoslab.snapshots.models import Snapshot

DEFAULT_LIMITATIONS: tuple[str, ...] = (
    (
        "Offline simulation only: modeled against a frozen snapshot of imported or synthetic "
        "assets, reachability rules, and findings; zero packets sent and no live hosts probed."
    ),
    (
        "A modeled path is not proof that an exploit succeeds or that a live control is "
        "misconfigured."
    ),
    (
        "Step likelihoods multiply assuming independence; no adversary detection, SIEM alerting, "
        "or incident response time is modeled."
    ),
    (
        "Reachability and credential relationships reflect presence only; secret values are never "
        "collected, stored, or tested."
    ),
)


def _e(value: Any) -> str:
    """HTML-escape every interpolated dynamic string cleanly."""
    return html.escape("" if value is None else str(value), quote=True)


def _md_text(value: Any) -> str:
    """Escape angle brackets in untrusted prose so Markdown viewers cannot inject raw HTML."""
    s = "" if value is None else str(value)
    return s.replace("<", "&lt;").replace(">", "&gt;")


def _md_cell(value: Any) -> str:
    """Escape Markdown table cells cleanly."""
    return (
        _md_text(value)
        .replace("|", "\\|")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def _safe_slug(text: str) -> str:
    out = []
    prev_dash = False
    for ch in text.lower():
        if ch.isalnum() or ch in ("_", "-"):
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    slug = "".join(out).strip("-")[:48]
    return slug or "scenario-run"


def build_report_context(db: Session, run_id: str) -> dict[str, Any]:
    """Assemble all provenance, path, comparison, and evidence facts for a scenario run."""
    run = db.get(ScenarioRun, run_id)
    if run is None:
        raise LookupError(f"Scenario run '{run_id}' not found.")
    snap = db.get(Snapshot, run.snapshot_id)
    env = db.get(Environment, run.environment_id)

    res = dict(run.result or {})
    scenario_meta = dict(res.get("scenario") or {})
    baseline = dict(res.get("baseline") or {})
    modified = res.get("modified")
    comparison = res.get("comparison")

    ev_doc = (snap.document or {}).get("evidence", []) if snap is not None else []
    ev_by_key = {str(e.get("key", "")): e for e in ev_doc if e.get("key")}

    referenced_keys: set[str] = set()
    for section in (baseline, modified):
        if not section:
            continue
        for path in section.get("paths", []):
            for step in path.get("steps", []):
                referenced_keys.update(step.get("evidence_keys", []))

    evidence_items: list[dict[str, Any]] = []
    for key in sorted(referenced_keys):
        ev = ev_by_key.get(key)
        if ev is not None:
            evidence_items.append(
                {
                    "key": key,
                    "kind": str(ev.get("kind", "")),
                    "title": str(ev.get("title", "")),
                    "excerpt": str(ev.get("excerpt", "")),
                    "sha256": str(ev.get("sha256", "")),
                    "origin": str(ev.get("origin", "")),
                    "source": str(ev.get("source", "")),
                    "observed_at": str(ev.get("observed_at", "")),
                    "confidence": float(ev.get("confidence", 1.0)),
                }
            )
        else:
            evidence_items.append(
                {
                    "key": key,
                    "kind": "reference",
                    "title": "Unresolved evidence reference",
                    "excerpt": "(Evidence metadata omitted from snapshot document)",
                    "sha256": "",
                    "origin": "",
                    "source": "",
                    "observed_at": "",
                    "confidence": 1.0,
                }
            )

    return {
        "result_kind": "modeled_report",
        "disclaimer": str(res.get("disclaimer") or RESULT_DISCLAIMER),
        "generated_note": "Generated dynamically from immutable snapshot and run records.",
        "environment": {
            "id": run.environment_id,
            "name": env.name if env is not None else run.environment_id,
        },
        "snapshot": {
            "id": run.snapshot_id,
            "label": snap.label if snap is not None else "Unknown snapshot",
            "sha256": str(res.get("snapshot_sha256") or (snap.sha256 if snap else "")),
            "created_at": to_utc_iso(snap.created_at) if snap is not None else None,
            "counts": dict(snap.counts or {}) if snap is not None else {},
        },
        "run": {
            "id": run.id,
            "scenario_id": run.scenario_id,
            "scenario_name": str(scenario_meta.get("name") or "Ad-hoc scenario"),
            "scenario": scenario_meta,
            "actions": list(run.actions or []),
            "engine_version": run.engine_version,
            "ruleset_version": run.ruleset_version,
            "input_sha256": run.input_sha256,
            "result_sha256": run.result_sha256,
            "duration_ms": run.duration_ms,
            "created_by": run.created_by,
            "created_at": to_utc_iso(run.created_at),
        },
        "baseline": baseline,
        "modified": modified,
        "comparison": comparison,
        "evidence": evidence_items,
        "global_assumptions": list(res.get("global_assumptions") or []),
        "limitations": list(DEFAULT_LIMITATIONS),
    }


def _render_md_paths(lines: list[str], title: str, section: dict[str, Any]) -> None:
    lines.append(f"### {title}")
    lines.append("")
    lines.append(
        f"- **Headline Modeled Score:** {section.get('headline_score', 0)}/100  \n"
        f"- **Total Modeled Paths:** {section.get('total_paths', 0)}  \n"
        f"- **Search Truncated:** {bool(section.get('search_truncated', False))}"
    )
    lines.append("")
    paths = section.get("paths", [])
    if not paths:
        lines.append("_No modeled paths reached target capabilities under current parameters._")
        lines.append("")
        return

    for idx, p in enumerate(paths, start=1):
        lines.append(
            f"#### Path #{idx}: `{_md_text(p.get('target_key'))}` "
            f"({ _md_text(p.get('goal_capability')) }) — Score **{p.get('modeled_score', 0)}/100**"
        )
        lines.append("")
        lines.append(
            f"- Path Likelihood: `{p.get('path_likelihood')}` | "
            f"Confidence: `{p.get('path_confidence')}` | "
            f"Impact: `{p.get('impact')}` | "
            f"Low Confidence Flag: `{bool(p.get('low_confidence', False))}`"
        )
        lines.append("")
        lines.append(
            "| Step | Rule | Transition | Gains | Likelihood | Conf | Controls | Evidence |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
        for s_idx, step in enumerate(p.get("steps", []), start=1):
            ctrls = ", ".join(c.get("key", "") for c in step.get("controls_applied", [])) or "—"
            evs = ", ".join(step.get("evidence_keys", [])) or "—"
            lines.append(
                f"| {s_idx} | `{_md_cell(step.get('rule_id'))}` | "
                f"`{_md_cell(step.get('from_position'))}` → `{_md_cell(step.get('target_key'))}` | "
                f"`{_md_cell(step.get('gains'))}` | "
                f"{step.get('likelihood')} (base {step.get('base_likelihood')}) | "
                f"{step.get('confidence')} | {_md_cell(ctrls)} | {_md_cell(evs)} |"
            )
        lines.append("")
        for s_idx, step in enumerate(p.get("steps", []), start=1):
            prereqs = "; ".join(
                f"[{pr.get('kind')}:{pr.get('key')}] {pr.get('detail')}"
                for pr in step.get("prerequisites", [])
            )
            assumps = "; ".join(step.get("assumptions", []))
            lines.append(
                f"- **Step {s_idx} Prerequisites:** {_md_text(prereqs)}"
                + (f"  \n  *Step Assumptions:* {_md_text(assumps)}" if assumps else "")
            )
        lines.append("")


def render_markdown_report(ctx: dict[str, Any]) -> str:
    """Render an offline scenario report as clean, escaped Markdown."""
    run = ctx["run"]
    snap = ctx["snapshot"]
    env = ctx["environment"]
    sc = run["scenario"]

    lines: list[str] = [
        f"# CHAOS LAB Scenario Report: {_md_text(run['scenario_name'])}",
        "",
        f"> **Modeled Result Notice:** {_md_text(ctx['disclaimer'])}",
        "",
        "## 1. Snapshot & Run Provenance",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Environment | {_md_cell(env['name'])} (`{_md_cell(env['id'])}`) |",
        f"| Snapshot | {_md_cell(snap['label'])} (`{_md_cell(snap['id'])}`) |",
        f"| Snapshot SHA-256 | `{_md_cell(snap['sha256'])}` |",
        f"| Run ID | `{_md_cell(run['id'])}` |",
        f"| Actor / Timestamp | `{_md_cell(run['created_by'])}` "
        f"at `{_md_cell(run['created_at'])}` |",
        f"| Engine / Ruleset | `{_md_cell(run['engine_version'])}` / "
        f"`{_md_cell(run['ruleset_version'])}` |",
        f"| Input SHA-256 | `{_md_cell(run['input_sha256'])}` |",
        f"| Result SHA-256 | `{_md_cell(run['result_sha256'])}` |",
        "",
        "## 2. Scenario Definition",
        "",
        f"- **Start:** `{_md_text(sc.get('start_kind'))}:{_md_text(sc.get('start_key'))}` "
        f"(privilege `{_md_text(sc.get('start_level', 'user'))}`)",
        "- **Targets:** "
        + (
            ", ".join(
                f"`{_md_text(t.get('asset_key'))}:{_md_text(t.get('level'))}`"
                for t in sc.get("targets", [])
            )
            or "None"
        ),
        (
            f"- **Bounds:** max_depth={sc.get('max_depth', 6)}, "
            f"k_paths={sc.get('k_paths', 5)}, max_expansions={sc.get('max_expansions', 20000)}"
        ),
        "",
    ]

    actions = run["actions"]
    lines.append("## 3. Defensive Actions & Before/After Comparison")
    lines.append("")
    if not actions:
        lines.append("_Baseline-only run: no what-if defensive actions applied._")
        lines.append("")
    else:
        lines.append(f"Applied **{len(actions)}** defensive action(s) against an in-memory copy:")
        lines.append("")
        for idx, act in enumerate(actions, start=1):
            lines.append(
                f"{idx}. `{_md_text(act.get('kind'))}` — params `{_md_text(act.get('params'))}`"
            )
        lines.append("")

    comp = ctx.get("comparison")
    if comp:
        delta = comp.get("score_delta", 0)
        lines.append(
            f"- **Headline Score:** {comp.get('baseline_headline_score')} → "
            f"{comp.get('modified_headline_score')} (delta {delta:+d})"
        )
        lines.append(
            f"- **Path Count:** {comp.get('baseline_path_count')} → "
            f"{comp.get('modified_path_count')}"
        )
        lines.append("")
        lines.append("| Status | Target | Score Before | Score After | Delta | Path Key |")
        lines.append("|---|---|---|---|---|---|")
        diff_entries = (
            list(comp.get("removed", []))
            + list(comp.get("remaining", []))
            + list(comp.get("new", []))
        )
        for entry in diff_entries:
            lines.append(
                f"| `{_md_cell(entry.get('status'))}` | `{_md_cell(entry.get('target_key'))}` | "
                f"{entry.get('score_before')} | {entry.get('score_after')} | "
                f"{entry.get('score_delta'):+d} | `{_md_cell(entry.get('path_key'))}` |"
            )
        lines.append("")

    lines.append("## 4. Modeled Attack Paths")
    lines.append("")
    _render_md_paths(lines, "Baseline Snapshot Analysis", ctx["baseline"])
    if ctx.get("modified") is not None:
        _render_md_paths(lines, "Post-Action Modified Analysis", ctx["modified"])

    lines.append("## 5. Supporting Evidence Referenced")
    lines.append("")
    if not ctx["evidence"]:
        lines.append("_No evidence items were referenced by paths in this run._")
        lines.append("")
    else:
        for ev in ctx["evidence"]:
            lines.append(
                f"### `{_md_text(ev['key'])}` — {_md_text(ev['title'])} (`{_md_text(ev['kind'])}`)"
            )
            lines.append(
                f"- Origin/Source: `{_md_text(ev['origin'])}` / `{_md_text(ev['source'])}` "
                f"| Observed: `{_md_text(ev['observed_at'])}` "
                f"| Confidence: `{ev['confidence']}` | SHA-256: `{_md_text(ev['sha256'][:16])}`"
            )
            lines.append("")
            lines.append("```text")
            lines.append(_md_text(ev["excerpt"]))
            lines.append("```")
            lines.append("")

    lines.append("## 6. Modeling Assumptions & Limitations")
    lines.append("")
    lines.append("### Global Engine Assumptions")
    for item in ctx["global_assumptions"]:
        lines.append(f"- {_md_text(item)}")
    lines.append("")
    lines.append("### Model Limitations")
    for item in ctx["limitations"]:
        lines.append(f"- {_md_text(item)}")
    lines.append("")

    return "\n".join(lines)


def _render_html_paths(title: str, section: dict[str, Any]) -> str:
    paths = section.get("paths", [])
    blocks: list[str] = [
        "<div class='card'>",
        f"<h3>{_e(title)}</h3>",
        "<p class='meta'>",
        f"Headline Modeled Score: <strong>{_e(section.get('headline_score', 0))}/100</strong> · ",
        f"Total Paths: <strong>{_e(section.get('total_paths', 0))}</strong> · ",
        f"Search Truncated: <strong>{_e(bool(section.get('search_truncated', False)))}</strong>",
        "</p>",
    ]
    if not paths:
        blocks.append("<p class='muted'>No modeled paths reached target capabilities.</p></div>")
        return "\n".join(blocks)

    for idx, p in enumerate(paths, start=1):
        blocks.append("<div class='path-box'>")
        blocks.append(
            f"<h4>Path #{idx}: <code>{_e(p.get('target_key'))}</code> "
            f"(<code>{_e(p.get('goal_capability'))}</code>) — "
            f"Score <strong>{_e(p.get('modeled_score', 0))}/100</strong></h4>"
        )
        blocks.append(
            "<p class='meta'>"
            f"Likelihood: <code>{_e(p.get('path_likelihood'))}</code> · "
            f"Confidence: <code>{_e(p.get('path_confidence'))}</code> · "
            f"Impact: <code>{_e(p.get('impact'))}</code> · "
            f"Low Confidence: <code>{_e(bool(p.get('low_confidence', False)))}</code>"
            "</p>"
        )
        blocks.append(
            "<table><thead><tr><th>#</th><th>Rule</th><th>Transition</th>"
            "<th>Gains</th><th>Likelihood</th><th>Conf</th><th>Controls</th><th>Evidence</th>"
            "</tr></thead><tbody>"
        )
        for s_idx, step in enumerate(p.get("steps", []), start=1):
            ctrls = ", ".join(c.get("key", "") for c in step.get("controls_applied", [])) or "—"
            evs = ", ".join(step.get("evidence_keys", [])) or "—"
            prereqs = "; ".join(
                f"[{pr.get('kind')}:{pr.get('key')}] {pr.get('detail')}"
                for pr in step.get("prerequisites", [])
            )
            assumps = "; ".join(step.get("assumptions", []))
            blocks.append(
                "<tr>"
                f"<td>{s_idx}</td>"
                f"<td><code>{_e(step.get('rule_id'))}</code></td>"
                f"<td><code>{_e(step.get('from_position'))}</code> &rarr; "
                f"<code>{_e(step.get('target_key'))}</code></td>"
                f"<td><code>{_e(step.get('gains'))}</code></td>"
                f"<td>{_e(step.get('likelihood'))} (base {_e(step.get('base_likelihood'))})</td>"
                f"<td>{_e(step.get('confidence'))}</td>"
                f"<td>{_e(ctrls)}</td>"
                f"<td>{_e(evs)}</td>"
                "</tr>"
            )
            blocks.append(
                f"<tr><td colspan='8' class='subcell'><strong>Prerequisites:</strong> "
                f"{_e(prereqs)}"
                + (
                    f"<br/><strong>Assumptions:</strong> {_e(assumps)}"
                    if assumps
                    else ""
                )
                + "</td></tr>"
            )
        blocks.append("</tbody></table></div>")

    blocks.append("</div>")
    return "\n".join(blocks)


def render_html_report(ctx: dict[str, Any]) -> str:
    """Render an offline scenario report as standalone, strictly escaped HTML5."""
    run = ctx["run"]
    snap = ctx["snapshot"]
    env = ctx["environment"]
    sc = run["scenario"]

    targets_html = (
        ", ".join(
            f"<code>{_e(t.get('asset_key'))}:{_e(t.get('level'))}</code>"
            for t in sc.get("targets", [])
        )
        or "None"
    )

    actions_html = "<p class='muted'>Baseline-only run (no defensive actions applied).</p>"
    if run["actions"]:
        items = "".join(
            f"<li><code>{_e(a.get('kind'))}</code> &mdash; <code>{_e(a.get('params'))}</code></li>"
            for a in run["actions"]
        )
        actions_html = f"<ol>{items}</ol>"

    comp_html = ""
    comp = ctx.get("comparison")
    if comp:
        diff_entries = (
            list(comp.get("removed", []))
            + list(comp.get("remaining", []))
            + list(comp.get("new", []))
        )
        rows = "".join(
            "<tr>"
            f"<td><span class='pill'>{_e(entry.get('status'))}</span></td>"
            f"<td><code>{_e(entry.get('target_key'))}</code></td>"
            f"<td>{_e(entry.get('score_before'))}</td>"
            f"<td>{_e(entry.get('score_after'))}</td>"
            f"<td>{_e(entry.get('score_delta'))}</td>"
            f"<td><code>{_e(entry.get('path_key'))}</code></td>"
            "</tr>"
            for entry in diff_entries
        )
        comp_html = (
            "<div class='card'>"
            "<h2>3. Defensive Action Comparison</h2>"
            f"<p><strong>Headline Score:</strong> {_e(comp.get('baseline_headline_score'))} "
            f"&rarr; {_e(comp.get('modified_headline_score'))} "
            f"(delta {_e(comp.get('score_delta'))}) · "
            f"<strong>Paths:</strong> {_e(comp.get('baseline_path_count'))} &rarr; "
            f"{_e(comp.get('modified_path_count'))}</p>"
            f"{actions_html}"
            "<table><thead><tr><th>Status</th><th>Target</th><th>Before</th>"
            "<th>After</th><th>Delta</th><th>Path Key</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    else:
        comp_html = f"<div class='card'><h2>3. Defensive Actions</h2>{actions_html}</div>"

    evidence_blocks = []
    for ev in ctx["evidence"]:
        evidence_blocks.append(
            "<div class='ev-box'>"
            f"<h4><code>{_e(ev['key'])}</code> &mdash; {_e(ev['title'])} "
            f"(<code>{_e(ev['kind'])}</code>)</h4>"
            f"<p class='meta'>Origin: <code>{_e(ev['origin'])}</code> · "
            f"Source: <code>{_e(ev['source'])}</code> · "
            f"Observed: <code>{_e(ev['observed_at'])}</code> · "
            f"Confidence: <code>{_e(ev['confidence'])}</code> · "
            f"SHA-256: <code>{_e(str(ev['sha256'])[:16])}</code></p>"
            f"<pre>{_e(ev['excerpt'])}</pre>"
            "</div>"
        )
    evidence_html = (
        "\n".join(evidence_blocks)
        if evidence_blocks
        else "<p class='muted'>No evidence records referenced by this run.</p>"
    )

    assumptions_li = "".join(f"<li>{_e(x)}</li>" for x in ctx["global_assumptions"])
    limitations_li = "".join(f"<li>{_e(x)}</li>" for x in ctx["limitations"])
    mod_section = (
        _render_html_paths("Post-Action Modified Analysis", ctx["modified"])
        if ctx.get("modified") is not None
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CHAOS LAB Report: {_e(run['scenario_name'])}</title>
  <style>
    body {{
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; line-height: 1.5;
    }}
    .wrap {{ max-width: 1120px; margin: 0 auto; }}
    .banner {{
      border: 1px solid #d97706; background: #271a07; color: #fcd34d;
      padding: 12px 16px; border-radius: 6px; margin-bottom: 18px; font-size: 13px;
    }}
    .card {{
      border: 1px solid #30363d; background: #161b22; border-radius: 6px;
      padding: 16px 20px; margin-bottom: 16px;
    }}
    h1, h2, h3, h4 {{ margin-top: 0; color: #f0f6fc; }}
    h1 {{ font-size: 22px; }}
    h2 {{ font-size: 16px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }}
    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
    }}
    pre {{
      background: #0d1117; border: 1px solid #30363d; padding: 10px;
      border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-word;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }}
    th, td {{ border: 1px solid #30363d; padding: 6px 8px; text-align: left; vertical-align: top; }}
    th {{ background: #21262d; color: #9da7b3; font-size: 11px; text-transform: uppercase; }}
    .subcell {{ background: #0d1117; color: #9da7b3; font-size: 11px; }}
    .meta {{ color: #9da7b3; font-size: 12px; }}
    .muted {{ color: #8b949e; font-size: 13px; }}
    .pill {{
      border: 1px solid #30363d; padding: 1px 6px; border-radius: 4px;
      text-transform: uppercase; font-size: 11px;
    }}
    .path-box, .ev-box {{
      border-top: 1px solid #30363d; padding-top: 12px; margin-top: 12px;
    }}
    @media print {{
      body {{ background: #ffffff; color: #111827; }}
      .card {{ background: #ffffff; border-color: #d1d5db; }}
      th {{ background: #f3f4f6; color: #111827; }}
      pre, .subcell {{ background: #f9fafb; color: #111827; }}
      h1, h2, h3, h4 {{ color: #111827; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>CHAOS LAB Scenario Report: {_e(run['scenario_name'])}</h1>
    <div class="banner"><strong>Modeled Result Notice:</strong> {_e(ctx['disclaimer'])}</div>

    <div class="card">
      <h2>1. Snapshot &amp; Run Provenance</h2>
      <table>
        <tbody>
          <tr><th>Environment</th><td>{_e(env['name'])} (<code>{_e(env['id'])}</code>)</td></tr>
          <tr><th>Snapshot</th><td>{_e(snap['label'])} (<code>{_e(snap['id'])}</code>)</td></tr>
          <tr><th>Snapshot SHA-256</th><td><code>{_e(snap['sha256'])}</code></td></tr>
          <tr><th>Run ID</th><td><code>{_e(run['id'])}</code></td></tr>
          <tr><th>Actor / UTC</th><td><code>{_e(run['created_by'])}</code> at
            <code>{_e(run['created_at'])}</code></td></tr>
          <tr><th>Engine / Ruleset</th><td><code>{_e(run['engine_version'])}</code> /
            <code>{_e(run['ruleset_version'])}</code></td></tr>
          <tr><th>Input SHA-256</th><td><code>{_e(run['input_sha256'])}</code></td></tr>
          <tr><th>Result SHA-256</th><td><code>{_e(run['result_sha256'])}</code></td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>2. Scenario Definition</h2>
      <p class="meta">
        <strong>Start:</strong>
        <code>{_e(sc.get('start_kind'))}:{_e(sc.get('start_key'))}</code>
        (privilege <code>{_e(sc.get('start_level', 'user'))}</code>) ·
        <strong>Targets:</strong> {targets_html} ·
        <strong>Bounds:</strong> depth={_e(sc.get('max_depth', 6))},
        k={_e(sc.get('k_paths', 5))}, max_expansions={_e(sc.get('max_expansions', 20000))}
      </p>
    </div>

    {comp_html}

    <h2>4. Modeled Attack Paths</h2>
    {_render_html_paths("Baseline Snapshot Analysis", ctx["baseline"])}
    {mod_section}

    <div class="card">
      <h2>5. Supporting Evidence Referenced</h2>
      {evidence_html}
    </div>

    <div class="card">
      <h2>6. Modeling Assumptions &amp; Limitations</h2>
      <h3>Global Engine Assumptions</h3>
      <ul>{assumptions_li}</ul>
      <h3>Model Limitations</h3>
      <ul>{limitations_li}</ul>
    </div>
  </div>
</body>
</html>
"""


def export_run_report(
    db: Session,
    *,
    run_id: str,
    fmt: Literal["html", "markdown"],
    actor_user_id: str | None,
    actor_email: str,
) -> tuple[str, str, str, str]:
    """Render a scenario run report in HTML or Markdown and log an immutable audit event."""
    ctx = build_report_context(db, run_id)
    if fmt == "html":
        content = render_html_report(ctx)
        media_type = "text/html; charset=utf-8"
        ext = "html"
    elif fmt == "markdown":
        content = render_markdown_report(ctx)
        media_type = "text/markdown; charset=utf-8"
        ext = "md"
    else:
        raise ValueError(f"Unsupported report format: '{fmt}'.")

    report_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    slug = _safe_slug(ctx["run"]["scenario_name"])
    filename = f"chaoslab-{slug}-{run_id[:8]}.{ext}"

    record_event(
        db,
        action="report.exported",
        subject_type="scenario_run",
        subject_id=run_id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        details={
            "environment_id": ctx["environment"]["id"],
            "snapshot_id": ctx["snapshot"]["id"],
            "snapshot_sha256": ctx["snapshot"]["sha256"],
            "format": fmt,
            "filename": filename,
            "result_sha256": ctx["run"]["result_sha256"],
            "report_sha256": report_sha256,
        },
    )
    db.commit()
    return content, media_type, filename, report_sha256
