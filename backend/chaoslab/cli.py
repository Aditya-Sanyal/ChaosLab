"""CLI commands for database initialization, synthetic demo seeding, and offline runs."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from chaoslab.audit.service import verify_chain
from chaoslab.auth.service import ConflictError, admin_create_user
from chaoslab.config import get_settings
from chaoslab.db.session import create_db_engine, make_session_factory
from chaoslab.demo.seeder import seed_demo
from chaoslab.inventory.models import Environment
from chaoslab.retention import run_retention
from chaoslab.scenarios.models import Scenario
from chaoslab.scenarios.service import execute_scenario_run
from chaoslab.snapshots.models import Snapshot


def _resolve_backend_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parent.parent,
        Path.cwd(),
        Path("/app"),
    ]
    for candidate in candidates:
        if (candidate / "alembic.ini").is_file() and (candidate / "alembic").is_dir():
            return candidate
    raise FileNotFoundError(
        "Could not locate alembic.ini and alembic/ directory from package root, cwd, or /app."
    )


def _cmd_init_db() -> int:
    settings = get_settings()
    backend_dir = _resolve_backend_dir()
    alembic_ini = backend_dir / "alembic.ini"
    cfg = Config(str(alembic_ini))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")
    print(f"Database initialized at {settings.database_url}")
    return 0


def _cmd_seed_demo() -> int:
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as db:
        info = seed_demo(db)
    print(f"Demo seed result: {info}")
    return 0


def _cmd_run_demo_scenario() -> int:
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as db:
        env = db.execute(
            select(Environment).where(Environment.is_demo.is_(True))
        ).scalar_one_or_none()
        if env is None:
            print("No demo environment found. Run `python -m chaoslab seed-demo` first.")
            return 1
        snap = db.execute(
            select(Snapshot)
            .where(Snapshot.environment_id == env.id)
            .order_by(Snapshot.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if snap is None:
            print("No snapshot found.")
            return 1
        sc = db.execute(
            select(Scenario)
            .where(Scenario.environment_id == env.id)
            .order_by(Scenario.name.asc())
            .limit(1)
        ).scalar_one_or_none()
        # Prefer the primary Orders DB scenario
        scenarios = list(
            db.execute(select(Scenario).where(Scenario.environment_id == env.id)).scalars().all()
        )
        for cand in scenarios:
            if "Orders DB" in cand.name:
                sc = cand
                break
        if sc is None:
            print("No scenarios found.")
            return 1

        print(f"Environment: {env.name}")
        print(f"Snapshot:    {snap.label} (sha256={snap.sha256[:16]}...)")
        print(f"Scenario:    {sc.name}")

        baseline_run = execute_scenario_run(
            db, snapshot_id=snap.id, scenario_id=sc.id, created_by="cli-demo"
        )
        b_res = baseline_run.result
        print(f"Disclaimer:  {b_res['disclaimer']}")
        print(
            f"Baseline:    headline_score={b_res['baseline']['headline_score']}/100, "
            f"paths={b_res['baseline']['total_paths']}, "
            f"result_sha256={b_res['result_sha256'][:16]}..."
        )
        for idx, p in enumerate(b_res["baseline"]["paths"], start=1):
            print(
                f"  Path {idx}: score={p['modeled_score']}/100 "
                f"likelihood={p['path_likelihood']} conf={p['path_confidence']} "
                f"low_conf={p['low_confidence']}"
            )
            for s in p["steps"]:
                print(
                    f"    - [{s['rule_id']}] {s['from_position']} -> {s['target_key']} "
                    f"(l={s['likelihood']}, c={s['confidence']}, ev={s['evidence_keys']})"
                )

        action_sets = [
            (
                "D1 (Remediate F-005 on app-01)",
                [{"kind": "remediate_finding", "params": {"finding_key": "F-005"}}],
            ),
            (
                "D2 (Remove zone flow DMZ->App RR-04)",
                [{"kind": "remove_reachability", "params": {"reachability_key": "RR-04"}}],
            ),
            (
                "D3 (Activate WAF CTRL-01 on web-01)",
                [{"kind": "activate_control", "params": {"control_key": "CTRL-01"}}],
            ),
        ]
        print("Defensive action comparisons:")
        for label, actions in action_sets:
            cmp_run = execute_scenario_run(
                db,
                snapshot_id=snap.id,
                scenario_id=sc.id,
                actions=actions,
                created_by="cli-demo",
            )
            comp = cmp_run.result["comparison"]
            print(
                f"  {label}: score {comp['baseline_headline_score']} -> "
                f"{comp['modified_headline_score']} "
                f"(paths {comp['baseline_path_count']} -> {comp['modified_path_count']})"
            )
    return 0


def _cmd_run_retention(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as db:
        summary = run_retention(
            db,
            settings=settings,
            dry_run=not args.apply,
            snapshots_days=args.snapshots_days,
            runs_days=args.runs_days,
            sessions_grace_days=args.sessions_grace_days,
            audit_days=args.audit_days,
            actor="cli:retention",
        )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        mode = "APPLIED" if not summary["dry_run"] else "DRY-RUN"
        c = summary["counts"]
        p = summary["policy_days"]
        print(f"Retention {mode} as of {summary['as_of']}")
        print(
            f"  Policy days: snapshots={p['snapshots']}, runs={p['scenario_runs']}, "
            f"sessions_grace={p['sessions_grace']}, audit_archive={p['audit_archive']}"
        )
        print(
            f"  Sessions: {c['sessions']} purged/eligible | "
            f"Runs: {c['scenario_runs']} | Snapshots: {c['snapshots']} "
            f"(protected by kept runs: {c['snapshots_protected_by_runs']})"
        )
        print(
            f"  Audit events ready for off-host archive: {c['audit_events_ready_for_archive']} "
            "(live chain preserved)"
        )
    return 0


def _cmd_verify_audit() -> int:
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as db:
        res = verify_chain(db)
    if res["valid"]:
        print(f"Audit hash chain OK ({res['checked_count']} event(s) verified).")
        return 0
    print(
        f"Audit hash chain BROKEN at seq={res['first_broken_seq']} "
        f"(checked {res['checked_count']} valid event(s))."
    )
    return 1


def _cmd_create_admin(args: argparse.Namespace) -> int:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: passwords do not match.", file=sys.stderr)
            return 1

    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as db:
        try:
            user = admin_create_user(
                db,
                email=args.email,
                display_name=args.name,
                password=password,
                role="admin",
                actor_email="cli:create-admin",
            )
        except (ValueError, ConflictError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    print(f"Created admin user {user.email} (id={user.id})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chaoslab", description="CHAOS LAB management CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="Run Alembic migrations to initialize the database")
    sub.add_parser("seed-demo", help="Seed synthetic Meridian Freight demo environment and users")
    sub.add_parser(
        "run-demo-scenario",
        help="Run the offline Meridian Freight Orders DB scenario and defensive comparisons",
    )
    admin_p = sub.add_parser(
        "create-admin",
        help="Create an initial or additional administrator user",
    )
    admin_p.add_argument("--email", required=True, help="Administrator email address")
    admin_p.add_argument("--name", required=True, help="Administrator display name")
    admin_p.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the administrator password from standard input instead of prompting",
    )
    ret_p = sub.add_parser(
        "run-retention",
        help="Evaluate (dry-run by default) or apply retention cleanup for expired data",
    )
    ret_p.add_argument(
        "--apply",
        action="store_true",
        help="Delete eligible expired records (without this flag, performs a read-only dry run)",
    )
    ret_p.add_argument("--snapshots-days", type=int, default=None)
    ret_p.add_argument("--runs-days", type=int, default=None)
    ret_p.add_argument("--sessions-grace-days", type=int, default=None)
    ret_p.add_argument("--audit-days", type=int, default=None)
    ret_p.add_argument("--json", action="store_true", help="Print JSON summary for automation")

    sub.add_parser("verify-audit", help="Verify the tamper-evident audit event hash chain")

    args = parser.parse_args(argv)
    if args.command == "init-db":
        return _cmd_init_db()
    if args.command == "seed-demo":
        return _cmd_seed_demo()
    if args.command == "run-demo-scenario":
        return _cmd_run_demo_scenario()
    if args.command == "create-admin":
        return _cmd_create_admin(args)
    if args.command == "run-retention":
        return _cmd_run_retention(args)
    if args.command == "verify-audit":
        return _cmd_verify_audit()
    return 2


if __name__ == "__main__":
    sys.exit(main())
