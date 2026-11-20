"""Scenario run report preview and audited export endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from chaoslab.api.schemas import ReportExportRequest, ReportPreviewResponse
from chaoslab.auth.dependencies import require
from chaoslab.auth.models import User
from chaoslab.auth.permissions import Permission
from chaoslab.db.session import get_db
from chaoslab.reporting import service as rep_svc

router = APIRouter(tags=["reports"])

HTML_REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


@router.get("/runs/{run_id}/report", response_model=ReportPreviewResponse)
def get_run_report_preview(
    run_id: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require(Permission.REPORTS_READ))],
) -> ReportPreviewResponse:
    try:
        ctx = rep_svc.build_report_context(db, run_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    markdown = rep_svc.render_markdown_report(ctx)
    return ReportPreviewResponse(
        result_kind=ctx["result_kind"],
        disclaimer=ctx["disclaimer"],
        run_id=ctx["run"]["id"],
        environment_id=ctx["environment"]["id"],
        environment_name=ctx["environment"]["name"],
        snapshot_id=ctx["snapshot"]["id"],
        snapshot_label=ctx["snapshot"]["label"],
        snapshot_sha256=ctx["snapshot"]["sha256"],
        scenario_name=ctx["run"]["scenario_name"],
        result_sha256=ctx["run"]["result_sha256"],
        evidence_count=len(ctx["evidence"]),
        limitations=ctx["limitations"],
        markdown=markdown,
    )


@router.post("/runs/{run_id}/report/export")
def export_run_report_endpoint(
    run_id: str,
    payload: ReportExportRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require(Permission.REPORTS_EXPORT))],
) -> Response:
    try:
        content, media_type, filename, report_sha256 = rep_svc.export_run_report(
            db,
            run_id=run_id,
            fmt=payload.format,
            actor_user_id=user.id,
            actor_email=user.email,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
        "X-Report-SHA256": report_sha256,
    }
    if payload.format == "html":
        headers["Content-Security-Policy"] = HTML_REPORT_CSP

    return Response(content=content, media_type=media_type, headers=headers)
