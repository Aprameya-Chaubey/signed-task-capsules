"""Audit log viewer and JSON endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.audit.logger import AuditLogger
from app.auth import require_admin_auth
from app.models import AuditEvent, AuditEventType


router = APIRouter(tags=["audit"])
_templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _short_capsule_id(capsule_id: str | None) -> str:
    """Return a compact, display-safe capsule identifier."""

    if not capsule_id:
        return "—"
    if len(capsule_id) <= 20:
        return capsule_id
    return f"{capsule_id[:8]}...{capsule_id[-8:]}"


def _event_row_class(event_type: AuditEventType) -> str:
    if event_type in {
        AuditEventType.CAPSULE_ISSUED,
        AuditEventType.CAPSULE_APPROVED,
        AuditEventType.TOOL_ALLOWED,
    }:
        return "row-allowed"
    if event_type in {
        AuditEventType.CAPSULE_DENIED,
        AuditEventType.CAPSULE_EXPIRED,
        AuditEventType.TOOL_BLOCKED,
    }:
        return "row-blocked"
    if event_type is AuditEventType.CAPSULE_PENDING:
        return "row-pending"
    return ""


def get_audit_logger(request: Request) -> AuditLogger:
    """Resolve the app-scoped AuditLogger dependency."""

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if not isinstance(audit_logger, AuditLogger):
        raise HTTPException(status_code=503, detail="Audit logger is unavailable")
    return audit_logger


@router.get("/audit", response_class=HTMLResponse)
async def audit_view(
    request: Request,
    capsule_id: str = Query(default="", max_length=128),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    _: None = Depends(require_admin_auth),
) -> HTMLResponse:
    """Render a minimal server-side audit table for demo visibility."""

    normalized_capsule_id = capsule_id.strip() or None
    events = await audit_logger.get_events(limit=100, capsule_id=normalized_capsule_id)
    event_rows = [
        {
            "event": event,
            "row_class": _event_row_class(event.event_type),
            "capsule_short": _short_capsule_id(event.capsule_id),
        }
        for event in events
    ]

    response = _templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "events": event_rows,
            "capsule_id": capsule_id,
            "refresh_seconds": 5,
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/api/audit", response_model=list[AuditEvent])
async def get_audit_events(
    response: Response,
    audit_logger: AuditLogger = Depends(get_audit_logger),
    _: None = Depends(require_admin_auth),
) -> list[AuditEvent]:
    """Return the latest 100 events as structured JSON."""

    response.headers["Cache-Control"] = "no-store"
    return await audit_logger.get_events(limit=100)


@router.get("/api/audit/{capsule_id}", response_model=list[AuditEvent])
async def get_audit_events_for_capsule(
    capsule_id: str,
    response: Response,
    audit_logger: AuditLogger = Depends(get_audit_logger),
    _: None = Depends(require_admin_auth),
) -> list[AuditEvent]:
    """Return all events associated with one capsule ID."""

    response.headers["Cache-Control"] = "no-store"
    return await audit_logger.get_events(limit=0, capsule_id=capsule_id)
