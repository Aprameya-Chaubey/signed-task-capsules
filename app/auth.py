"""Shared admin authentication dependency for sensitive endpoints."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Query, Request

from app.config import Settings, get_settings


def _auth_settings(request: Request) -> Settings:
    """Resolve settings from app state when available, else process settings."""

    candidate = getattr(request.app.state, "settings", None)
    if isinstance(candidate, Settings):
        return candidate
    return get_settings()


async def require_admin_auth(
    request: Request,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
) -> None:
    """Reject requests that do not present the configured admin token.

    The token may be supplied via the ``X-Admin-Token`` header or, for the
    browser-facing audit page, an ``admin_token`` query parameter.
    """

    settings = _auth_settings(request)
    if not settings.admin_api_token:
        raise HTTPException(status_code=503, detail="Admin auth not configured")

    provided = x_admin_token or admin_token or ""
    if not hmac.compare_digest(provided, settings.admin_api_token):
        raise HTTPException(status_code=401, detail="Unauthorized")
