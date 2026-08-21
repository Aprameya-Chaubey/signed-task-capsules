"""Shared admin authentication dependency for sensitive endpoints."""

from __future__ import annotations

import hmac
import secrets

from fastapi import Header, HTTPException, Request

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
    authorization: str | None = Header(default=None),
) -> None:
    """Reject requests that do not present the configured admin token.

    The token may be supplied via the ``X-Admin-Token`` header or
    ``Authorization: Bearer <token>`` header. Query parameters are NOT accepted.
    """

    settings = _auth_settings(request)
    if not settings.admin_api_token:
        raise HTTPException(status_code=503, detail="Admin auth not configured")

    token = x_admin_token
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ")

    if not token or not secrets.compare_digest(token, settings.admin_api_token):
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")
