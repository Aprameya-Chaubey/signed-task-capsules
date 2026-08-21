"""Deterministic GitHub-permission to trust-tier resolution."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from app.ingestion.github_client import GitHubClient
from app.models import TrustTier, TrustTierResult


logger = logging.getLogger(__name__)

PERMISSION_TO_TIER: dict[str, TrustTier] = {
    "admin": TrustTier.MAINTAINER,
    "maintain": TrustTier.MAINTAINER,
    "write": TrustTier.CONTRIBUTOR,
    "triage": TrustTier.EXTERNAL,
    "read": TrustTier.EXTERNAL,
    "none": TrustTier.EXTERNAL,
}

_KNOWN_PERMISSIONS = frozenset(PERMISSION_TO_TIER)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fallback_result(author: str, repo_full_name: str) -> TrustTierResult:
    return TrustTierResult(
        author=author,
        repo_full_name=repo_full_name,
        trust_tier=TrustTier.EXTERNAL,
        github_permission="none",
        resolved_at=_utc_now(),
    )


async def resolve_trust_tier(author: str, repo_full_name: str) -> TrustTierResult:
    """Resolve a GitHub collaborator permission into a deterministic trust tier.

    This function intentionally accepts only GitHub identity data. It never receives
    webhook text, so untrusted issue or comment content cannot influence the tier.
    """

    client = GitHubClient()
    try:
        permission = await asyncio.to_thread(
            client.get_collaborator_permission, repo_full_name, author
        )
        normalized_permission = permission.lower()
    except Exception as exc:  # All lookup failures must fail closed.
        logger.warning(
            "Unable to resolve GitHub permission for %s in %s; using external tier: %s",
            author,
            repo_full_name,
            exc,
        )
        return _fallback_result(author, repo_full_name)

    if normalized_permission not in _KNOWN_PERMISSIONS:
        logger.warning(
            "Unrecognized GitHub permission %r for %s in %s; using external tier",
            permission,
            author,
            repo_full_name,
        )
        return _fallback_result(author, repo_full_name)

    return TrustTierResult(
        author=author,
        repo_full_name=repo_full_name,
        trust_tier=PERMISSION_TO_TIER[normalized_permission],
        github_permission=normalized_permission,
        resolved_at=_utc_now(),
    )
