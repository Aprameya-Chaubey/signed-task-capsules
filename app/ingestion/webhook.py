"""Webhook ingestion router and governance pipeline orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import ValidationError

from app.audit.logger import AuditLogger
from app.config import Settings
from app.governance.compiler import TaskCompiler
from app.governance.policy import PolicyEngine
from app.governance.session import SessionTracker
from app.governance.signer import CapsuleSigner
from app.ingestion.github_client import GitHubClient
from app.ingestion.hmac_verify import verify_hmac
from app.ingestion.trust_tier import resolve_trust_tier
from app.pending_store import PendingCapsuleStore
from app.models import (
    AuditEvent,
    AuditEventType,
    GovernancePipelineOutput,
    PolicyDecision,
    TrustTierResult,
    WebhookEvent,
)


logger = logging.getLogger(__name__)
router = APIRouter(tags=["webhook"])

TrustTierResolver = Callable[[str, str], Awaitable[TrustTierResult]]
ApprovalRequester = Callable[[dict[str, Any], PolicyDecision, str, Settings], Awaitable[None]]


@dataclass(slots=True)
class WebhookDependencies:
    """All externally managed webhook pipeline dependencies."""

    settings: Settings
    compiler: TaskCompiler
    policy_engine: PolicyEngine
    signer: CapsuleSigner
    session_tracker: SessionTracker
    audit_logger: AuditLogger
    trust_tier_resolver: TrustTierResolver = resolve_trust_tier
    approval_requester: ApprovalRequester | None = None
    pending_store: PendingCapsuleStore | None = None

    def __post_init__(self) -> None:
        if self.approval_requester is None:
            self.approval_requester = _post_human_approval_comment
        if self.pending_store is None:
            self.pending_store = PendingCapsuleStore(self.settings.database_path)


def get_webhook_dependencies(request: Request) -> WebhookDependencies:
    """Resolve app-scoped pipeline dependencies."""

    dependencies = getattr(request.app.state, "webhook_dependencies", None)
    if not isinstance(dependencies, WebhookDependencies):
        raise HTTPException(status_code=503, detail="Webhook dependencies are unavailable")
    return dependencies


def extract_raw_text(payload: dict[str, Any], event_type: str) -> str:
    """Extract the relevant body text from a GitHub webhook payload."""

    if event_type == "issues":
        return str(payload.get("issue", {}).get("body") or "")
    if event_type == "pull_request":
        return str(payload.get("pull_request", {}).get("body") or "")
    if event_type in {"issue_comment", "pull_request_review_comment"}:
        return str(payload.get("comment", {}).get("body") or "")
    return ""


def _extract_issue_number(payload: dict[str, Any]) -> int | None:
    for key in ("issue", "pull_request"):
        candidate = payload.get(key, {}).get("number")
        if isinstance(candidate, int) and candidate >= 0:
            return candidate
    return None


def _extract_source_url(payload: dict[str, Any], event_type: str, repo_full_name: str) -> str:
    if event_type == "issues":
        source = payload.get("issue", {}).get("html_url")
    elif event_type == "pull_request":
        source = payload.get("pull_request", {}).get("html_url")
    elif event_type in {"issue_comment", "pull_request_review_comment"}:
        source = payload.get("comment", {}).get("html_url")
    else:
        source = None

    if isinstance(source, str) and source:
        return source

    repository_url = payload.get("repository", {}).get("html_url")
    if isinstance(repository_url, str) and repository_url:
        return repository_url

    return f"https://github.com/{repo_full_name}"


def _extract_thread_id(payload: dict[str, Any], repo_full_name: str, delivery_id: str | None) -> str:
    issue_number = _extract_issue_number(payload)
    if issue_number is not None:
        return f"{repo_full_name}#{issue_number}"
    
    if delivery_id:
        # Validate as UUID
        if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", delivery_id):
            return f"{repo_full_name}#delivery-{delivery_id}"
    
    raise ValueError(f"Invalid or missing delivery ID for non-issue event: {delivery_id}")


async def _post_human_approval_comment(
    payload: dict[str, Any],
    policy_decision: PolicyDecision,
    pending_id: str,
    settings: Settings,
) -> None:
    """Post a best-effort GitHub comment requesting human capsule approval."""

    repo_full_name = payload.get("repository", {}).get("full_name")
    issue_number = _extract_issue_number(payload)

    if not isinstance(repo_full_name, str) or not repo_full_name or issue_number is None:
        return

    comment_body = (
        "Governance requires human approval before this capsule can be issued. "
        f"Pending ID: {pending_id}. "
        f"Intent: {policy_decision.intent}."
    )

    try:
        await asyncio.to_thread(
            GitHubClient(settings).post_issue_comment,
            repo_full_name,
            issue_number,
            comment_body,
        )
    except Exception as exc:
        logger.warning(
            "Failed to post human-approval comment for %s#%s: %s",
            repo_full_name,
            issue_number,
            exc,
        )


def _as_non_empty_text(candidate: Any, fallback: str) -> str:
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()
    return fallback


def _build_webhook_event(
    payload: dict[str, Any],
    event_type: str,
    raw_text: str,
    raw_payload_hash: str,
) -> WebhookEvent:
    repository = payload.get("repository", {})
    sender = payload.get("sender", {})

    repo_full_name = _as_non_empty_text(repository.get("full_name"), "unknown/unknown")
    author = _as_non_empty_text(sender.get("login"), "unknown")
    source_url = _extract_source_url(payload, event_type, repo_full_name)

    return WebhookEvent(
        event_type=event_type,
        raw_text=raw_text,
        author=author,
        repo_full_name=repo_full_name,
        source_url=source_url,
        raw_payload_hash=raw_payload_hash,
    )


@router.post("/webhook", response_model=GovernancePipelineOutput)
async def webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    dependencies: WebhookDependencies = Depends(get_webhook_dependencies),
) -> GovernancePipelineOutput:
    """Receive a GitHub webhook and run the full governance pipeline."""

    raw_body = await request.body()

    # Authenticate before anything else touches shared state (e.g. the
    # duplicate-delivery cache), so an unauthenticated caller can't use
    # arbitrary X-GitHub-Delivery values to pollute or evict it.
    if not verify_hmac(
        raw_body=raw_body,
        signature_header=x_hub_signature_256 or "",
        secret=dependencies.settings.github_webhook_secret,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    if await dependencies.session_tracker.is_duplicate_delivery(x_github_delivery):
        return GovernancePipelineOutput(
            capsule_id=None,
            status="denied",
            denial_reason="Duplicate webhook delivery",
            capsule=None,
        )

    try:
        decoded_payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if not isinstance(decoded_payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object")

    event_type = (x_github_event or "").strip()
    raw_text = extract_raw_text(decoded_payload, event_type)
    raw_payload_hash = hashlib.sha256(raw_body).hexdigest()
    source_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    try:
        webhook_event = _build_webhook_event(
            payload=decoded_payload,
            event_type=event_type,
            raw_text=raw_text,
            raw_payload_hash=raw_payload_hash,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook payload: {exc}") from exc

    trust_tier_result, compiler_output = await asyncio.gather(
        dependencies.trust_tier_resolver(
            webhook_event.author,
            webhook_event.repo_full_name,
        ),
        dependencies.compiler.compile(webhook_event.raw_text),
    )

    thread_id = _extract_thread_id(decoded_payload, webhook_event.repo_full_name, x_github_delivery)
    session_history = await dependencies.session_tracker.get_or_create(thread_id)

    policy_decision = dependencies.policy_engine.evaluate(
        compiler_output=compiler_output,
        trust_tier=trust_tier_result.trust_tier,
        session_history=session_history,
        source_hash=source_hash,
    )

    if not policy_decision.allow:
        await dependencies.audit_logger.log(
            AuditEvent(
                capsule_id=None,
                event_type=AuditEventType.CAPSULE_DENIED,
                trust_tier=policy_decision.trust_tier,
                detail=policy_decision.denial_reason,
            )
        )
        return GovernancePipelineOutput(
            capsule_id=None,
            status="denied",
            denial_reason=policy_decision.denial_reason,
            capsule=None,
        )

    if policy_decision.require_human_approval:
        pending_id = str(uuid.uuid4())
        await dependencies.pending_store.add_pending(
            pending_id, policy_decision.model_dump_json(), thread_id
        )
        await dependencies.approval_requester(
            decoded_payload,
            policy_decision,
            pending_id,
            dependencies.settings,
        )
        await dependencies.audit_logger.log(
            AuditEvent(
                capsule_id=pending_id,
                event_type=AuditEventType.CAPSULE_PENDING,
                trust_tier=policy_decision.trust_tier,
                detail="Human approval required before issuance",
            )
        )
        return GovernancePipelineOutput(
            capsule_id=pending_id,
            status="pending_approval",
            capsule=None,
        )

    signed_capsule = await dependencies.signer.sign(policy_decision)
    await dependencies.session_tracker.record_capsule(thread_id, signed_capsule)
    await dependencies.session_tracker.persist(dependencies.settings.database_path)
    await dependencies.pending_store.record_issued(signed_capsule, thread_id)

    await dependencies.audit_logger.log(
        AuditEvent(
            capsule_id=signed_capsule.capsule_id,
            event_type=AuditEventType.CAPSULE_ISSUED,
            trust_tier=policy_decision.trust_tier,
        )
    )
    return GovernancePipelineOutput(
        capsule_id=signed_capsule.capsule_id,
        status="issued",
        capsule=signed_capsule,
    )
