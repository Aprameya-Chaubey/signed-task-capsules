"""Endpoints for human approval of pending capsules."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.auth import require_admin_auth
from app.governance.session import SessionTracker
from app.ingestion.webhook import WebhookDependencies, get_webhook_dependencies
from app.models import AuditEvent, AuditEventType, GovernancePipelineOutput, PolicyDecision


logger = logging.getLogger(__name__)
router = APIRouter(tags=["approval"])


def get_session_tracker(request: Request) -> SessionTracker:
    """Resolve the app-scoped SessionTracker dependency."""
    tracker = getattr(request.app.state, "session_tracker", None)
    if not isinstance(tracker, SessionTracker):
        raise HTTPException(status_code=503, detail="Session tracker is unavailable")
    return tracker


@router.post("/capsules/{capsule_id}/approve", response_model=GovernancePipelineOutput)
async def approve_capsule(
    capsule_id: str,
    dependencies: WebhookDependencies = Depends(get_webhook_dependencies),
    _: None = Depends(require_admin_auth),
) -> GovernancePipelineOutput:
    """Approve one pending capsule and mark it as issued."""

    pending_data = await dependencies.pending_store.get_pending(capsule_id)
    if pending_data is None:
        raise HTTPException(status_code=404, detail="Pending approval not found")
    if pending_data["status"] != "pending":
        raise HTTPException(status_code=409, detail="Pending approval already resolved")

    # Atomically claim the pending record before signing to prevent race conditions
    claim = await dependencies.pending_store.try_claim_pending(capsule_id)
    if not claim:
        raise HTTPException(status_code=409, detail="Pending approval already resolved")

    policy_decision = PolicyDecision.model_validate_json(pending_data["policy_decision"])
    
    # Sign the capsule now that we have exclusive claim
    signed_capsule = await dependencies.signer.sign(policy_decision)

    # Record issued AND mark resolved atomically
    success = await dependencies.pending_store.record_issued_and_resolve(
        capsule_id, signed_capsule, pending_data["thread_id"]
    )
    if not success:
        raise HTTPException(status_code=409, detail="Pending approval already resolved")

    await dependencies.session_tracker.record_approval(pending_data["thread_id"])
    await dependencies.session_tracker.record_capsule(pending_data["thread_id"], signed_capsule)
    await dependencies.session_tracker.persist(dependencies.settings.database_path)

    await dependencies.audit_logger.log(
        AuditEvent(
            capsule_id=signed_capsule.capsule_id,
            event_type=AuditEventType.CAPSULE_APPROVED,
            trust_tier=signed_capsule.trust_tier,
            detail="Human approval granted",
        )
    )

    return GovernancePipelineOutput(
        capsule_id=signed_capsule.capsule_id,
        status="issued",
        capsule=signed_capsule,
    )


@router.post("/capsules/{capsule_id}/reject", response_model=GovernancePipelineOutput)
async def reject_capsule(
    capsule_id: str,
    dependencies: WebhookDependencies = Depends(get_webhook_dependencies),
    _: None = Depends(require_admin_auth),
) -> GovernancePipelineOutput:
    """Reject one pending capsule and record the denial."""

    pending_data = await dependencies.pending_store.get_pending(capsule_id)
    if pending_data is None:
        raise HTTPException(status_code=404, detail="Pending approval not found")
    if pending_data["status"] != "pending":
        raise HTTPException(status_code=409, detail="Pending approval already resolved")

    success = await dependencies.pending_store.resolve_approval(capsule_id, "rejected")
    if not success:
        raise HTTPException(status_code=409, detail="Pending approval already resolved")

    policy_decision = PolicyDecision.model_validate_json(pending_data["policy_decision"])

    await dependencies.audit_logger.log(
        AuditEvent(
            capsule_id=capsule_id,
            event_type=AuditEventType.CAPSULE_DENIED,
            trust_tier=policy_decision.trust_tier,
            detail="Human approval rejected",
        )
    )

    return GovernancePipelineOutput(
        capsule_id=None,
        status="denied",
        denial_reason="Human approval rejected",
        capsule=None,
    )


@router.delete("/sessions")
async def reset_session(
    request: Request,
    thread_id: str,
    tracker: SessionTracker = Depends(get_session_tracker),
    _: None = Depends(require_admin_auth),
) -> JSONResponse:
    """Clear the in-memory session history for one thread (demo / test utility).

    Pass the thread ID as a query parameter, e.g.::

        DELETE /sessions?thread_id=owner%2Frepo%231

    This endpoint only resets the in-memory escalation counters that live in
    ``SessionTracker``.  The caller should also wipe the relevant SQLite rows
    (``session_history``, ``session_tools``) if a full clean-room reset is
    required.
    """
    async with tracker._lock:
        tracker._sessions.pop(thread_id, None)
        tracker._unique_tools.pop(thread_id, None)
        tracker._dirty_threads.discard(thread_id)

    logger.info("In-memory session reset for thread %r", thread_id)
    return JSONResponse({"thread_id": thread_id, "reset": True})
