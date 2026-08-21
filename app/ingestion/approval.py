"""Endpoints for human approval of pending capsules."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.auth import require_admin_auth
from app.ingestion.webhook import WebhookDependencies, get_webhook_dependencies
from app.models import AuditEvent, AuditEventType, GovernancePipelineOutput, PolicyDecision


logger = logging.getLogger(__name__)
router = APIRouter(tags=["approval"])


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

    policy_decision = PolicyDecision.model_validate_json(pending_data["policy_decision"])
    
    # Sign the capsule now!
    signed_capsule = await dependencies.signer.sign(policy_decision)

    # Atomically mark resolved AND record issued
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

    from app.models import PolicyDecision
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
