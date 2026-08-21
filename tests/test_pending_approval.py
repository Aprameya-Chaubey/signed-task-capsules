import pytest
import json
import asyncio
from uuid import uuid4
from fastapi.testclient import TestClient
from app.models import PolicyDecision, KnownTools, TrustTier, SignedCapsule
from tests.test_webhook import _build_app, _issues_payload, _signature

@pytest.mark.asyncio
async def test_pending_approval_does_not_sign_initially():
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=['app/api.py'],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=True,
        denial_reason=None,
        intent='Fix input validation',
        source_hash='a' * 64,
        compiler_version='1.0.0',
    )
    app, _, _, signer, audit_logger = _build_app(
        secret='correct-secret',
        policy_decision=decision,
    )
    payload = _issues_payload()

    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        raw_body = json.dumps(payload).encode('utf-8')
        response = await client.post(
            '/webhook',
            content=raw_body,
            headers={
                'Content-Type': 'application/json',
                'X-GitHub-Event': 'issues',
                'X-Hub-Signature-256': _signature(raw_body, 'correct-secret'),
            },
        )

        assert response.status_code == 200
        parsed = response.json()
        assert parsed['status'] == 'pending_approval'
        
        # Assert signer was NOT called
        assert signer.called is False
        
        # Assert pending event was logged
        assert len(audit_logger.events) == 1
        assert audit_logger.events[0].event_type.value == 'capsule_pending'
        
        pending_id = parsed['capsule_id']
        
        # Assert pending_capsules table contains no capsule for this request
        assert pending_id is not None
        capsule_in_db = await app.state.webhook_dependencies.pending_store.get(pending_id)
        assert capsule_in_db is None

        # Call approve endpoint
        approve_resp = await client.post(
            f"/capsules/{pending_id}/approve",
            headers={"X-Admin-Token": "admin-secret-token"}
        )
        assert approve_resp.status_code == 200
        approve_parsed = approve_resp.json()
        assert approve_parsed["status"] == "issued"
        issued_capsule_id = approve_parsed["capsule_id"]
        
    # Assert signer was called exactly once
    assert signer.call_count == 1
    
    # Assert capsule is persisted with status approved
    capsule_in_db = await app.state.webhook_dependencies.pending_store.get(issued_capsule_id)
    assert capsule_in_db is not None
    assert capsule_in_db.status == "approved"
    
    # Assert audit log
    assert len(audit_logger.events) == 2
    assert audit_logger.events[1].event_type.value == 'capsule_approved'

@pytest.mark.asyncio
async def test_concurrent_double_approval_prevents_multiple_issuance():
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=['app/api.py'],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=True,
        denial_reason=None,
        intent='Fix input validation',
        source_hash='a' * 64,
        compiler_version='1.0.0',
    )
    app, _, _, signer, audit_logger = _build_app(
        secret='correct-secret',
        policy_decision=decision,
    )
    
    # Seed the pending store
    import uuid
    pending_id = str(uuid.uuid4())
    await app.state.webhook_dependencies.pending_store.add_pending(pending_id, decision.model_dump_json(), "org/repo#123")
    
    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Fire two concurrent approvals
        req1 = client.post(f"/capsules/{pending_id}/approve", headers={"X-Admin-Token": "admin-secret-token"})
        req2 = client.post(f"/capsules/{pending_id}/approve", headers={"X-Admin-Token": "admin-secret-token"})
        
        res1, res2 = await asyncio.gather(req1, req2)
        
        statuses = [res1.status_code, res2.status_code]
        assert 200 in statuses
        assert 409 in statuses
        assert statuses.count(200) == 1
        assert statuses.count(409) == 1
        
    assert signer.call_count in (1, 2)
    
@pytest.mark.asyncio
async def test_sequential_double_approval_fails():
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=['app/api.py'],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=True,
        denial_reason=None,
        intent='Fix input validation',
        source_hash='a' * 64,
        compiler_version='1.0.0',
    )
    app, _, _, signer, audit_logger = _build_app(
        secret='correct-secret',
        policy_decision=decision,
    )
    
    import uuid
    pending_id = str(uuid.uuid4())
    await app.state.webhook_dependencies.pending_store.add_pending(pending_id, decision.model_dump_json(), "org/repo#123")
    
    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res1 = await client.post(f"/capsules/{pending_id}/approve", headers={"X-Admin-Token": "admin-secret-token"})
        assert res1.status_code == 200
        
        res2 = await client.post(f"/capsules/{pending_id}/approve", headers={"X-Admin-Token": "admin-secret-token"})
        assert res2.status_code == 409
        
@pytest.mark.asyncio
async def test_rejection_then_approval_fails():
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=['app/api.py'],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=True,
        denial_reason=None,
        intent='Fix input validation',
        source_hash='a' * 64,
        compiler_version='1.0.0',
    )
    app, _, _, signer, audit_logger = _build_app(
        secret='correct-secret',
        policy_decision=decision,
    )
    
    import uuid
    pending_id = str(uuid.uuid4())
    await app.state.webhook_dependencies.pending_store.add_pending(pending_id, decision.model_dump_json(), "org/repo#123")
    
    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res1 = await client.post(f"/capsules/{pending_id}/reject", headers={"X-Admin-Token": "admin-secret-token"})
        assert res1.status_code == 200
        
        res2 = await client.post(f"/capsules/{pending_id}/approve", headers={"X-Admin-Token": "admin-secret-token"})
        assert res2.status_code == 409
        
        assert signer.call_count == 0
        
@pytest.mark.asyncio
async def test_approve_nonexistent_or_unauthorized():
    app, _, _, signer, audit_logger = _build_app(
        secret='correct-secret',
        policy_decision=None,
    )
    
    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Nonexistent
        res1 = await client.post("/capsules/nonexistent-id/approve", headers={"X-Admin-Token": "admin-secret-token"})
        assert res1.status_code == 404
        
        # Unauthorized
        res2 = await client.post("/capsules/nonexistent-id/approve", headers={"X-Admin-Token": "wrong-token"})
        assert res2.status_code == 401
