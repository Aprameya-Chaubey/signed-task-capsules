"""Tests for webhook HMAC verification and governance orchestration."""

from __future__ import annotations

import json
import hashlib
import hmac
from pathlib import Path
from uuid import uuid4
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.ingestion.hmac_verify import verify_hmac
from app.ingestion.webhook import (
    WebhookDependencies,
    extract_raw_text,
    router as webhook_router,
)
from app.models import (
    AuditEvent,
    AuditEventType,
    CompilerOutput,
    GovernancePipelineOutput,
    KnownTools,
    PolicyDecision,
    SessionHistory,
    SignedCapsule,
    TrustTier,
    TrustTierResult,
)


def _signature(raw_body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _issues_payload() -> dict[str, object]:
    return {
        "sender": {"login": "octocat"},
        "repository": {
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo",
        },
        "issue": {
            "number": 42,
            "body": "Fix input validation in app/api.py",
            "html_url": "https://github.com/owner/repo/issues/42",
        },
    }


class FakeCompiler:
    def __init__(self, output: CompilerOutput) -> None:
        self.output = output
        self.calls: list[str] = []

    async def compile(self, raw_text: str) -> CompilerOutput:
        self.calls.append(raw_text)
        return self.output


class FakePolicyEngine:
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.calls: list[tuple[CompilerOutput, TrustTier, str]] = []

    def evaluate(
        self,
        compiler_output: CompilerOutput,
        trust_tier: TrustTier,
        session_history,
        source_hash: str,
    ) -> PolicyDecision:
        _ = session_history
        self.calls.append((compiler_output, trust_tier, source_hash))
        return self.decision


class FakeSigner:
    def __init__(self, capsule: SignedCapsule) -> None:
        self.capsule = capsule
        self.called = False
        self.call_count = 0

    async def sign(self, policy_decision: PolicyDecision) -> SignedCapsule:
        _ = policy_decision
        self.called = True
        self.call_count += 1
        return self.capsule


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def log(self, event: AuditEvent) -> None:
        self.events.append(event)


class FakeSessionTracker:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionHistory] = {}
        self.seen_deliveries: dict[str, bool] = {}

    async def is_duplicate_delivery(self, delivery_id: str | None) -> bool:
        if not delivery_id:
            return False
        if delivery_id in self.seen_deliveries:
            return True
        self.seen_deliveries[delivery_id] = True
        return False

    async def get_or_create(self, thread_id: str) -> SessionHistory:
        session = self.sessions.get(thread_id)
        if session is None:
            session = SessionHistory(thread_id=thread_id)
            self.sessions[thread_id] = session
        return session

    async def record_capsule(self, thread_id: str, capsule: SignedCapsule) -> None:
        _ = (thread_id, capsule)

    async def record_approval(self, thread_id: str) -> None:
        _ = thread_id

    async def persist(self, db_path: str) -> None:
        _ = db_path


def _trust_tier_result() -> TrustTierResult:
    return TrustTierResult(
        author="octocat",
        repo_full_name="owner/repo",
        trust_tier=TrustTier.CONTRIBUTOR,
        github_permission="write",
        resolved_at="2026-08-09T00:00:00Z",
    )


def _compiler_output() -> CompilerOutput:
    return CompilerOutput(
        intent="Fix input validation",
        requested_tools=[KnownTools.READ_FILE, KnownTools.WRITE_FILE],
        target_paths=["app/api.py"],
        compiler_model="test-model",
        compiler_version="1.0.0",
    )


def _issued_capsule() -> SignedCapsule:
    return SignedCapsule(
        capsule_id=str(uuid4()),
        intent="Fix input validation",
        allowed_tools=[KnownTools.READ_FILE],
        target_paths=["app/api.py"],
        trust_tier=TrustTier.CONTRIBUTOR,
        expiry="2030-01-01T00:00:00Z",
        source_hash="a" * 64,
        compiler_version="1.0.0",
        signature="c2ln",
    )


def _build_app(
    secret: str,
    policy_decision: PolicyDecision,
    *,
    capsule: SignedCapsule | None = None,
) -> tuple[FastAPI, FakeCompiler, FakePolicyEngine, FakeSigner, FakeAuditLogger]:
    compiler = FakeCompiler(_compiler_output())
    policy_engine = FakePolicyEngine(policy_decision)
    signer = FakeSigner(capsule or _issued_capsule())
    audit_logger = FakeAuditLogger()
    session_tracker = FakeSessionTracker()

    async def trust_tier_resolver(author: str, repo_full_name: str) -> TrustTierResult:
        assert author == "octocat"
        assert repo_full_name == "owner/repo"
        return _trust_tier_result()

    dependencies = WebhookDependencies(
        settings=Settings(
            GITHUB_WEBHOOK_SECRET=secret,
            DATABASE_PATH=str(Path(".pytest_tmp") / "webhook" / f"{uuid4()}.db"),
            ADMIN_API_TOKEN="admin-secret-token",
        ),
        compiler=compiler,
        policy_engine=policy_engine,
        signer=signer,
        session_tracker=session_tracker,
        audit_logger=audit_logger,
        trust_tier_resolver=trust_tier_resolver,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await dependencies.pending_store.close()

    app = FastAPI(lifespan=lifespan)
    app.state.webhook_dependencies = dependencies
    app.state.settings = dependencies.settings
    app.include_router(webhook_router)
    
    from app.ingestion.approval import router as approval_router
    app.include_router(approval_router)
    
    return app, compiler, policy_engine, signer, audit_logger


def test_verify_hmac_succeeds_with_correct_secret() -> None:
    raw_body = b'{"hello":"world"}'
    secret = "top-secret"
    signature = _signature(raw_body, secret)

    assert verify_hmac(raw_body, signature, secret) is True


def test_webhook_rejects_wrong_hmac_secret() -> None:
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=["app/api.py"],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=False,
        denial_reason=None,
        intent="Fix input validation",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )
    app, _, _, _, _ = _build_app(secret="correct-secret", policy_decision=decision)
    payload = _issues_payload()
    raw_body = json.dumps(payload).encode("utf-8")

    with TestClient(app) as client:
        response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "issues",
                "X-Hub-Signature-256": _signature(
                    raw_body,
                    "wrong-secret",
                ),
            },
        )

    assert response.status_code == 401


def test_webhook_rejects_missing_signature_header() -> None:
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=["app/api.py"],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=False,
        denial_reason=None,
        intent="Fix input validation",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )
    app, _, _, _, _ = _build_app(secret="correct-secret", policy_decision=decision)
    raw_body = json.dumps(_issues_payload()).encode("utf-8")

    with TestClient(app) as client:
        response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "issues",
            },
        )

    assert response.status_code == 401


def test_invalid_signature_is_rejected_before_duplicate_check_consumes_delivery_id() -> None:
    """An unauthenticated request must not be able to pollute or evict the
    duplicate-delivery cache: a bad signature should fail with 401 without
    marking its X-GitHub-Delivery id as seen, and a later legitimate request
    reusing that same id must still be processed normally."""
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=["app/api.py"],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=False,
        denial_reason=None,
        intent="Fix input validation",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )
    app, _, _, _, _ = _build_app(secret="correct-secret", policy_decision=decision)
    raw_body = json.dumps(_issues_payload()).encode("utf-8")
    delivery_id = "550e8400-e29b-41d4-a716-446655440000"

    with TestClient(app) as client:
        forged_response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": delivery_id,
                "X-Hub-Signature-256": _signature(raw_body, "wrong-secret"),
            },
        )
        assert forged_response.status_code == 401

        tracker = app.state.webhook_dependencies.session_tracker
        assert delivery_id not in tracker.seen_deliveries

        genuine_response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": delivery_id,
                "X-Hub-Signature-256": _signature(raw_body, "correct-secret"),
            },
        )

    assert genuine_response.status_code == 200
    parsed = GovernancePipelineOutput.model_validate(genuine_response.json())
    assert parsed.status == "issued"


def test_extract_raw_text_for_supported_events() -> None:
    assert extract_raw_text({"issue": {"body": "issue body"}}, "issues") == "issue body"
    assert (
        extract_raw_text({"pull_request": {"body": "pr body"}}, "pull_request")
        == "pr body"
    )
    assert (
        extract_raw_text({"comment": {"body": "comment body"}}, "issue_comment")
        == "comment body"
    )
    assert (
        extract_raw_text(
            {"comment": {"body": "review body"}},
            "pull_request_review_comment",
        )
        == "review body"
    )
    assert extract_raw_text({}, "fork") == ""


def test_webhook_full_pipeline_issued_with_mocked_dependencies() -> None:
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=["app/api.py"],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=False,
        denial_reason=None,
        intent="Fix input validation",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )
    app, compiler, policy_engine, signer, audit_logger = _build_app(
        secret="correct-secret",
        policy_decision=decision,
    )
    payload = _issues_payload()

    with TestClient(app) as client:
        raw_body = json.dumps(payload).encode("utf-8")
        response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "issues",
                "X-Hub-Signature-256": _signature(raw_body, "correct-secret"),
            },
        )

    assert response.status_code == 200
    parsed = GovernancePipelineOutput.model_validate(response.json())
    assert parsed.status == "issued"
    assert parsed.capsule is not None
    assert parsed.capsule_id == parsed.capsule.capsule_id
    assert compiler.calls == ["Fix input validation in app/api.py"]
    assert len(policy_engine.calls) == 1
    assert signer.called is True
    assert len(audit_logger.events) == 1
    assert audit_logger.events[0].event_type is AuditEventType.CAPSULE_ISSUED


def test_denied_request_returns_denial_reason() -> None:
    decision = PolicyDecision(
        allow=False,
        final_tools=[],
        final_paths=[],
        trust_tier=TrustTier.EXTERNAL,
        require_human_approval=False,
        denial_reason="No requested tools are permitted for the external trust tier.",
        intent="Extract secrets",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )
    app, _, _, signer, audit_logger = _build_app(
        secret="correct-secret",
        policy_decision=decision,
    )
    payload = _issues_payload()

    with TestClient(app) as client:
        raw_body = json.dumps(payload).encode("utf-8")
        response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "issues",
                "X-Hub-Signature-256": _signature(raw_body, "correct-secret"),
            },
        )

    assert response.status_code == 200
    parsed = GovernancePipelineOutput.model_validate(response.json())
    assert parsed.status == "denied"
    assert parsed.denial_reason == decision.denial_reason
    assert parsed.capsule is None
    assert signer.called is False
    assert len(audit_logger.events) == 1
    assert audit_logger.events[0].event_type is AuditEventType.CAPSULE_DENIED
    assert audit_logger.events[0].capsule_id is None


def test_webhook_event_accepts_bot_author() -> None:
    from app.models import WebhookEvent

    event = WebhookEvent(
        event_type="issues",
        raw_text="Bump dependencies",
        author="dependabot[bot]",
        repo_full_name="owner/repo",
        source_url="https://github.com/owner/repo/issues/1",
        raw_payload_hash="a" * 64,
    )

    assert event.author == "dependabot[bot]"


def test_webhook_non_issue_event_uses_delivery_id_for_thread() -> None:
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=["app/api.py"],
        trust_tier=TrustTier.CONTRIBUTOR,
        require_human_approval=False,
        denial_reason=None,
        intent="Fix input validation",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )
    app, _, _, _, _ = _build_app(secret="correct-secret", policy_decision=decision)
    # Using push event (no issue number)
    payload = {
        "sender": {"login": "octocat"},
        "repository": {"full_name": "owner/repo", "html_url": "https://github.com/owner/repo"},
        "commits": [{"message": "Fix input validation"}],
    }
    raw_body = json.dumps(payload).encode("utf-8")

    with TestClient(app) as client:
        response = client.post(
            "/webhook",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Delivery": str(__import__('uuid').uuid4()), "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "550e8400-e29b-41d4-a716-446655440000",
                "X-Hub-Signature-256": _signature(raw_body, "correct-secret"),
            },
        )
    
    assert response.status_code == 200, response.json()

    # Verify thread_id was derived from delivery_id
    dependencies = app.state.webhook_dependencies
    tracker = dependencies.session_tracker
    
    assert "owner/repo#delivery-550e8400-e29b-41d4-a716-446655440000" in tracker.sessions
