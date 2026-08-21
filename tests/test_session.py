"""Tests for session tracking, persistence, and approval flow."""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.governance.session import SessionTracker
from app.governance.signer import Ed25519Signer
from app.ingestion.approval import router as approval_router
from app.ingestion.webhook import WebhookDependencies
from app.models import (
    AuditEvent,
    AuditEventType,
    CapsuleSummary,
    GovernancePipelineOutput,
    KnownTools,
    PolicyDecision,
    SignedCapsule,
    TrustTier,
)


@pytest.fixture
def workspace_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "session"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def runtime_settings(workspace_tmp_path: Path, *, expiry_hours: int = 1) -> Settings:
    return Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(workspace_tmp_path / "ed25519.key"),
        CAPSULE_EXPIRY_HOURS=expiry_hours,
        DATABASE_PATH=str(workspace_tmp_path / "session.db"),
        ADMIN_API_TOKEN="test-admin-token",
    )


def policy_decision(
    *,
    tools: list[KnownTools],
    paths: list[str],
    tier: TrustTier = TrustTier.CONTRIBUTOR,
) -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        final_tools=tools,
        final_paths=paths,
        trust_tier=tier,
        require_human_approval=False,
        denial_reason=None,
        intent="Session policy test capsule",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )


async def signed_capsule(
    *,
    settings: Settings,
    tools: list[KnownTools],
    paths: list[str],
) -> SignedCapsule:
    signer = Ed25519Signer(settings=settings)
    return await signer.sign(policy_decision(tools=tools, paths=paths))


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def log(self, event: AuditEvent) -> None:
        self.events.append(event)


class DummyCompiler:
    async def compile(self, raw_text: str):
        _ = raw_text
        raise NotImplementedError


class DummyPolicyEngine:
    def evaluate(self, *args, **kwargs):
        _ = (args, kwargs)
        raise NotImplementedError


class DummySigner:
    def __init__(self, capsule=None):
        self.capsule = capsule
    async def sign(self, decision):
        if self.capsule: return self.capsule
        raise NotImplementedError


def test_get_or_create_returns_empty_session_for_new_thread() -> None:
    tracker = SessionTracker()

    session = asyncio.run(tracker.get_or_create("owner/repo#1"))

    assert session.thread_id == "owner/repo#1"
    assert session.recent_capsules == []
    assert session.consecutive_high_scope == 0
    assert session.cumulative_unique_tools == 0
    assert session.last_human_approval_at is None


def test_record_capsule_adds_summary_and_updates_counters(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    tracker = SessionTracker()
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE, KnownTools.WRITE_FILE],
            paths=["src/main.py"],
        )
    )

    asyncio.run(tracker.record_capsule("owner/repo#1", capsule))
    session = asyncio.run(tracker.get_or_create("owner/repo#1"))

    assert len(session.recent_capsules) == 1
    assert session.recent_capsules[0].capsule_id == capsule.capsule_id
    assert session.consecutive_high_scope == 0
    assert session.cumulative_unique_tools == 2


def test_old_capsules_are_pruned_from_recent_history(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    tracker = SessionTracker()
    thread_id = "owner/repo#2"
    session = asyncio.run(tracker.get_or_create(thread_id))

    old_time = (
        datetime.now(timezone.utc) - timedelta(minutes=61)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    session.recent_capsules.append(
        CapsuleSummary(
            capsule_id=str(uuid4()),
            issued_at=old_time,
            trust_tier=TrustTier.CONTRIBUTOR,
            tools_count=1,
            paths_count=1,
        )
    )

    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/main.py"],
        )
    )
    asyncio.run(tracker.record_capsule(thread_id, capsule))

    updated = asyncio.run(tracker.get_or_create(thread_id))
    assert len(updated.recent_capsules) == 1
    assert updated.recent_capsules[0].capsule_id == capsule.capsule_id


def test_consecutive_high_scope_increments_and_resets(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    tracker = SessionTracker()
    thread_id = "owner/repo#3"

    high_one = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE, KnownTools.WRITE_FILE, KnownTools.RUN_TESTS],
            paths=["src/**"],
        )
    )
    high_two = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE, KnownTools.WRITE_FILE, KnownTools.RUN_TESTS],
            paths=["src/**"],
        )
    )
    low_scope = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )

    asyncio.run(tracker.record_capsule(thread_id, high_one))
    asyncio.run(tracker.record_capsule(thread_id, high_two))
    session = asyncio.run(tracker.get_or_create(thread_id))
    assert session.consecutive_high_scope == 2

    asyncio.run(tracker.record_capsule(thread_id, low_scope))
    session = asyncio.run(tracker.get_or_create(thread_id))
    assert session.consecutive_high_scope == 0


def test_cumulative_unique_tools_accumulates_across_capsules(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    tracker = SessionTracker()
    thread_id = "owner/repo#4"

    first = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE, KnownTools.WRITE_FILE],
            paths=["src/**"],
        )
    )
    second = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE, KnownTools.RUN_TESTS],
            paths=["src/**"],
        )
    )

    asyncio.run(tracker.record_capsule(thread_id, first))
    asyncio.run(tracker.record_capsule(thread_id, second))

    session = asyncio.run(tracker.get_or_create(thread_id))
    assert session.cumulative_unique_tools == 3


def test_session_persist_and_load_round_trip(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    thread_id = "owner/repo#5"

    tracker = SessionTracker()
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/main.py"],
        )
    )

    asyncio.run(tracker.record_capsule(thread_id, capsule))
    asyncio.run(tracker.record_approval(thread_id))
    asyncio.run(tracker.persist(settings.database_path))

    loaded_tracker = SessionTracker()
    asyncio.run(loaded_tracker.load(settings.database_path))
    loaded_session = asyncio.run(loaded_tracker.get_or_create(thread_id))

    assert len(loaded_session.recent_capsules) == 1
    assert loaded_session.recent_capsules[0].capsule_id == capsule.capsule_id
    assert loaded_session.cumulative_unique_tools == 1
    assert loaded_session.last_human_approval_at is not None

    # SessionTracker now caches its SQLite connection across persist()/load()
    # calls (see app/governance/session.py); close both explicitly so a
    # lingering open handle can't block Windows' temp-dir cleanup on teardown.
    asyncio.run(tracker.close())
    asyncio.run(loaded_tracker.close())


def test_approval_endpoint_returns_200_and_updates_session_state(
    workspace_tmp_path: Path,
) -> None:
    settings = runtime_settings(workspace_tmp_path)
    tracker = SessionTracker()
    thread_id = SessionTracker.compute_thread_id("owner/repo", 42)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/main.py"],
        )
    )

    audit_logger = FakeAuditLogger()

    async def trust_tier_resolver(author: str, repo_full_name: str):
        _ = (author, repo_full_name)
        raise NotImplementedError

    dependencies = WebhookDependencies(
        settings=settings,
        compiler=DummyCompiler(),
        policy_engine=DummyPolicyEngine(),
        signer=DummySigner(capsule),
        session_tracker=tracker,
        audit_logger=audit_logger,
        trust_tier_resolver=trust_tier_resolver,
    )
    asyncio.run(dependencies.pending_store.init_db())
    pd_json = """{"allow": true, "final_tools": ["read_file"], "final_paths": ["src/main.py"], "trust_tier": "contributor", "require_human_approval": true, "denial_reason": null, "intent": "test", "source_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "compiler_version": "1.0.0", "allowed_hosts": []}"""
    asyncio.run(dependencies.pending_store.add_pending(capsule.capsule_id, pd_json, thread_id))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await dependencies.pending_store.close()

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.webhook_dependencies = dependencies
    app.include_router(approval_router)

    with TestClient(app) as client:
        response = client.post(
            f"/capsules/{capsule.capsule_id}/approve",
            headers={"X-Admin-Token": settings.admin_api_token},
        )
    
        assert response.status_code == 200
        parsed = GovernancePipelineOutput.model_validate(response.json())
        assert parsed.status == "issued"
        assert parsed.capsule is not None
        assert parsed.capsule_id == capsule.capsule_id
        stored = asyncio.run(dependencies.pending_store.get(capsule.capsule_id))
        assert stored is not None
        assert stored.status == "approved"

        session = asyncio.run(tracker.get_or_create(thread_id))
        assert session.last_human_approval_at is not None
        assert len(session.recent_capsules) == 1
        assert audit_logger.events
        assert audit_logger.events[0].event_type is AuditEventType.CAPSULE_APPROVED

    # The /approve endpoint calls tracker.persist(), which now caches a
    # SQLite connection (see app/governance/session.py); close it explicitly
    # so a lingering open handle can't block Windows' temp-dir cleanup.
    asyncio.run(tracker.close())


def _approval_app(
    workspace_tmp_path: Path,
) -> tuple[TestClient, WebhookDependencies, SignedCapsule, str, Settings]:
    settings = runtime_settings(workspace_tmp_path)
    tracker = SessionTracker()
    thread_id = SessionTracker.compute_thread_id("owner/repo", 7)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/main.py"],
        )
    )

    async def trust_tier_resolver(author: str, repo_full_name: str):
        _ = (author, repo_full_name)
        raise NotImplementedError

    dependencies = WebhookDependencies(
        settings=settings,
        compiler=DummyCompiler(),
        policy_engine=DummyPolicyEngine(),
        signer=DummySigner(capsule),
        session_tracker=tracker,
        audit_logger=FakeAuditLogger(),
        trust_tier_resolver=trust_tier_resolver,
    )
    asyncio.run(dependencies.pending_store.init_db())
    pd_json = """{"allow": true, "final_tools": ["read_file"], "final_paths": ["src/main.py"], "trust_tier": "contributor", "require_human_approval": true, "denial_reason": null, "intent": "test", "source_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "compiler_version": "1.0.0", "allowed_hosts": []}"""
    asyncio.run(dependencies.pending_store.add_pending(capsule.capsule_id, pd_json, thread_id))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await dependencies.pending_store.close()

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.webhook_dependencies = dependencies
    app.include_router(approval_router)
    return TestClient(app), dependencies, capsule, thread_id, settings


def test_approval_endpoint_rejects_missing_admin_token(workspace_tmp_path: Path) -> None:
    client, _, capsule, _, _ = _approval_app(workspace_tmp_path)

    with client:
        response = client.post(f"/capsules/{capsule.capsule_id}/approve")

    assert response.status_code == 401


def test_reject_endpoint_marks_capsule_rejected(workspace_tmp_path: Path) -> None:
    client, dependencies, capsule, _, settings = _approval_app(workspace_tmp_path)

    with client:
        response = client.post(
            f"/capsules/{capsule.capsule_id}/reject",
            headers={"X-Admin-Token": settings.admin_api_token},
        )

        assert response.status_code == 200
        parsed = GovernancePipelineOutput.model_validate(response.json())
        assert parsed.status == "denied"
        assert parsed.capsule is None

        stored = asyncio.run(dependencies.pending_store.get_pending(capsule.capsule_id))
        assert stored is not None
        assert stored["status"] == "rejected"

        events = dependencies.audit_logger.events
        assert events
        assert events[0].event_type is AuditEventType.CAPSULE_DENIED


def test_admin_auth_returns_503_when_token_not_configured(workspace_tmp_path: Path) -> None:
    settings = Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(workspace_tmp_path / "ed25519.key"),
        DATABASE_PATH=str(workspace_tmp_path / "session.db"),
    )
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/main.py"],
        )
    )

    async def trust_tier_resolver(author: str, repo_full_name: str):
        _ = (author, repo_full_name)
        raise NotImplementedError

    dependencies = WebhookDependencies(
        settings=settings,
        compiler=DummyCompiler(),
        policy_engine=DummyPolicyEngine(),
        signer=DummySigner(capsule),
        session_tracker=SessionTracker(),
        audit_logger=FakeAuditLogger(),
        trust_tier_resolver=trust_tier_resolver,
    )
    asyncio.run(dependencies.pending_store.init_db())
    asyncio.run(dependencies.pending_store.record_issued(capsule, "owner/repo#7"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await dependencies.pending_store.close()

    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.state.webhook_dependencies = dependencies
    app.include_router(approval_router)

    with TestClient(app) as client:
        response = client.post(
            f"/capsules/{capsule.capsule_id}/approve",
            headers={"X-Admin-Token": "anything"},
        )

    assert response.status_code == 503


def test_approval_endpoint_rejects_double_approval(workspace_tmp_path: Path) -> None:
    client, dependencies, capsule, _, settings = _approval_app(workspace_tmp_path)

    with client:
        # First approval
        response1 = client.post(
            f"/capsules/{capsule.capsule_id}/approve",
            headers={"X-Admin-Token": settings.admin_api_token},
        )
        assert response1.status_code == 200

        # Second approval
        response2 = client.post(
            f"/capsules/{capsule.capsule_id}/approve",
            headers={"X-Admin-Token": settings.admin_api_token},
        )
        assert response2.status_code == 409
        assert "already resolved" in response2.json()["detail"]
