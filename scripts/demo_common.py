"""Shared helpers for deterministic local demo scenarios."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.governance.policy import PolicyEngine
from app.governance.session import SessionTracker
from app.governance.signer import Ed25519Signer
from app.ingestion.approval import router as approval_router
from app.ingestion.webhook import WebhookDependencies, router as webhook_router
from app.models import AuditEvent, CompilerOutput, TrustTier, TrustTierResult


@dataclass(slots=True)
class DemoContext:
    """Runtime handles used by scenario scripts."""

    app: FastAPI
    dependencies: WebhookDependencies
    compiler: "SequenceCompiler"
    audit_logger: "InMemoryAuditLogger"
    settings: Settings
    secret: str


class InMemoryAuditLogger:
    """Collect audit events without touching SQLite during demos."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def log(self, event: AuditEvent) -> None:
        self.events.append(event)


class SequenceCompiler:
    """Return predefined compiler outputs in call order."""

    def __init__(self, outputs: list[CompilerOutput]) -> None:
        if not outputs:
            raise ValueError("outputs must contain at least one compiler payload")
        self._outputs = outputs
        self.calls: list[str] = []
        self._index = 0

    async def compile(self, raw_text: str) -> CompilerOutput:
        self.calls.append(raw_text)
        index = min(self._index, len(self._outputs) - 1)
        self._index += 1
        return self._outputs[index]


def issue_payload(
    body: str,
    *,
    issue_number: int,
    repo_full_name: str = "owner/repo",
    author: str = "attacker",
) -> dict[str, Any]:
    """Build a minimal GitHub issues-style webhook payload."""

    return {
        "sender": {"login": author},
        "repository": {
            "full_name": repo_full_name,
            "html_url": f"https://github.com/{repo_full_name}",
        },
        "issue": {
            "number": issue_number,
            "body": body,
            "html_url": f"https://github.com/{repo_full_name}/issues/{issue_number}",
        },
    }


def _signature(raw_body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def post_webhook(
    client: TestClient,
    *,
    payload: dict[str, Any],
    event_type: str,
    secret: str,
):
    """Send a signed webhook request using raw body bytes."""

    raw_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return client.post(
        "/webhook",
        content=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": event_type,
            "X-Hub-Signature-256": _signature(raw_body, secret),
        },
    )


async def _noop_approval_requester(
    payload: dict[str, Any],
    policy_decision,
    pending_id: str,
    settings: Settings,
) -> None:
    _ = (payload, policy_decision, pending_id, settings)


def _runtime_dir(work_dir: Path | None) -> Path:
    if work_dir is not None:
        work_dir.mkdir(parents=True, exist_ok=True)
        return work_dir

    generated = Path(".pytest_tmp") / "demo-runtime" / str(uuid4())
    generated.mkdir(parents=True, exist_ok=False)
    return generated


def build_demo_app(
    compiler_outputs: list[CompilerOutput],
    *,
    secret: str = "demo-secret",
    trust_tier: TrustTier = TrustTier.EXTERNAL,
    repo_full_name: str = "owner/repo",
    author: str = "attacker",
    work_dir: Path | None = None,
) -> DemoContext:
    """Construct a deterministic app instance for one scripted scenario."""

    runtime_dir = _runtime_dir(work_dir)
    settings = Settings(
        GITHUB_WEBHOOK_SECRET=secret,
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(runtime_dir / "ed25519.key"),
        DATABASE_PATH=str(runtime_dir / "demo.db"),
        CAPSULE_EXPIRY_HOURS=1,
    )

    compiler = SequenceCompiler(compiler_outputs)
    policy_engine = PolicyEngine()
    signer = Ed25519Signer(settings=settings)
    session_tracker = SessionTracker()
    audit_logger = InMemoryAuditLogger()

    async def trust_tier_resolver(request_author: str, request_repo: str) -> TrustTierResult:
        _ = request_author
        _ = request_repo
        resolved_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        return TrustTierResult(
            author=author,
            repo_full_name=repo_full_name,
            trust_tier=trust_tier,
            github_permission="none" if trust_tier is TrustTier.EXTERNAL else "write",
            resolved_at=resolved_at,
        )

    dependencies = WebhookDependencies(
        settings=settings,
        compiler=compiler,
        policy_engine=policy_engine,
        signer=signer,
        session_tracker=session_tracker,
        audit_logger=audit_logger,
        trust_tier_resolver=trust_tier_resolver,
        approval_requester=_noop_approval_requester,
    )
    import asyncio
    asyncio.run(dependencies.pending_store.init_db())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await dependencies.pending_store.close()

    app = FastAPI(lifespan=lifespan)
    app.state.webhook_dependencies = dependencies
    app.include_router(webhook_router)
    app.include_router(approval_router)

    return DemoContext(
        app=app,
        dependencies=dependencies,
        compiler=compiler,
        audit_logger=audit_logger,
        settings=settings,
        secret=secret,
    )
