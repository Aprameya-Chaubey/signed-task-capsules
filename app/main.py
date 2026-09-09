"""Minimal FastAPI application for the Signed Task Capsules service."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
from fastapi import Depends, FastAPI

from app.audit.logger import AuditLogger
from app.audit.viewer import router as audit_router
from app.auth import require_admin_auth
from app.config import Settings, get_settings
from app.enforcement.mcp_server import create_app_mcp_router
from app.enforcement.proxy import MCPEnforcementProxy
from app.enforcement.tool_provider import GovernedToolHandler
from app.governance.compiler import TaskCompiler
from app.governance.policy import PolicyEngine
from app.governance.session import SessionTracker
from app.governance.signer import create_signer
from app.ingestion.approval import router as approval_router
from app.ingestion.webhook import WebhookDependencies, router as webhook_router
from app.pending_store import PendingCapsuleStore


logger = logging.getLogger(__name__)


async def _pending_cleanup_loop(
    store: PendingCapsuleStore,
    audit_logger: AuditLogger,
    app_settings: Settings,
) -> None:
    """Periodically expire stale pending approvals and purge old resolved rows.

    Sleeps for the configured interval BEFORE each sweep, rather than
    sweeping immediately on startup, so that a lifespan which exits quickly
    (as in tests that never yield control long enough for a real interval to
    elapse) never triggers a real database sweep before this task is
    cancelled in the lifespan's shutdown path.
    """

    interval_seconds = max(60, app_settings.pending_cleanup_interval_minutes * 60)
    ttl = timedelta(hours=app_settings.pending_approval_ttl_hours)
    retention = timedelta(days=app_settings.pending_approval_retention_days)

    while True:
        await asyncio.sleep(interval_seconds)
        try:
            counts = await store.run_retention_sweep(
                pending_ttl=ttl,
                resolved_retention=retention,
                audit_logger=audit_logger,
            )
            if any(counts.values()):
                logger.info("Pending-approval retention sweep: %s", counts)
        except Exception:
            logger.exception("Pending-approval retention sweep failed")


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize long-lived resources used by API routes."""

    settings = get_settings()

    audit_logger = AuditLogger(settings.database_path)
    await audit_logger.init_db()

    pending_store = PendingCapsuleStore(settings.database_path)
    await pending_store.init_db()

    http_client = httpx.AsyncClient(timeout=30.0)

    compiler = TaskCompiler(settings=settings, http_client=http_client)
    policy_engine = PolicyEngine()
    signer = create_signer(settings)
    session_tracker = SessionTracker()
    await session_tracker.load(settings.database_path)

    enforcement_proxy = MCPEnforcementProxy(
        audit_logger=audit_logger,
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root),
    )

    if not settings.admin_api_token:
        logging.getLogger(__name__).warning(
            "ADMIN_API_TOKEN not set — approval and audit endpoints will return 503"
        )

    application.state.settings = settings
    application.state.audit_logger = audit_logger
    application.state.session_tracker = session_tracker
    application.state.enforcement_proxy = enforcement_proxy
    application.state.pending_store = pending_store
    application.state.http_client = http_client
    application.state.webhook_dependencies = WebhookDependencies(
        settings=settings,
        compiler=compiler,
        policy_engine=policy_engine,
        signer=signer,
        session_tracker=session_tracker,
        audit_logger=audit_logger,
        pending_store=pending_store,
    )
    cleanup_task = asyncio.create_task(
        _pending_cleanup_loop(pending_store, audit_logger, settings)
    )
    application.state.pending_cleanup_task = cleanup_task
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

        # Persist session history before closing to avoid race conditions
        await session_tracker.persist(settings.database_path)
        await session_tracker.close()

        await asyncio.gather(
            audit_logger.close(),
            pending_store.close(),
            http_client.aclose(),
            return_exceptions=True,
        )


app = FastAPI(title="Signed Task Capsules", lifespan=lifespan)
app.include_router(audit_router)
app.include_router(webhook_router)
app.include_router(approval_router)
app.include_router(
    create_app_mcp_router(),
    dependencies=[Depends(require_admin_auth)],
)


@app.get("/")
async def root() -> dict[str, str]:
    """Return the service health response."""

    return {"service": "signed-task-capsules", "status": "ok"}


# Importing get_settings above verifies that environment-backed configuration is available.
_ = get_settings()
