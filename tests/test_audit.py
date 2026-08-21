"""Tests for the append-only audit logger and viewer routes."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.audit.logger import AuditLogger
from app.audit.viewer import router as audit_router
from app.config import Settings
from app.models import AuditEvent, AuditEventType, TrustTier


ADMIN_TOKEN = "test-admin-token"
ADMIN_HEADERS = {"X-Admin-Token": ADMIN_TOKEN}


def _admin_settings() -> Settings:
    return Settings(ADMIN_API_TOKEN=ADMIN_TOKEN)


def memory_database_uri() -> str:
    return f"file:audit-{uuid4()}?mode=memory&cache=shared"


def sample_event(
    capsule_id: str,
    event_type: AuditEventType = AuditEventType.CAPSULE_ISSUED,
) -> AuditEvent:
    return AuditEvent(
        capsule_id=capsule_id,
        event_type=event_type,
        trust_tier=TrustTier.CONTRIBUTOR,
        tool_name="read_file",
        target_path="app/**",
        detail="sample",
    )


def test_init_db_creates_audit_events_table() -> None:
    logger = AuditLogger(memory_database_uri())

    async def assert_table_exists() -> None:
        await logger.init_db()
        assert logger._connection is not None
        cursor = await logger._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events';"
        )
        row = await cursor.fetchone()
        assert row is not None
        await logger.close()

    asyncio.run(assert_table_exists())


def test_log_inserts_row_and_get_events_reads_it() -> None:
    logger = AuditLogger(memory_database_uri())
    event = sample_event(str(uuid4()))

    async def run_test() -> None:
        await logger.init_db()
        await logger.log(event)
        events = await logger.get_events(limit=100)
        assert len(events) == 1
        assert events[0].capsule_id == event.capsule_id
        assert events[0].event_type is event.event_type
        await logger.close()

    asyncio.run(run_test())


def test_get_events_filters_by_capsule_id() -> None:
    logger = AuditLogger(memory_database_uri())
    kept_id = str(uuid4())

    async def run_test() -> None:
        await logger.init_db()
        await logger.log(sample_event(kept_id, AuditEventType.CAPSULE_ISSUED))
        await logger.log(sample_event(str(uuid4()), AuditEventType.TOOL_BLOCKED))

        filtered_events = await logger.get_events(limit=100, capsule_id=kept_id)
        assert len(filtered_events) == 1
        assert filtered_events[0].capsule_id == kept_id
        await logger.close()

    asyncio.run(run_test())


def test_audit_viewer_endpoint_returns_html() -> None:
    logger = AuditLogger(memory_database_uri())
    asyncio.run(logger.init_db())
    asyncio.run(logger.log(sample_event(str(uuid4()))))

    app = FastAPI()
    app.state.settings = _admin_settings()
    app.state.audit_logger = logger
    app.include_router(audit_router)

    with TestClient(app) as client:
        response = client.get("/audit", headers=ADMIN_HEADERS)
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert response.headers["cache-control"] == "no-store"
        assert "Audit Events" in response.text

    asyncio.run(logger.close())


def test_audit_json_api_returns_valid_audit_events() -> None:
    logger = AuditLogger(memory_database_uri())
    capsule_id = str(uuid4())
    asyncio.run(logger.init_db())
    asyncio.run(logger.log(sample_event(capsule_id, AuditEventType.TOOL_ALLOWED)))

    app = FastAPI()
    app.state.settings = _admin_settings()
    app.state.audit_logger = logger
    app.include_router(audit_router)

    with TestClient(app) as client:
        response = client.get("/api/audit", headers=ADMIN_HEADERS)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        payload = response.json()
        assert isinstance(payload, list)
        assert payload
        parsed = [AuditEvent.model_validate(item) for item in payload]
        assert parsed[0].capsule_id == capsule_id

        capsule_response = client.get(f"/api/audit/{capsule_id}", headers=ADMIN_HEADERS)
        assert capsule_response.status_code == 200
        assert capsule_response.headers["cache-control"] == "no-store"
        capsule_payload = [AuditEvent.model_validate(item) for item in capsule_response.json()]
        assert len(capsule_payload) == 1
        assert capsule_payload[0].capsule_id == capsule_id

    asyncio.run(logger.close())
