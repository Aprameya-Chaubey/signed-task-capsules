"""Tests for pending-approval/capsule retention and expiry sweeps.

Covers the fix for unbounded pending_approvals (and pending_capsules) growth:
expire_stale_pending_approvals(), purge_resolved_pending_approvals(),
purge_stale_unresolved_pending_capsules(), and the run_retention_sweep()
orchestration, including that 'approved' pending_capsules rows -- required by
latest_approved()/latest_approved_for_thread() for the live MCP hot-reload
path -- are never deleted regardless of age.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.models import AuditEvent, AuditEventType
from app.pending_store import EXPIRED, PendingCapsuleStore


def memory_database_uri() -> str:
    return f"file:pending-retention-{uuid4()}?mode=memory&cache=shared"


def _fmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def log(self, event: AuditEvent) -> None:
        self.events.append(event)


async def _insert_pending_approval(
    store: PendingCapsuleStore,
    *,
    pending_id: str,
    created_at: datetime,
    status: str = "pending",
    resolved_at: datetime | None = None,
    thread_id: str = "owner/repo#1",
) -> None:
    conn = await store._get_connection()
    await conn.execute(
        "INSERT INTO pending_approvals "
        "(pending_id, policy_decision, thread_id, status, created_at, resolved_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (pending_id, "{}", thread_id, status, _fmt(created_at), _fmt(resolved_at) if resolved_at else None),
    )
    await conn.commit()


async def _insert_pending_capsule(
    store: PendingCapsuleStore,
    *,
    capsule_id: str,
    created_at: datetime,
    status: str,
    resolved_at: datetime | None = None,
    thread_id: str = "owner/repo#1",
) -> None:
    conn = await store._get_connection()
    await conn.execute(
        "INSERT INTO pending_capsules "
        "(capsule_id, capsule_json, thread_id, status, created_at, resolved_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (capsule_id, "{}", thread_id, status, _fmt(created_at), _fmt(resolved_at) if resolved_at else None),
    )
    await conn.commit()


async def _approval_status(store: PendingCapsuleStore, pending_id: str) -> str | None:
    conn = await store._get_connection()
    cursor = await conn.execute(
        "SELECT status FROM pending_approvals WHERE pending_id = ?", (pending_id,)
    )
    row = await cursor.fetchone()
    return row["status"] if row else None


async def _approval_row_exists(store: PendingCapsuleStore, pending_id: str) -> bool:
    conn = await store._get_connection()
    cursor = await conn.execute(
        "SELECT 1 FROM pending_approvals WHERE pending_id = ?", (pending_id,)
    )
    return await cursor.fetchone() is not None


async def _capsule_row_exists(store: PendingCapsuleStore, capsule_id: str) -> bool:
    conn = await store._get_connection()
    cursor = await conn.execute(
        "SELECT 1 FROM pending_capsules WHERE capsule_id = ?", (capsule_id,)
    )
    return await cursor.fetchone() is not None


NOW = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
OLD = NOW - timedelta(hours=48)
FRESH = NOW - timedelta(minutes=5)


def test_expire_stale_pending_approvals_expires_only_old_pending_rows() -> None:
    async def run() -> tuple[list[str], str | None, str | None]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_approval(store, pending_id="old", created_at=OLD)
        await _insert_pending_approval(store, pending_id="fresh", created_at=FRESH)

        expired = await store.expire_stale_pending_approvals(ttl=timedelta(hours=1), now=NOW)

        old_status = await _approval_status(store, "old")
        fresh_status = await _approval_status(store, "fresh")
        await store.close()
        return expired, old_status, fresh_status

    expired, old_status, fresh_status = asyncio.run(run())
    assert expired == ["old"]
    assert old_status == EXPIRED
    assert fresh_status == "pending"


def test_expire_stale_pending_approvals_never_touches_resolved_rows() -> None:
    async def run() -> list[str]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_approval(
            store, pending_id="already-approved", created_at=OLD, status="approved", resolved_at=OLD
        )

        expired = await store.expire_stale_pending_approvals(ttl=timedelta(hours=1), now=NOW)
        await store.close()
        return expired

    expired = asyncio.run(run())
    assert expired == []


def test_expire_stale_pending_approvals_yields_to_concurrent_resolution() -> None:
    """If a human approval/rejection races with the sweep, resolve_approval()'s
    atomic 'WHERE status = pending' guard means the sweep never overwrites it."""

    async def run() -> tuple[bool, str | None]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_approval(store, pending_id="raced", created_at=OLD)

        # Simulate a human resolving it moments before the sweep's UPDATE runs.
        resolved_first = await store.resolve_approval("raced", "approved")

        expired = await store.expire_stale_pending_approvals(ttl=timedelta(hours=1), now=NOW)
        status = await _approval_status(store, "raced")
        await store.close()
        return resolved_first, status if "raced" not in expired else "EXPIRED_INCORRECTLY"

    resolved_first, status = asyncio.run(run())
    assert resolved_first is True
    assert status == "approved"


def test_purge_resolved_pending_approvals_deletes_old_terminal_rows_only() -> None:
    async def run() -> tuple[bool, bool, bool]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_approval(
            store, pending_id="old-resolved", created_at=OLD, status="approved", resolved_at=OLD
        )
        await _insert_pending_approval(
            store, pending_id="fresh-resolved", created_at=OLD, status="rejected", resolved_at=FRESH
        )
        await _insert_pending_approval(store, pending_id="still-pending", created_at=OLD)

        purged_count = await store.purge_resolved_pending_approvals(
            older_than=timedelta(hours=1), now=NOW
        )

        old_exists = await _approval_row_exists(store, "old-resolved")
        fresh_exists = await _approval_row_exists(store, "fresh-resolved")
        pending_exists = await _approval_row_exists(store, "still-pending")
        await store.close()
        assert purged_count == 1
        return old_exists, fresh_exists, pending_exists

    old_exists, fresh_exists, pending_exists = asyncio.run(run())
    assert old_exists is False
    assert fresh_exists is True
    assert pending_exists is True


def test_purge_stale_unresolved_pending_capsules_never_deletes_approved() -> None:
    async def run() -> tuple[bool, bool]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_capsule(
            store, capsule_id="old-approved", created_at=OLD, status="approved", resolved_at=OLD
        )
        # Defensive scenario: current write paths never produce this, but a
        # future/alternate writer might leave a stale non-approved row behind.
        await _insert_pending_capsule(
            store, capsule_id="old-rejected", created_at=OLD, status="rejected", resolved_at=OLD
        )

        purged_count = await store.purge_stale_unresolved_pending_capsules(
            older_than=timedelta(hours=1), now=NOW
        )

        approved_exists = await _capsule_row_exists(store, "old-approved")
        rejected_exists = await _capsule_row_exists(store, "old-rejected")
        await store.close()
        assert purged_count == 1
        return approved_exists, rejected_exists

    approved_exists, rejected_exists = asyncio.run(run())
    assert approved_exists is True
    assert rejected_exists is False


def test_run_retention_sweep_logs_audit_event_per_expired_approval() -> None:
    # AuditEvent.capsule_id is pattern-constrained to UUID shape (matching
    # production, where pending_id is always uuid.uuid4() -- see
    # app/ingestion/webhook.py); non-UUID ids would raise inside AuditEvent
    # construction, which run_retention_sweep swallows, silently skipping the
    # log -- use real UUIDs so this test actually exercises audit logging.
    old_id_1, old_id_2 = str(uuid4()), str(uuid4())
    fresh_id = str(uuid4())

    async def run() -> tuple[dict[str, int], FakeAuditLogger]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_approval(store, pending_id=old_id_1, created_at=OLD)
        await _insert_pending_approval(store, pending_id=old_id_2, created_at=OLD)
        await _insert_pending_approval(store, pending_id=fresh_id, created_at=FRESH)

        audit_logger = FakeAuditLogger()
        counts = await store.run_retention_sweep(
            pending_ttl=timedelta(hours=1),
            resolved_retention=timedelta(days=1),
            audit_logger=audit_logger,
            now=NOW,
        )
        await store.close()
        return counts, audit_logger

    counts, audit_logger = asyncio.run(run())
    assert counts["expired_pending_approvals"] == 2
    assert len(audit_logger.events) == 2
    assert {event.capsule_id for event in audit_logger.events} == {old_id_1, old_id_2}
    assert all(event.event_type is AuditEventType.CAPSULE_EXPIRED for event in audit_logger.events)


def test_run_retention_sweep_returns_accurate_counts_across_both_tables() -> None:
    async def run() -> dict[str, int]:
        store = PendingCapsuleStore(memory_database_uri())
        await store.init_db()
        await _insert_pending_approval(store, pending_id="to-expire", created_at=OLD)
        await _insert_pending_approval(
            store, pending_id="to-purge", created_at=OLD, status="rejected", resolved_at=OLD
        )
        await _insert_pending_capsule(
            store, capsule_id="stale-capsule", created_at=OLD, status="rejected", resolved_at=OLD
        )
        await _insert_pending_capsule(
            store, capsule_id="kept-capsule", created_at=OLD, status="approved", resolved_at=OLD
        )

        counts = await store.run_retention_sweep(
            pending_ttl=timedelta(hours=1),
            resolved_retention=timedelta(hours=1),
            now=NOW,
        )
        kept_exists = await _capsule_row_exists(store, "kept-capsule")
        await store.close()
        assert kept_exists is True
        return counts

    counts = asyncio.run(run())
    assert counts == {
        "expired_pending_approvals": 1,
        "purged_pending_approvals": 1,
        "purged_pending_capsules": 1,
    }
