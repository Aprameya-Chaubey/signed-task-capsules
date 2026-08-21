"""SQLite-backed storage for capsules awaiting human approval.

Pending capsules are persisted (rather than held in process memory) so that the
approval flow survives restarts and multiple workers, and so the out-of-process
MCP enforcement server can load the active approved capsule for a session.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from app.audit.logger import AuditLogger
from app.models import AuditEvent, AuditEventType, SignedCapsule
from app.sqlite_utils import configure_connection


logger = logging.getLogger(__name__)

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"


@dataclass(slots=True)
class PendingCapsule:
    """A signed capsule and the thread it belongs to, with a lifecycle status."""

    capsule: SignedCapsule
    thread_id: str
    status: str = PENDING


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    """Parse a stored timestamp regardless of fractional-second precision.

    Rows written by this module use ``_utc_now_text()`` (no fractional
    seconds), while SQLite's own ``created_at`` column default uses
    ``strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`` (fractional seconds included).
    Comparing these as raw strings is unsafe -- two timestamps within the same
    second can sort in the wrong order lexicographically depending on which
    format produced them. Parsing to ``datetime`` before comparing sidesteps
    the mismatch entirely.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class PendingCapsuleStore:
    """Persist and resolve capsules that require explicit human approval."""

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        self._schema_ensured = False
        self._connection: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    def _is_uri(self) -> bool:
        return self._database_path.startswith("file:")

    def _uses_memory_mode(self) -> bool:
        return self._database_path == ":memory:" or "mode=memory" in self._database_path

    async def close(self) -> None:
        if self._connection:
            await self._connection.close()
            self._connection = None

    @staticmethod
    async def _ensure_schema(connection: aiosqlite.Connection) -> None:
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS pending_capsules (
                capsule_id   TEXT PRIMARY KEY,
                capsule_json TEXT NOT NULL,
                thread_id    TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'pending',
                created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                resolved_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS pending_approvals (
                pending_id       TEXT PRIMARY KEY,
                policy_decision  TEXT NOT NULL,
                thread_id        TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                resolved_at      TEXT
            );
            """
        )
        await connection.commit()

    async def _get_connection(self) -> aiosqlite.Connection:
        """Lazily initialize the SQLite connection per event loop."""
        if self._connection is None:
            if not self._is_uri() and not self._uses_memory_mode():
                Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)
            self._connection = await aiosqlite.connect(self._database_path, uri=self._is_uri())
            self._connection.row_factory = aiosqlite.Row
            await configure_connection(self._connection)
            if not self._schema_ensured:
                await self._ensure_schema(self._connection)
                self._schema_ensured = True
        return self._connection

    async def init_db(self) -> None:
        """Create the pending-capsule table if it does not yet exist.
        Included for backward compatibility. Use _get_connection() directly instead."""
        await self._get_connection()

    async def add_pending(self, pending_id: str, policy_decision: str, thread_id: str) -> None:
        """Store an unsigned policy decision in the pending_approvals table."""
        conn = await self._get_connection()
        async with self._lock:
            await conn.execute(
                "INSERT INTO pending_approvals (pending_id, policy_decision, thread_id) VALUES (?, ?, ?)",
                (pending_id, policy_decision, thread_id),
            )
            await conn.commit()

    async def get_pending(self, pending_id: str) -> dict[str, Any] | None:
        """Retrieve a pending decision."""
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT policy_decision, thread_id, status FROM pending_approvals WHERE pending_id = ?",
                (pending_id,),
            )
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None

    async def resolve_approval(self, pending_id: str, status: str) -> bool:
        """Atomically mark a pending approval as resolved. Returns True if successful."""
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "UPDATE pending_approvals SET status = ?, resolved_at = ? WHERE pending_id = ? AND status = 'pending'",
                (status, _utc_now_text(), pending_id),
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def record_issued_and_resolve(self, pending_id: str, capsule: SignedCapsule, thread_id: str) -> bool:
        """Atomically resolve a pending approval and record the issued capsule.
        
        Returns True if successful, False if the pending approval was already resolved or not found.
        """
        conn = await self._get_connection()
        async with self._lock:
            # First attempt to resolve the pending approval
            cursor = await conn.execute(
                "UPDATE pending_approvals SET status = 'approved', resolved_at = ? WHERE pending_id = ? AND status = 'pending'",
                (_utc_now_text(), pending_id),
            )
            if cursor.rowcount == 0:
                # If we didn't update anything, the pending approval doesn't exist or is not pending.
                # Rollback is automatic on next query or close, but we haven't mutated anything.
                return False

            # If successful, record the capsule
            await conn.execute(
                """
                INSERT INTO pending_capsules
                    (capsule_id, capsule_json, thread_id, status, resolved_at)
                VALUES (?, ?, ?, 'approved', ?)
                ON CONFLICT(capsule_id) DO UPDATE SET
                    capsule_json = excluded.capsule_json,
                    thread_id = excluded.thread_id,
                    status = 'approved',
                    resolved_at = excluded.resolved_at;
                """,
                (
                    capsule.capsule_id,
                    capsule.model_dump_json(),
                    thread_id,
                    _utc_now_text(),
                ),
            )
            await conn.commit()
            return True

    async def record_issued(self, capsule: SignedCapsule, thread_id: str) -> None:
        """Persist a directly-issued capsule as the active (approved) record.

        Capsules issued without human approval must still be loadable by the
        out-of-process MCP server, so they are stored with an approved status.
        """
        conn = await self._get_connection()
        async with self._lock:
            await conn.execute(
                """
                INSERT INTO pending_capsules
                    (capsule_id, capsule_json, thread_id, status, resolved_at)
                VALUES (?, ?, ?, 'approved', ?)
                ON CONFLICT(capsule_id) DO UPDATE SET
                    capsule_json = excluded.capsule_json,
                    thread_id = excluded.thread_id,
                    status = 'approved',
                    resolved_at = excluded.resolved_at;
                """,
                (
                    capsule.capsule_id,
                    capsule.model_dump_json(),
                    thread_id,
                    _utc_now_text(),
                ),
            )
            await conn.commit()

    async def get(self, capsule_id: str) -> PendingCapsule | None:
        """Return a stored capsule regardless of status, or None if absent."""
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT capsule_json, thread_id, status FROM pending_capsules "
                "WHERE capsule_id = ?",
                (capsule_id,),
            )
            row = await cursor.fetchone()

        if row is None:
            return None
        return PendingCapsule(
            capsule=SignedCapsule.model_validate_json(row["capsule_json"]),
            thread_id=row["thread_id"],
            status=row["status"],
        )

    async def resolve(self, capsule_id: str, status: str) -> PendingCapsule | None:
        """Transition a pending capsule to a terminal status.

        Returns the capsule if it was pending and got resolved; None if it does
        not exist or was already resolved.
        """
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT capsule_json, thread_id, status FROM pending_capsules "
                "WHERE capsule_id = ?",
                (capsule_id,),
            )
            row = await cursor.fetchone()
            if row is None or row["status"] != PENDING:
                return None

            await self._connection.execute(
                "UPDATE pending_capsules SET status = ?, resolved_at = ? "
                "WHERE capsule_id = ?",
                (status, _utc_now_text(), capsule_id),
            )
            await conn.commit()

        return PendingCapsule(
            capsule=SignedCapsule.model_validate_json(row["capsule_json"]),
            thread_id=row["thread_id"],
            status=status,
        )

    async def latest_approved_for_thread(self, thread_id: str) -> SignedCapsule | None:
        """Return the most recently approved capsule for a thread, if any."""
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT capsule_json FROM pending_capsules "
                "WHERE thread_id = ? AND status = 'approved' "
                "ORDER BY resolved_at DESC, created_at DESC LIMIT 1",
                (thread_id,),
            )
            row = await cursor.fetchone()

        if row is None:
            return None
        return SignedCapsule.model_validate_json(row["capsule_json"])

    async def latest_approved(self) -> SignedCapsule | None:
        """Return the single most recently approved capsule across all threads."""
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT capsule_json FROM pending_capsules "
                "WHERE status = 'approved' "
                "ORDER BY resolved_at DESC, created_at DESC LIMIT 1"
            )
            row = await cursor.fetchone()

        if row is None:
            return None
        return SignedCapsule.model_validate_json(row["capsule_json"])

    # -- Retention / cleanup -------------------------------------------------
    #
    # Without these, pending_approvals grows without bound: every webhook that
    # requires human approval inserts a row that otherwise lives forever, even
    # after it is approved/rejected or simply abandoned. The methods below are
    # deliberately conservative:
    #   * expire_stale_pending_approvals() only ever transitions rows that are
    #     still 'pending' -- it never touches an already-resolved row.
    #   * purge_resolved_pending_approvals() only deletes rows that already
    #     reached a terminal state (approved/rejected/expired); a still-open
    #     approval is never deleted, only expired.
    #   * purge_stale_unresolved_pending_capsules() never deletes an
    #     'approved' pending_capsules row, because latest_approved() and
    #     latest_approved_for_thread() (used by the live MCP hot-reload path)
    #     depend on that history being retained indefinitely.
    #
    # All comparisons are done in Python (via _parse_utc) rather than in SQL,
    # because created_at/resolved_at columns can hold either SQLite's own
    # strftime('%f')-based default (fractional seconds) or this module's
    # _utc_now_text() (no fractional seconds) -- lexical/string comparison of
    # those two formats is not reliably ordered.

    async def expire_stale_pending_approvals(
        self, *, ttl: timedelta, now: datetime | None = None
    ) -> list[str]:
        """Transition 'pending' approvals older than ``ttl`` to 'expired'.

        Reuses resolve_approval()'s atomic ``WHERE status = 'pending'`` guard
        for each row, so a human approval/rejection racing with this sweep
        always wins over an expiry. Returns the pending_ids that were expired.
        """
        cutoff_now = now or datetime.now(timezone.utc)
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT pending_id, created_at FROM pending_approvals WHERE status = 'pending'"
            )
            rows = await cursor.fetchall()

        stale_ids = [
            row["pending_id"] for row in rows if cutoff_now - _parse_utc(row["created_at"]) >= ttl
        ]

        expired: list[str] = []
        for pending_id in stale_ids:
            if await self.resolve_approval(pending_id, EXPIRED):
                expired.append(pending_id)
        return expired

    async def purge_resolved_pending_approvals(
        self, *, older_than: timedelta, now: datetime | None = None
    ) -> int:
        """Permanently delete resolved pending_approvals rows past retention.

        Only rows with a non-'pending' status and a resolved_at timestamp are
        considered, so an approval still awaiting a decision is never deleted.
        """
        cutoff_now = now or datetime.now(timezone.utc)
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT pending_id, resolved_at FROM pending_approvals "
                "WHERE status != 'pending' AND resolved_at IS NOT NULL"
            )
            rows = await cursor.fetchall()

            stale_ids = [
                row["pending_id"]
                for row in rows
                if cutoff_now - _parse_utc(row["resolved_at"]) >= older_than
            ]
            if not stale_ids:
                return 0

            await conn.executemany(
                "DELETE FROM pending_approvals WHERE pending_id = ? AND status != 'pending'",
                [(pending_id,) for pending_id in stale_ids],
            )
            await conn.commit()
            return len(stale_ids)

    async def purge_stale_unresolved_pending_capsules(
        self, *, older_than: timedelta, now: datetime | None = None
    ) -> int:
        """Delete old pending_capsules rows that are NOT 'approved'.

        Current write paths (record_issued, record_issued_and_resolve) always
        insert pending_capsules rows with status='approved', so in practice
        this is a defensive safety net for any alternate writer or future code
        path -- it never deletes an 'approved' row, which must be retained for
        latest_approved()/latest_approved_for_thread().
        """
        cutoff_now = now or datetime.now(timezone.utc)
        conn = await self._get_connection()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT capsule_id, created_at FROM pending_capsules WHERE status != 'approved'"
            )
            rows = await cursor.fetchall()

            stale_ids = [
                row["capsule_id"]
                for row in rows
                if cutoff_now - _parse_utc(row["created_at"]) >= older_than
            ]
            if not stale_ids:
                return 0

            await conn.executemany(
                "DELETE FROM pending_capsules WHERE capsule_id = ? AND status != 'approved'",
                [(capsule_id,) for capsule_id in stale_ids],
            )
            await conn.commit()
            return len(stale_ids)

    async def run_retention_sweep(
        self,
        *,
        pending_ttl: timedelta,
        resolved_retention: timedelta,
        audit_logger: AuditLogger | None = None,
        now: datetime | None = None,
    ) -> dict[str, int]:
        """Run the full pending-approval retention policy in one pass.

        Expires stale pending approvals first (optionally audit-logging each
        one), then purges rows past the resolved-retention window from both
        tables. Returns counts for observability and testing.
        """
        effective_now = now or datetime.now(timezone.utc)

        expired_ids = await self.expire_stale_pending_approvals(ttl=pending_ttl, now=effective_now)
        if audit_logger is not None:
            for pending_id in expired_ids:
                try:
                    await audit_logger.log(
                        AuditEvent(
                            capsule_id=pending_id,
                            event_type=AuditEventType.CAPSULE_EXPIRED,
                            detail=f"Pending approval auto-expired after exceeding TTL of {pending_ttl}",
                        )
                    )
                except Exception:
                    logger.exception("Failed to audit-log expiry of pending approval %s", pending_id)

        purged_approvals = await self.purge_resolved_pending_approvals(
            older_than=resolved_retention, now=effective_now
        )
        purged_capsules = await self.purge_stale_unresolved_pending_capsules(
            older_than=resolved_retention, now=effective_now
        )

        return {
            "expired_pending_approvals": len(expired_ids),
            "purged_pending_approvals": purged_approvals,
            "purged_pending_capsules": purged_capsules,
        }
