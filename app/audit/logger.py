"""Append-only SQLite audit logger for governance events."""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite

from app.audit.models import AuditEvent
from app.sqlite_utils import configure_connection


class AuditLogger:
    """Persist and query governance audit events in an append-only table."""

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        self._connection: aiosqlite.Connection | None = None
        self._init_lock = asyncio.Lock()

    async def init_db(self) -> None:
        """Initialize the database schema and indexes if they are missing."""

        async with self._init_lock:
            if self._connection is not None:
                return

            is_uri = self._database_path.startswith("file:")
            uses_memory_mode = self._database_path == ":memory:" or "mode=memory" in self._database_path
            if not is_uri and not uses_memory_mode:
                Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)

            self._connection = await aiosqlite.connect(
                self._database_path,
                uri=is_uri,
            )
            self._connection.row_factory = aiosqlite.Row

            # WAL + busy_timeout improve read/write concurrency for the demo UI
            # polling path and avoid instant "database is locked" failures when
            # another component (PendingCapsuleStore, SessionTracker) writes to
            # the same on-disk database file concurrently.
            await configure_connection(self._connection)
            await self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    capsule_id  TEXT,
                    event_type  TEXT    NOT NULL CHECK (event_type IN (
                        'capsule_issued',
                        'capsule_denied',
                        'capsule_pending',
                        'capsule_approved',
                        'capsule_expired',
                        'tool_allowed',
                        'tool_blocked'
                    )),
                    trust_tier  TEXT,
                    tool_name   TEXT,
                    target_path TEXT,
                    detail      TEXT
                );
                """
            )
            await self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_capsule ON audit_events(capsule_id);"
            )
            await self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp);"
            )
            await self._connection.commit()

    async def close(self) -> None:
        """Close the database connection if one is open."""

        if self._connection is None:
            return
        await self._connection.close()
        self._connection = None

    async def _connection_or_raise(self) -> aiosqlite.Connection:
        if self._connection is None:
            await self.init_db()
        if self._connection is None:
            raise RuntimeError("Audit logger database is not initialized")
        return self._connection

    async def log(self, event: AuditEvent) -> None:
        """Insert one audit event row."""

        connection = await self._connection_or_raise()
        await connection.execute(
            """
            INSERT INTO audit_events (
                timestamp,
                capsule_id,
                event_type,
                trust_tier,
                tool_name,
                target_path,
                detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                event.timestamp,
                event.capsule_id,
                event.event_type.value,
                event.trust_tier.value if event.trust_tier is not None else None,
                event.tool_name,
                event.target_path,
                event.detail,
            ),
        )
        await connection.commit()

    async def get_events(
        self,
        limit: int = 100,
        capsule_id: str | None = None,
    ) -> list[AuditEvent]:
        """Read recent events, optionally filtered to one capsule ID."""

        connection = await self._connection_or_raise()
        effective_limit = max(0, min(limit, 10_000))

        query = (
            "SELECT timestamp, capsule_id, event_type, trust_tier, tool_name, target_path, detail "
            "FROM audit_events"
        )
        parameters: list[str | int] = []
        if capsule_id is not None:
            query += " WHERE capsule_id = ?"
            parameters.append(capsule_id)
        query += " ORDER BY timestamp DESC, id DESC"
        if effective_limit > 0:
            query += " LIMIT ?"
            parameters.append(effective_limit)

        cursor = await connection.execute(query, parameters)
        rows = await cursor.fetchall()

        events: list[AuditEvent] = []
        for row in rows:
            events.append(
                AuditEvent(
                    timestamp=row["timestamp"],
                    capsule_id=row["capsule_id"],
                    event_type=row["event_type"],
                    trust_tier=row["trust_tier"],
                    tool_name=row["tool_name"],
                    target_path=row["target_path"],
                    detail=row["detail"],
                )
            )
        return events
