"""Per-thread session history tracking with SQLite persistence."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite

from app.models import CapsuleSummary, SessionHistory, SignedCapsule
from app.sqlite_utils import configure_connection


_SESSION_WINDOW = timedelta(minutes=60)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class SessionTracker:
    """Track per-thread escalation state across issued capsules."""

    def __init__(self) -> None:
        if os.getenv("WEB_CONCURRENCY", "1") != "1":
            raise RuntimeError("SessionTracker cannot run with multiple worker processes")

        self._sessions: dict[str, SessionHistory] = {}
        self._unique_tools: dict[str, dict[str, set[str]]] = {}
        self._lock = asyncio.Lock()
        self._dirty_threads: set[str] = set()
        self._schema_ensured = False
        self._seen_deliveries: dict[str, bool] = {}
        self._connection: aiosqlite.Connection | None = None
        self._connection_path: str | None = None

    async def is_duplicate_delivery(self, delivery_id: str | None) -> bool:
        if not delivery_id:
            return False
        async with self._lock:
            if delivery_id in self._seen_deliveries:
                return True
            self._seen_deliveries[delivery_id] = True
            if len(self._seen_deliveries) > 1000:
                self._seen_deliveries.pop(next(iter(self._seen_deliveries)))
            return False

    @classmethod
    def compute_thread_id(cls, repo_full_name: str, issue_or_pr_number: int) -> str:
        return f"{repo_full_name}#{issue_or_pr_number}"

    def _get_or_create_locked(self, thread_id: str) -> SessionHistory:
        session = self._sessions.get(thread_id)
        if session is None:
            session = SessionHistory(thread_id=thread_id)
            self._sessions[thread_id] = session
        self._unique_tools.setdefault(thread_id, {})
        return session

    async def get_or_create(self, thread_id: str) -> SessionHistory:
        """Return the existing thread session or initialize a new empty one."""

        async with self._lock:
            return self._get_or_create_locked(thread_id)

    async def record_capsule(self, thread_id: str, capsule: SignedCapsule) -> None:
        """Record one issued capsule into thread history and update counters."""

        now = _utc_now()
        summary = CapsuleSummary(
            capsule_id=capsule.capsule_id,
            issued_at=_utc_text(now),
            trust_tier=capsule.trust_tier,
            tools_count=len(capsule.allowed_tools),
            paths_count=len(capsule.target_paths),
        )

        async with self._lock:
            session = self._get_or_create_locked(thread_id)
            self._dirty_threads.add(thread_id)

            pruned = [
                entry
                for entry in session.recent_capsules
                if now - _parse_utc(entry.issued_at) <= _SESSION_WINDOW
            ]
            pruned.append(summary)
            session.recent_capsules = pruned

            high_scope = summary.tools_count > 2 or summary.paths_count > 10
            if high_scope:
                session.consecutive_high_scope += 1
            else:
                session.consecutive_high_scope = 0

            # Track tools for this capsule
            capsule_tools = {tool.value for tool in capsule.allowed_tools}
            self._unique_tools.setdefault(thread_id, {})[capsule.capsule_id] = capsule_tools
            
            # Remove tools for expired capsules
            current_capsule_ids = {entry.capsule_id for entry in pruned}
            thread_tools = self._unique_tools.get(thread_id, {})
            for cid in list(thread_tools.keys()):
                if cid not in current_capsule_ids:
                    del thread_tools[cid]
            
            # Calculate cumulative unique tools in the current window
            active_tools = set()
            for tool_set in thread_tools.values():
                active_tools.update(tool_set)
            session.cumulative_unique_tools = len(active_tools)


    async def record_approval(self, thread_id: str) -> None:
        """Record that a human approved a pending capsule in this thread."""

        async with self._lock:
            session = self._get_or_create_locked(thread_id)
            session.last_human_approval_at = _utc_text(_utc_now())
            self._dirty_threads.add(thread_id)

    @staticmethod
    async def _ensure_schema(connection: aiosqlite.Connection) -> None:
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS session_history (
                thread_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            """
        )
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS session_tools (
                thread_id TEXT PRIMARY KEY,
                tools TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            """
        )
        await connection.commit()

    async def _get_connection(self, db_path: str) -> aiosqlite.Connection:
        """Return a cached connection for db_path, applying WAL + busy_timeout.

        Reconnecting on every persist()/load() call (the previous behavior)
        meant this component never benefited from WAL or an explicit busy
        timeout, unlike AuditLogger and PendingCapsuleStore which each cache a
        connection. Caching here brings SessionTracker in line with them and
        avoids paying reconnect + schema-check overhead on every call -- most
        notably the /approve endpoint, which calls persist() on every request.

        If db_path differs from the path the cached connection was opened
        against (not expected in current call sites, which always pass
        settings.database_path, but not guaranteed by the public signature),
        the stale connection is closed and a fresh one opened instead of
        silently writing to the wrong file.
        """
        if self._connection is not None and self._connection_path != db_path:
            await self._connection.close()
            self._connection = None
            self._schema_ensured = False

        if self._connection is None:
            is_uri = db_path.startswith("file:")
            uses_memory_mode = db_path == ":memory:" or "mode=memory" in db_path
            if not is_uri and not uses_memory_mode:
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            connection = await aiosqlite.connect(db_path, uri=is_uri)
            await configure_connection(connection)
            self._connection = connection
            self._connection_path = db_path

        if not self._schema_ensured:
            await self._ensure_schema(self._connection)
            self._schema_ensured = True

        return self._connection

    async def close(self) -> None:
        """Close the cached database connection, if one is open."""

        if self._connection is not None:
            await self._connection.close()
            self._connection = None
            self._connection_path = None

    async def persist(self, db_path: str) -> None:
        """Persist all in-memory session state to SQLite."""

        if not self._dirty_threads:
            return

        async with self._lock:
            connection = await self._get_connection(db_path)

            for thread_id in list(self._dirty_threads):
                session = self._sessions.get(thread_id)
                if not session:
                    self._dirty_threads.discard(thread_id)
                    continue
                await connection.execute(
                    """
                    INSERT INTO session_history (thread_id, data, updated_at)
                    VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT(thread_id) DO UPDATE SET
                        data = excluded.data,
                        updated_at = excluded.updated_at;
                    """,
                    (thread_id, session.model_dump_json()),
                )

                tools_dict = {
                    cid: list(tools)
                    for cid, tools in self._unique_tools.get(thread_id, {}).items()
                }
                serialized_tools = json.dumps(tools_dict)

                await connection.execute(
                    """
                    INSERT INTO session_tools (thread_id, tools, updated_at)
                    VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT(thread_id) DO UPDATE SET
                        tools = excluded.tools,
                        updated_at = excluded.updated_at;
                    """,
                    (thread_id, serialized_tools),
                )
                self._dirty_threads.discard(thread_id)

            await connection.commit()

    async def load(self, db_path: str) -> None:
        """Load session state from SQLite if persisted rows already exist."""

        async with self._lock:
            connection = await self._get_connection(db_path)

            self._sessions.clear()
            self._unique_tools.clear()
            self._dirty_threads.clear()

            history_rows = await (
                await connection.execute("SELECT thread_id, data FROM session_history")
            ).fetchall()
            for thread_id, data in history_rows:
                session = SessionHistory.model_validate_json(data)
                self._sessions[thread_id] = session

            tool_rows = await (
                await connection.execute("SELECT thread_id, tools FROM session_tools")
            ).fetchall()
            for thread_id, tools_json in tool_rows:
                parsed = json.loads(tools_json)
                if isinstance(parsed, list):
                    # Backward compatibility for old DBs: attach tools to the latest capsule
                    session = self._sessions.get(thread_id)
                    if session and session.recent_capsules:
                        latest_cid = session.recent_capsules[-1].capsule_id
                        self._unique_tools[thread_id] = {
                            latest_cid: {entry for entry in parsed if isinstance(entry, str)}
                        }
                    else:
                        self._unique_tools[thread_id] = {}
                elif isinstance(parsed, dict):
                    self._unique_tools[thread_id] = {
                        cid: set(tools)
                        for cid, tools in parsed.items()
                        if isinstance(tools, list)
                    }

            for thread_id in self._sessions:
                self._unique_tools.setdefault(thread_id, {})

