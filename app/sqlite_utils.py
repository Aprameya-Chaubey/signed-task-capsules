"""Shared SQLite connection-hygiene helpers.

Every component that persists state to the shared SQLite database file
(``AuditLogger``, ``PendingCapsuleStore``, ``SessionTracker``) should route
newly-opened connections through :func:`configure_connection` so that all
three apply the same journal mode and busy timeout.

Without an explicit busy timeout, concurrent writers sharing one SQLite file
under WAL can still raise "database is locked" as soon as two writes overlap
by even a few milliseconds. ``PRAGMA busy_timeout`` makes SQLite retry
internally (blocking briefly) instead of failing the operation immediately,
which is the behavior every writer here actually wants given they all share
one on-disk database file (``settings.database_path``).
"""

from __future__ import annotations

import aiosqlite

# Milliseconds SQLite will keep retrying a locked write before giving up and
# raising "database is locked". Applied explicitly (rather than relying on the
# sqlite3 module's own 5-second default connection timeout) so the behavior is
# documented, consistent across every writer, and independent of future
# changes to how connections are opened.
BUSY_TIMEOUT_MS = 5_000


async def configure_connection(connection: aiosqlite.Connection) -> None:
    """Apply the standard pragmas (WAL journal mode + busy timeout).

    Safe to call on any freshly-opened connection, including ones backed by
    an in-memory or URI database; SQLite silently ignores ``journal_mode=WAL``
    for ``:memory:`` databases (it falls back to MEMORY mode).
    """

    await connection.execute("PRAGMA journal_mode=WAL;")
    await connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS};")
