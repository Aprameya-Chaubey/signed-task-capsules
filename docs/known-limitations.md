# Known Limitations

This document lists security and correctness gaps that are intentionally out of
scope for the hackathon implementation. Each item has a clear production fix.

## Enforcement boundary

- **Native tool bypass.** IBM Bob's built-in file/bash tools do not route through
  the MCP enforcement proxy. This build relies on `.bob/custom_modes.yaml`
  (`stc-governed` mode) to disable native tools so 100% of actions flow through
  the governed proxy. The `stc-governed` mode explicitly excludes the `read`
  group to prevent any native read operations outside capsule scope. Production
  fix: integrate capsule verification into Bob's core execution loop.

- **External-proxy architecture limitation.** Removing the `read` group from
  `stc-governed` mode means Bob cannot perform native reads even within the
  capsule's `target_paths`. All reads must go through the MCP proxy. This is a
  known limitation of the external-proxy architecture: native tool groups are
  all-or-nothing, so we exclude them entirely and rely on `.bobignore` as a
  static safety net.

## Network requests

- **`net_request` SSRF hardening (resolved).** The `net_request` tool includes comprehensive SSRF protection:
  - Allowlist enforcement for destination hosts
  - `getaddrinfo`-based DNS resolution with private-IP rejection
  - IP-pinned connections to prevent redirect-based bypasses
  - Per-redirect re-validation of destination IPs
  
  See `app/enforcement/proxy.py` for implementation details.

## Path handling

- **Symlink traversal (resolved on Linux/macOS).** `GovernedToolHandler._resolve()`
  calls `Path.resolve()` (dereferences symlinks) and checks containment before
  authorizing a `read_file`/`write_file` call, but that check reflects the
  filesystem's state only at the moment it runs. On platforms with `dir_fd`
  support (`os.supports_dir_fd` -- Linux/macOS, including this project's
  `python:3.11-slim` Docker target), the actual open is performed by
  `_secure_open_fd()`, which walks the path one component at a time with
  `O_NOFOLLOW` relative to each parent directory's file descriptor. This
  closes the TOCTOU window: even if a path component is swapped for a symlink
  after authorization but before the open, the kernel rejects it (`ELOOP` for
  a symlinked leaf; empirically `ENOTDIR` on Linux for a symlinked
  *intermediate* directory opened with `O_NOFOLLOW | O_DIRECTORY` -- both are
  caught) rather than silently following it. **On Windows, this falls back to the
  previous `Path.read_text()`/`Path.write_text()` behavior**, which is still
  protected by the lexical check above but remains theoretically racy --
  Windows has no direct equivalent of `dir_fd` + `O_NOFOLLOW` exposed via
  `os`. Since production deployment is the Linux container, not Windows, this
  is considered acceptable. See `tests/test_fs_race_hardening.py`.
- **Windows absolute paths.** Path matching is tuned for POSIX-style repository
  paths. Windows drive-letter absolute paths (e.g. `C:\...`) are treated as
  opaque path-like strings and matched literally against capsule globs.

## Governed tool surface

- **Governed handler covers file ops and network requests.** `GovernedToolHandler`
  (`app/enforcement/tool_provider.py`) implements in-scope `read_file`/`write_file`
  behind the proxy, contained within `WORKSPACE_ROOT`, as well as `net_request`
  with comprehensive SSRF hardening (allowlist enforcement, `getaddrinfo`-based
  DNS resolution with private-IP rejection, IP-pinned connections, and
  per-redirect re-validation). `execute_cmd` and `run_tests` are deliberately
  reported as "no governed implementation" rather than executed, so a locked-down
  agent never runs arbitrary shell calls through the governed surface.
  Production fix: sandboxed executors for those tools if the demo requires them.

## Storage / operations

- **Pending-capsule schema migration.** The audit `capsule_id` column was
  relaxed from `NOT NULL` to nullable. `CREATE TABLE IF NOT EXISTS` does not
  alter pre-existing databases; a fresh database is required to store denied
  events with a null capsule ID.
- **MCP capsule binding (resolved).** Directly-issued capsules are persisted via
  `PendingCapsuleStore.record_issued` and the MCP server hot-reloads the latest
  active capsule per request (`tools/call` / `tools/list`), so both approved and
  auto-issued capsules are visible to the out-of-process server without restart.
  The binding is still "latest active globally" rather than per-thread; a
  thread-scoped binding is a future enhancement.
- **Unbounded pending-approval growth (resolved).** `pending_approvals` and
  `pending_capsules` previously grew without bound -- every webhook requiring
  human approval inserted a row that lived forever, even once resolved or
  abandoned. A background sweep (`PendingCapsuleStore.run_retention_sweep`,
  scheduled from `app/main.py`'s lifespan) now auto-expires pending approvals
  older than `PENDING_APPROVAL_TTL_HOURS` (default 24h) and permanently
  deletes resolved/terminal rows older than `PENDING_APPROVAL_RETENTION_DAYS`
  (default 30d). `pending_capsules` rows with `status='approved'` are never
  purged, since `latest_approved()`/`latest_approved_for_thread()` depend on
  that history. See `tests/test_pending_retention.py`.
- **SQLite connection consistency.** `AuditLogger`, `PendingCapsuleStore`, and
  `SessionTracker` each maintain their own SQLite connection against the same
  database file. All three now apply identical `PRAGMA journal_mode=WAL` +
  `PRAGMA busy_timeout` settings via a shared helper
  (`app/sqlite_utils.configure_connection`), so concurrent writes from
  different components consistently retry instead of racing with mismatched
  locking behavior. `SessionTracker` additionally caches its connection
  across calls (previously reopened per `persist()`/`load()` call).
