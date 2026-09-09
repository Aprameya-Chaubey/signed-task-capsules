"""Regression tests for confirmed audit findings (Audits.md).

Each test class maps 1-to-1 to a confirmed fix, guarding against re-introduction.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.enforcement.path_utils import match_pattern
from app.enforcement.proxy import MCPEnforcementProxy
from app.enforcement.scope_checker import _looks_like_path, extract_paths
from app.governance.compiler import TaskCompiler
from app.governance.policy import PolicyEngine
from app.models import (
    AuditEvent,
    AuditEventType,
    CompilerOutput,
    KnownTools,
    PolicyDecision,
    SessionHistory,
    SignedCapsule,
    TrustTier,
)
from app.pending_store import PendingCapsuleStore


# ─── shared helpers ────────────────────────────────────────────────────────────


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def log(self, event: AuditEvent) -> None:
        self.events.append(event)


def _fresh_session() -> SessionHistory:
    return SessionHistory(thread_id="owner/repo#1")


def _policy_decision(
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
        intent="Regression test",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )


async def _signed_capsule(
    settings: Settings,
    tools: list[KnownTools],
    paths: list[str],
    tier: TrustTier = TrustTier.CONTRIBUTOR,
) -> SignedCapsule:
    from app.governance.signer import Ed25519Signer
    signer = Ed25519Signer(settings=settings)
    return await signer.sign(_policy_decision(tools, paths, tier))


@pytest.fixture
def audit_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "audit_findings"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _rt_settings(tmp: Path) -> Settings:
    return Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(tmp / "ed25519.key"),
        CAPSULE_EXPIRY_HOURS=1,
    )


def _tools_call(name: str, arguments: dict, rid: str | int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


# ─── Fix 1: Newline injection bypass (scope_checker.py) ───────────────────────


class TestNewlineInjectionBypass:
    """Newline-injected paths must still be extracted so the allowlist can block them."""

    def test_path_with_injected_newline_is_still_identified(self):
        assert _looks_like_path("src/main.py\n") is True

    def test_root_path_with_injected_newline_is_still_identified(self):
        assert _looks_like_path("/etc/passwd\n") is True

    def test_multiline_code_content_not_extracted_as_path(self):
        """Multi-line code/text (e.g. file content) must not be treated as a path."""
        paths = extract_paths({"content": "# heading\nprint('hi')\n"})
        for p in paths:
            assert "/" not in p or p.startswith("http"), (
                f"Code content incorrectly extracted as path: {p!r}"
            )

    def test_bare_newline_is_not_a_path(self):
        assert _looks_like_path("\n") is False

    def test_proxy_blocks_newline_injected_out_of_scope_path(self, audit_tmp_path: Path):
        settings = _rt_settings(audit_tmp_path)
        capsule = asyncio.run(
            _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**"])
        )
        audit = FakeAuditLogger()
        proxy = MCPEnforcementProxy(audit_logger=audit, settings=settings)
        proxy.register_capsule(capsule, "s")

        # ".env\n" — injected newline; stripped value ".env" is outside src/**
        response = asyncio.run(
            proxy.handle_tool_call(_tools_call("read_file", {"path": ".env\n"}), "s")
        )
        blocked = (
            response.get("result", {}).get("isError") is True
            or "error" in response
        )
        assert blocked, "Newline-injected .env path was not blocked by the allowlist"


# ─── Fix 2: Glob intersection exfiltration (policy.py) ───────────────────────


class TestGlobIntersectionDenial:
    """Broad target-path globs that could expand to denied files must be filtered."""

    def _eval(self, paths: list[str], tier: TrustTier = TrustTier.EXTERNAL) -> PolicyDecision:
        engine = PolicyEngine()
        output = CompilerOutput(
            intent="test",
            requested_tools=[KnownTools.READ_FILE],
            target_paths=paths,
            compiler_model="t",
            compiler_version="1.0.0",
        )
        return engine.evaluate(output, tier, _fresh_session(), "a" * 64)

    def test_src_star_star_denied_for_external(self):
        """src/** can expand to src/.env — must not appear in final_paths."""
        decision = self._eval(["src/**"])
        assert "src/**" not in decision.final_paths, (
            "src/** was approved for EXTERNAL — glob intersection bypass still open"
        )

    def test_src_star_star_py_allowed_for_external(self):
        """src/**/*.py cannot match .env or *.pem — must be approved."""
        decision = self._eval(["src/**/*.py"])
        assert decision.allow is True
        assert "src/**/*.py" in decision.final_paths

    def test_src_star_star_pem_denied_for_external(self):
        """src/**/*.pem matches **/*.pem denied pattern — must be removed."""
        decision = self._eval(["src/**/*.pem"])
        assert "src/**/*.pem" not in decision.final_paths

    def test_unanchored_glob_denied_as_overly_broad(self):
        """**/*.md (no concrete dir prefix) must be denied as overly broad."""
        decision = self._eval(["**/*.md"])
        assert decision.allow is False
        assert decision.denial_reason is not None
        assert "overly broad" in decision.denial_reason

    def test_anchored_specific_glob_allowed(self):
        """src/**/*.md must be approved for EXTERNAL — no overlap with denied patterns."""
        decision = self._eval(["src/**/*.md"])
        assert decision.allow is True
        assert "src/**/*.md" in decision.final_paths


# ─── Fix 3: Missing allowed_hosts in compiler schema (compiler.py) ────────────


class TestCompilerAllowedHosts:
    """allowed_hosts must be in the schema and propagated through parsing."""

    def test_schema_includes_allowed_hosts(self):
        schema = TaskCompiler.CAPSULE_REQUEST_SCHEMA
        assert "allowed_hosts" in schema["properties"], (
            "allowed_hosts missing from CAPSULE_REQUEST_SCHEMA"
        )

    def test_parse_completion_propagates_allowed_hosts(self, audit_tmp_path: Path):
        settings = Settings(
            SIGNING_METHOD="ed25519",
            ED25519_PRIVATE_KEY_PATH=str(audit_tmp_path / "key"),
            LLM_API_KEY="test",
        )
        compiler = TaskCompiler(settings=settings)
        payload = json.dumps({
            "intent": "Fetch data",
            "requested_tools": ["net_request"],
            "target_paths": [],
            "allowed_hosts": ["api.example.com", "data.example.org"],
        })
        result = compiler._parse_completion(payload)
        assert result.allowed_hosts == ["api.example.com", "data.example.org"]

    def test_parse_completion_allows_missing_allowed_hosts(self, audit_tmp_path: Path):
        """allowed_hosts is optional — its absence must not raise."""
        settings = Settings(
            SIGNING_METHOD="ed25519",
            ED25519_PRIVATE_KEY_PATH=str(audit_tmp_path / "key"),
            LLM_API_KEY="test",
        )
        compiler = TaskCompiler(settings=settings)
        payload = json.dumps({
            "intent": "Read files",
            "requested_tools": ["read_file"],
            "target_paths": ["src/**/*.py"],
        })
        result = compiler._parse_completion(payload)
        assert result.allowed_hosts == []

    def test_parse_completion_rejects_unknown_fields(self, audit_tmp_path: Path):
        settings = Settings(
            SIGNING_METHOD="ed25519",
            ED25519_PRIVATE_KEY_PATH=str(audit_tmp_path / "key"),
            LLM_API_KEY="test",
        )
        compiler = TaskCompiler(settings=settings)
        payload = json.dumps({
            "intent": "test",
            "requested_tools": [],
            "target_paths": [],
            "injected_field": "bad",
        })
        with pytest.raises(ValueError, match="capsule request fields"):
            compiler._parse_completion(payload)


# ─── Fix 4: Audit log truncation (proxy.py) ───────────────────────────────────


class TestAuditLogAllPaths:
    """All matched paths must be recorded in the audit log, not just the first."""

    def test_multiple_matched_paths_all_appear_in_log(self, audit_tmp_path: Path):
        settings = _rt_settings(audit_tmp_path)
        capsule = asyncio.run(
            _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**", "docs/**"])
        )
        audit = FakeAuditLogger()

        async def handler(req, cid, cap):
            return {"ok": True}

        proxy = MCPEnforcementProxy(
            audit_logger=audit, tool_handler=handler, settings=settings
        )
        proxy.register_capsule(capsule, "s")

        asyncio.run(
            proxy.handle_tool_call(
                _tools_call("read_file", {"path": "src/main.py", "backup": "docs/notes.md"}), "s"
            )
        )

        all_logged = " ".join(e.target_path or "" for e in audit.events)
        assert "src/main.py" in all_logged, "src/main.py missing from audit log"
        assert "docs/notes.md" in all_logged, "docs/notes.md missing from audit log (truncation bug)"


# ─── Fix 5: MCP protocol violation (proxy.py) ─────────────────────────────────


class TestMCPProtocolCompliance:
    """Policy blocks use JSON-RPC success + isError:true, not transport errors."""

    def test_blocked_tool_returns_success_is_error(self, audit_tmp_path: Path):
        settings = _rt_settings(audit_tmp_path)
        capsule = asyncio.run(
            _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**"])
        )
        audit = FakeAuditLogger()
        proxy = MCPEnforcementProxy(audit_logger=audit, settings=settings)
        proxy.register_capsule(capsule, "s")

        res = asyncio.run(
            proxy.handle_tool_call(_tools_call("write_file", {"path": "src/x.py"}), "s")
        )
        assert "error" not in res, "Policy block returned JSON-RPC transport error (MCP violation)"
        assert res.get("result", {}).get("isError") is True

    def test_out_of_scope_path_returns_success_is_error(self, audit_tmp_path: Path):
        settings = _rt_settings(audit_tmp_path)
        capsule = asyncio.run(
            _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**"])
        )
        audit = FakeAuditLogger()
        proxy = MCPEnforcementProxy(audit_logger=audit, settings=settings)
        proxy.register_capsule(capsule, "s")

        res = asyncio.run(
            proxy.handle_tool_call(_tools_call("read_file", {"path": ".env"}), "s")
        )
        assert "error" not in res
        assert res.get("result", {}).get("isError") is True

    def test_expired_capsule_returns_success_is_error(self, audit_tmp_path: Path):
        settings = _rt_settings(audit_tmp_path)
        capsule = asyncio.run(
            _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**"])
        )
        expired = capsule.model_copy(update={"expiry": "2000-01-01T00:00:00Z"})
        audit = FakeAuditLogger()
        proxy = MCPEnforcementProxy(audit_logger=audit, settings=settings)
        proxy.register_capsule(capsule, "s")
        proxy._capsules["s"] = expired

        res = asyncio.run(
            proxy.handle_tool_call(_tools_call("read_file", {"path": "src/x.py"}), "s")
        )
        assert "error" not in res
        assert res.get("result", {}).get("isError") is True

    def test_missing_session_still_uses_transport_error(self):
        """No-capsule is a structural transport error, not a policy block."""
        audit = FakeAuditLogger()
        proxy = MCPEnforcementProxy(audit_logger=audit)
        res = asyncio.run(
            proxy.handle_tool_call(_tools_call("read_file", {"path": "src/x.py"}), "no-sess")
        )
        assert "error" in res
        assert res["error"]["code"] == -32600


# ─── Fix 6: Forensic audit evasion (proxy.py) ─────────────────────────────────


class TestPreExecutionAuditLogging:
    """A pre-execution audit entry must be written before the tool handler runs."""

    def test_pre_execution_entry_exists_before_handler(self, audit_tmp_path: Path):
        settings = _rt_settings(audit_tmp_path)
        capsule = asyncio.run(
            _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**"])
        )
        audit = FakeAuditLogger()
        handler_saw_n_events: list[int] = []

        async def ordered_handler(req, cid, cap):
            handler_saw_n_events.append(len(audit.events))
            return {"ok": True}

        proxy = MCPEnforcementProxy(
            audit_logger=audit, tool_handler=ordered_handler, settings=settings
        )
        proxy.register_capsule(capsule, "s")
        asyncio.run(
            proxy.handle_tool_call(_tools_call("read_file", {"path": "src/main.py"}), "s")
        )

        assert handler_saw_n_events, "Handler never called"
        assert handler_saw_n_events[0] >= 1, (
            "Handler ran before any audit entry — fail-open forensic evasion possible"
        )
        pre = [e for e in audit.events if e.detail == "pre_execution_attempt"]
        assert len(pre) == 1, f"Expected 1 pre_execution_attempt log, got {len(pre)}"


# ─── Fix 7: ReDoS in path globbing (path_utils.py) ────────────────────────────


class TestReDoSResistance:
    """Memoized glob matching must complete in bounded time for adversarial patterns."""

    def test_many_consecutive_stars_completes_fast(self):
        path = "a/b/c/d/e/f/g/h/i/j/k"
        pattern = "**/**/**/**/**/**/**/**/**/**/*.py"
        start = time.perf_counter()
        result = match_pattern(path, pattern)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"Glob matching took {elapsed:.3f}s — possible ReDoS"
        assert result is False  # path doesn't end in .py

    def test_memoization_correctness(self):
        assert match_pattern("src/main.py", "src/**") is True
        assert match_pattern("src/a/b/c/main.py", "src/**/*.py") is True
        assert match_pattern(".env", "**/.env") is True
        assert match_pattern("src/main.py", "**/.env") is False
        assert match_pattern("secrets/api.key", "**/*.key") is True
        assert match_pattern("other/file.md", "**/*.key") is False


# ─── Fix 8: Dead code in resolve() (pending_store.py) ────────────────────────


class TestResolveDeadCode:
    """resolve() must succeed because capsules are stored with status 'approved'."""

    def test_resolve_returns_capsule_for_approved_status(self, audit_tmp_path: Path):
        async def _run():
            settings = _rt_settings(audit_tmp_path)
            capsule = await _signed_capsule(settings, [KnownTools.READ_FILE], ["src/**"])
            store = PendingCapsuleStore(str(audit_tmp_path / "resolve_test.db"))
            await store.init_db()
            # Persist the capsule the same way the production code does
            await store.record_issued(capsule, "thread-1")
            result = await store.resolve(capsule.capsule_id, "approved")
            assert result is not None, (
                "resolve() returned None for an 'approved' capsule — dead-code bug reintroduced"
            )
            await store.close()

        asyncio.run(_run())


# ─── Fix 9: Missing database indexes (pending_store.py) ──────────────────────


class TestDatabaseIndexes:
    """Both pending tables must have the declared indexes after init_db()."""

    def test_all_declared_indexes_exist(self, audit_tmp_path: Path):
        async def _run():
            store = PendingCapsuleStore(str(audit_tmp_path / "idx_test.db"))
            await store.init_db()
            cursor = await store._connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='index' "
                "AND tbl_name IN ('pending_capsules','pending_approvals') "
                "ORDER BY name"
            )
            names = {row[0] for row in await cursor.fetchall()}
            for expected in [
                "idx_pending_capsules_thread_status",
                "idx_pending_capsules_resolved_at",
                "idx_pending_approvals_status",
                "idx_pending_approvals_resolved_at",
            ]:
                assert expected in names, f"Missing DB index: {expected}"
            await store.close()

        asyncio.run(_run())


# ─── Fix 10: Processing state leak (pending_store.py) ────────────────────────


class TestProcessingStateLeak:
    """expire_stale_pending_approvals must expire stuck 'processing' rows."""

    def test_stale_processing_row_is_expired(self, audit_tmp_path: Path):
        async def _run():
            store = PendingCapsuleStore(str(audit_tmp_path / "proc_test.db"))
            await store.init_db()
            conn = store._connection
            pid = str(uuid4())
            old_ts = "2000-01-01T00:00:00.000Z"
            await conn.execute(
                "INSERT INTO pending_approvals "
                "(pending_id, policy_decision, thread_id, status, created_at) "
                "VALUES (?, ?, 'thread-x', 'processing', ?)",
                (pid, "{}", old_ts),
            )
            await conn.commit()
            expired = await store.expire_stale_pending_approvals(ttl=timedelta(seconds=1))
            assert pid in expired, (
                "Stale 'processing' row was NOT expired — state-machine leak reintroduced"
            )
            await store.close()

        asyncio.run(_run())
