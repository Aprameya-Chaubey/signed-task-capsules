"""Tests for the governed MCP runtime: tool provider, capsule persistence, hot reload."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.enforcement.mcp_server import MCPServer
from app.enforcement.proxy import MCPEnforcementProxy
from app.enforcement.tool_provider import GovernedToolHandler
from app.governance.signer import Ed25519Signer
from app.models import KnownTools, PolicyDecision, SignedCapsule, TrustTier
from app.pending_store import PendingCapsuleStore


@pytest.fixture
def workspace_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "governed"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def runtime_settings(workspace_tmp_path: Path) -> Settings:
    return Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(workspace_tmp_path / "ed25519.key"),
        DATABASE_PATH=str(workspace_tmp_path / "runtime.db"),
        CAPSULE_EXPIRY_HOURS=1,
    )


def policy_decision(
    *, tools: list[KnownTools], paths: list[str], tier: TrustTier = TrustTier.CONTRIBUTOR
) -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        final_tools=tools,
        final_paths=paths,
        trust_tier=tier,
        require_human_approval=False,
        denial_reason=None,
        intent="Governed runtime test",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )


async def _sign(settings: Settings, tools: list[KnownTools], paths: list[str]) -> SignedCapsule:
    return await Ed25519Signer(settings=settings).sign(policy_decision(tools=tools, paths=paths))


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list = []

    async def log(self, event) -> None:
        self.events.append(event)


def tools_call(name: str, arguments: dict, request_id: str | int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def test_governed_handler_reads_file_in_scope(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.READ_FILE], ["src/**"]))
    (workspace_tmp_path / "src").mkdir()
    (workspace_tmp_path / "src" / "main.py").write_text("print('hi')", encoding="utf-8")
    handler = GovernedToolHandler(workspace_tmp_path)

    result = handler(tools_call("read_file", {"path": "src/main.py"}), "c", capsule)

    assert result["ok"] is True
    assert result["content"] == "print('hi')"


def test_governed_handler_writes_file_in_scope(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.WRITE_FILE], ["out/**"]))
    handler = GovernedToolHandler(workspace_tmp_path)

    result = handler(tools_call("write_file", {"path": "out/new.txt", "content": "data"}), "c", capsule)

    assert result["ok"] is True
    assert (workspace_tmp_path / "out" / "new.txt").read_text(encoding="utf-8") == "data"


def test_governed_handler_blocks_path_escape(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.READ_FILE], ["**"]))
    handler = GovernedToolHandler(workspace_tmp_path)

    result = handler(tools_call("read_file", {"path": "../../etc/passwd"}), "c", capsule)

    assert result["ok"] is False
    assert "escapes" in result["error"]


def test_governed_handler_reports_unsupported_tool(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.EXECUTE_CMD], ["**"]))
    handler = GovernedToolHandler(workspace_tmp_path)

    result = handler(tools_call("execute_cmd", {"cmd": "ls"}), "c", capsule)

    assert result["ok"] is False
    assert "no governed implementation" in result["error"]


def test_issued_capsule_is_retrievable_from_store(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    store = PendingCapsuleStore(settings.database_path)

    async def run() -> tuple[SignedCapsule, SignedCapsule | None]:
        await store.init_db()
        capsule = await _sign(settings, [KnownTools.READ_FILE], ["src/**"])
        await store.record_issued(capsule, "owner/repo#1")
        return capsule, await store.latest_approved()

    capsule, loaded = asyncio.run(run())
    assert loaded is not None
    assert loaded.capsule_id == capsule.capsule_id


def test_mcp_server_hot_reloads_active_capsule(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    (workspace_tmp_path / "src").mkdir()
    (workspace_tmp_path / "src" / "main.py").write_text("x=1", encoding="utf-8")

    store = PendingCapsuleStore(settings.database_path)
    proxy = MCPEnforcementProxy(
        audit_logger=FakeAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(workspace_tmp_path),
    )

    async def loader(_connection_id: str) -> SignedCapsule | None:
        return await store.latest_approved()

    server = MCPServer(proxy, capsule_loader=loader)

    async def run() -> tuple[dict, dict]:
        await store.init_db()
        before = await server.dispatch(tools_call("read_file", {"path": "src/main.py"}), "conn")
        capsule = await _sign(settings, [KnownTools.READ_FILE], ["src/**"])
        await store.record_issued(capsule, "owner/repo#1")
        after = await server.dispatch(tools_call("read_file", {"path": "src/main.py"}), "conn")
        return before, after

    before, after = asyncio.run(run())
    assert "error" in before
    assert "result" in after
    assert after["result"]["ok"] is True
    assert after["result"]["content"] == "x=1"


def test_governed_handler_net_request_blocked_host(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        Ed25519Signer(settings=settings).sign(
            PolicyDecision(
                allow=True,
                final_tools=[KnownTools.NET_REQUEST],
                final_paths=[],
                trust_tier=TrustTier.CONTRIBUTOR,
                require_human_approval=False,
                denial_reason=None,
                intent="test",
                source_hash="a" * 64,
                compiler_version="1.0.0",
                allowed_hosts=["api.github.com"]
            )
        )
    )
    handler = GovernedToolHandler(workspace_tmp_path)

    result = handler(tools_call("net_request", {"url": "https://example.com/api"}), "c", capsule)
    
    assert result["ok"] is False
    assert "not in allowed_hosts" in result["error"]

def test_governed_handler_net_request_blocked_localhost(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        Ed25519Signer(settings=settings).sign(
            PolicyDecision(
                allow=True,
                final_tools=[KnownTools.NET_REQUEST],
                final_paths=[],
                trust_tier=TrustTier.CONTRIBUTOR,
                require_human_approval=False,
                denial_reason=None,
                intent="test",
                source_hash="a" * 64,
                compiler_version="1.0.0",
                allowed_hosts=["127.0.0.1", "localhost"]
            )
        )
    )
    handler = GovernedToolHandler(workspace_tmp_path)

    result = handler(tools_call("net_request", {"url": "https://localhost:8080"}), "c", capsule)

    assert result["ok"] is False
    # New hardened implementation uses getaddrinfo (covers IPv6) and produces a
    # per-address message; check for the family of terms rather than the exact string.
    assert any(
        phrase in result["error"]
        for phrase in (
            "private/local",
            "loopback",
            "reserved",
            "private/local/reserved",
        )
    )
