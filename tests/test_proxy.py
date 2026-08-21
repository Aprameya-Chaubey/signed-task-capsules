"""Tests for runtime MCP tool-call enforcement behavior."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.enforcement.mcp_server import MCPServer
from app.enforcement.proxy import MCPEnforcementProxy
from app.governance.signer import Ed25519Signer
from app.models import AuditEvent, AuditEventType, KnownTools, PolicyDecision, SignedCapsule, TrustTier


@pytest.fixture
def workspace_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "proxy"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def runtime_settings(workspace_tmp_path: Path, expiry_hours: int = 1) -> Settings:
    return Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(workspace_tmp_path / "ed25519.key"),
        CAPSULE_EXPIRY_HOURS=expiry_hours,
    )


def policy_decision(
    *,
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
        intent="Proxy test capsule",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )


async def signed_capsule(
    *,
    settings: Settings,
    tools: list[KnownTools],
    paths: list[str],
) -> SignedCapsule:
    signer = Ed25519Signer(settings=settings)
    return await signer.sign(policy_decision(tools=tools, paths=paths))


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def log(self, event: AuditEvent) -> None:
        self.events.append(event)


async def fake_tool_handler(request: dict, connection_id: str, capsule: SignedCapsule) -> dict:
    return {
        "forwarded": True,
        "connection_id": connection_id,
        "tool": request["params"]["name"],
    }


def tools_call(tool_name: str, arguments: dict, request_id: str | int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }


def test_tool_call_allowed_when_tool_and_path_are_in_scope(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )
    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(
        audit_logger=audit_logger,
        tool_handler=fake_tool_handler,
        settings=settings,
    )
    proxy.register_capsule(capsule, "session-1")

    response = asyncio.run(
        proxy.handle_tool_call(
            tools_call("read_file", {"path": "src/main.py"}),
            "session-1",
        )
    )

    assert "result" in response
    assert response["result"]["forwarded"] is True
    assert len(audit_logger.events) == 1
    assert audit_logger.events[0].event_type is AuditEventType.TOOL_ALLOWED


def test_tool_call_blocked_when_tool_not_in_allowed_tools(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )
    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(audit_logger=audit_logger, settings=settings)
    proxy.register_capsule(capsule, "session-1")

    response = asyncio.run(
        proxy.handle_tool_call(
            tools_call("write_file", {"path": "src/main.py"}),
            "session-1",
        )
    )

    assert response["error"]["code"] == -32600
    assert "blocked" in response["error"]["message"].lower()
    assert len(audit_logger.events) == 1
    assert audit_logger.events[0].event_type is AuditEventType.TOOL_BLOCKED


def test_tool_call_blocked_when_path_outside_scope(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )
    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(audit_logger=audit_logger, settings=settings)
    proxy.register_capsule(capsule, "session-1")

    response = asyncio.run(
        proxy.handle_tool_call(
            tools_call("read_file", {"path": ".env"}),
            "session-1",
        )
    )

    assert response["error"]["code"] == -32600
    assert "outside allowed target paths" in response["error"]["message"]
    assert audit_logger.events[0].event_type is AuditEventType.TOOL_BLOCKED


def test_path_traversal_attack_is_caught_after_canonicalization(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )
    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(audit_logger=audit_logger, settings=settings)
    proxy.register_capsule(capsule, "session-1")

    response = asyncio.run(
        proxy.handle_tool_call(
            tools_call("read_file", {"path": "src/../../.env"}),
            "session-1",
        )
    )

    assert response["error"]["code"] == -32600
    assert ".env" in response["error"]["message"]


def test_expired_capsule_blocks_all_calls(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )
    expired_capsule = capsule.model_copy(update={"expiry": "2000-01-01T00:00:00Z"})

    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(audit_logger=audit_logger, settings=settings)
    proxy.register_capsule(capsule, "session-1")
    proxy._capsules["session-1"] = expired_capsule

    response = asyncio.run(
        proxy.handle_tool_call(
            tools_call("read_file", {"path": "src/main.py"}),
            "session-1",
        )
    )

    assert response["error"]["code"] == -32600
    assert "expired" in response["error"]["message"].lower()


def test_no_capsule_for_session_returns_error() -> None:
    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(audit_logger=audit_logger)

    response = asyncio.run(
        proxy.handle_tool_call(
            tools_call("read_file", {"path": "src/main.py"}),
            "missing-session",
        )
    )

    assert response["error"]["code"] == -32600
    assert response["error"]["message"] == "No active capsule for session"


def test_path_extraction_finds_nested_argument_paths() -> None:
    arguments = {
        "items": [
            {
                "path": "src/main.py",
                "nested": {"backup": "C:\\repo\\src\\util.py"},
            },
            "README.md",
        ],
        "url": "https://github.com/owner/repo",
    }

    extracted = MCPEnforcementProxy._extract_paths(arguments)

    assert "src/main.py" in extracted
    assert "C:\\repo\\src\\util.py" in extracted
    assert "README.md" in extracted
    assert "https://github.com/owner/repo" not in extracted


def test_path_extraction_detects_extensionless_files() -> None:
    arguments = {
        "a": "Makefile",
        "b": "Dockerfile",
        "c": ".gitignore",
        "d": "LICENSE",
        "e": "true",
        "f": "42",
    }

    extracted = MCPEnforcementProxy._extract_paths(arguments)

    assert "Makefile" in extracted
    assert "Dockerfile" in extracted
    assert ".gitignore" in extracted
    assert "LICENSE" in extracted
    assert "true" not in extracted
    assert "42" not in extracted


def test_tools_list_only_returns_capsule_allowed_tools(workspace_tmp_path: Path) -> None:
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(
        signed_capsule(
            settings=settings,
            tools=[KnownTools.RUN_TESTS, KnownTools.READ_FILE],
            paths=["src/**"],
        )
    )

    audit_logger = FakeAuditLogger()
    proxy = MCPEnforcementProxy(audit_logger=audit_logger, settings=settings)
    proxy.register_capsule(capsule, "session-1")
    server = MCPServer(proxy)

    response = asyncio.run(
        server.dispatch(
            {
                "jsonrpc": "2.0",
                "id": "list-1",
                "method": "tools/list",
                "params": {},
            },
            "session-1",
        )
    )

    assert "result" in response
    tool_names = [tool["name"] for tool in response["result"]["tools"]]
    assert tool_names == ["read_file", "run_tests"]
