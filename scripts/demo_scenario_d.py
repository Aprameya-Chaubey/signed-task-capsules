"""Scenario D demo: the governed MCP runtime path Bob uses under stc-governed mode.

Unlike A/B/C (which prove capsule issuance math), this scenario issues a capsule
through the webhook, then loads it from the shared SQLite store exactly as the
out-of-process MCP server does, and dispatches real tool calls through the
governed tool handler — proving the forced-MCP runtime end to end.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from app.enforcement.mcp_server import MCPServer
from app.enforcement.proxy import MCPEnforcementProxy
from app.enforcement.tool_provider import GovernedToolHandler
from app.models import CompilerOutput, GovernancePipelineOutput, KnownTools, TrustTier
from app.pending_store import PendingCapsuleStore
from scripts.demo_common import build_demo_app, issue_payload, post_webhook


def _tools_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": name,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def run_scenario() -> dict[str, Any]:
    work_dir = Path(".pytest_tmp") / "demo-governed" / str(uuid4())
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "src").mkdir(parents=True, exist_ok=True)
    (work_dir / "src" / "main.py").write_text("print('hello from governed tool')\n", encoding="utf-8")

    compiler_output = CompilerOutput(
        intent="Read and update project source",
        requested_tools=[KnownTools.READ_FILE, KnownTools.WRITE_FILE],
        target_paths=["src/**"],
        compiler_model="demo-compiler",
        compiler_version="1.0.0",
    )

    context = build_demo_app(
        [compiler_output],
        trust_tier=TrustTier.CONTRIBUTOR,
        author="contributor",
        work_dir=work_dir,
    )

    with TestClient(context.app) as client:
        response = post_webhook(
            client,
            payload=issue_payload("Read and update project source", issue_number=404),
            event_type="issues",
            secret=context.secret,
        )
    pipeline_output = GovernancePipelineOutput.model_validate(response.json())

    # Load the capsule from the shared store exactly as the MCP child process does.
    store = PendingCapsuleStore(context.settings.database_path)
    proxy = MCPEnforcementProxy(
        audit_logger=context.audit_logger,
        settings=context.settings,
        tool_handler=GovernedToolHandler(work_dir),
    )

    async def _load_active(_connection_id: str):
        if store._connection is None:
            await store.init_db()
        return await store.latest_approved()

    server = MCPServer(proxy, capsule_loader=_load_active)

    async def _drive() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        allowed_read = await server.dispatch(
            _tools_call("read_file", {"path": "src/main.py"}), "bob-session"
        )
        governed_write = await server.dispatch(
            _tools_call("write_file", {"path": "src/patch.py", "content": "# governed edit\n"}),
            "bob-session",
        )
        blocked_env = await server.dispatch(
            _tools_call("read_file", {"path": ".env"}), "bob-session"
        )
        return allowed_read, governed_write, blocked_env

    allowed_read, governed_write, blocked_env = asyncio.run(_drive())

    return {
        "scenario": "D",
        "status": pipeline_output.status,
        "capsule_loaded_from_store": pipeline_output.capsule_id is not None,
        "governed_read_ok": allowed_read.get("result", {}).get("ok") is True,
        "governed_read_content": allowed_read.get("result", {}).get("content"),
        "governed_write_ok": governed_write.get("result", {}).get("ok") is True,
        "patch_written": (work_dir / "src" / "patch.py").exists(),
        "blocked_env_read": "error" in blocked_env,
    }


def main() -> None:
    result = run_scenario()
    print("Scenario D: Governed MCP Runtime (stc-governed path)")
    print(f"Webhook status: {result['status']}")
    print(f"Capsule retrievable by MCP server: {result['capsule_loaded_from_store']}")
    print(f"Governed read executed in scope: {result['governed_read_ok']}")
    print(f"Governed write executed in scope: {result['governed_write_ok']}")
    print(f"Out-of-scope .env read blocked: {result['blocked_env_read']}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
