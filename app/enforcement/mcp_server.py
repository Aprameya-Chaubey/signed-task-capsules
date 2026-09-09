"""Minimal JSON-RPC dispatcher for MCP enforcement proxy integration."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from typing import Any, Awaitable, Callable, TextIO

from fastapi import APIRouter, Header, HTTPException, Request

from app.enforcement.proxy import MCPEnforcementProxy
from app.models import SignedCapsule


def _reconfigure_stdio() -> None:
    """Switch stdin/stdout to UTF-8 on Windows (Bob spawns with cp1252 by default).

    Without this, json.dumps output containing characters outside cp1252 — such as
    the U+2264 (≤) in README.md — raises UnicodeEncodeError when written to stdout,
    silently killing the tool call response.
    """
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stdin, "reconfigure"):
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_reconfigure_stdio()


logger = logging.getLogger(__name__)

CapsuleLoader = Callable[[str], Awaitable[SignedCapsule | None]]


def _jsonrpc_error_response(
    request_id: str | int | None,
    code: int,
    message: str,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def _jsonrpc_success_response(request_id: str | int | None, result: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


TOOL_DEFINITIONS: dict[str, dict[str, Any]] = {
    "read_file": {
        "name": "read_file",
        "description": "Read the complete contents of a file at the specified path within the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file to read (e.g. 'README.md')",
                }
            },
            "required": ["path"],
        },
    },
    "write_file": {
        "name": "write_file",
        "description": "Write or overwrite content to a file at the specified path within the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file to write",
                },
                "content": {
                    "type": "string",
                    "description": "Text content to write into the file",
                },
            },
            "required": ["path", "content"],
        },
    },
    "net_request": {
        "name": "net_request",
        "description": "Make an HTTP request to an authorized destination host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The destination URL to request",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, etc.)",
                    "default": "GET",
                },
            },
            "required": ["url"],
        },
    },
    "execute_cmd": {
        "name": "execute_cmd",
        "description": "Execute a shell command within the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command line to execute",
                }
            },
            "required": ["command"],
        },
    },
    "run_tests": {
        "name": "run_tests",
        "description": "Run repository test suites.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
}


class MCPServer:
    """Dispatch MCP JSON-RPC methods through an enforcement proxy."""

    def __init__(self, proxy: MCPEnforcementProxy, capsule_loader: CapsuleLoader | None = None) -> None:
        self._proxy = proxy
        self._capsule_loader = capsule_loader

    async def _refresh_active_capsule(self, thread_id: str) -> None:
        """Re-bind the latest active capsule for the given thread_id."""

        if self._capsule_loader is None:
            return
        try:
            capsule = await self._capsule_loader(thread_id)
        except Exception as exc:
            logger.warning("Capsule loader failed: %s", exc)
            return
        if capsule is None:
            return
        if capsule.capsule_id == self._proxy.current_capsule_id(thread_id):
            return
        try:
            self._proxy.register_capsule(capsule, thread_id)
        except ValueError as exc:
            logger.warning("Could not register refreshed capsule: %s", exc)

    async def dispatch(self, request: dict[str, Any], thread_id: str) -> dict[str, Any]:
        """Dispatch one JSON-RPC payload for a specific thread."""

        if not isinstance(request, dict):
            return _jsonrpc_error_response(None, -32600, "Invalid request")

        request_id = request.get("id")
        if request.get("jsonrpc") != "2.0":
            return _jsonrpc_error_response(request_id, -32600, "Invalid JSON-RPC version")

        method = request.get("method")

        # Standard MCP lifecycle initialization
        if method == "initialize":
            client_version = request.get("params", {}).get("protocolVersion", "2024-11-05")
            return _jsonrpc_success_response(
                request_id,
                {
                    "protocolVersion": client_version,
                    "capabilities": {
                        "tools": {
                            "listChanged": False,
                        },
                    },
                    "serverInfo": {
                        "name": "stc-enforcement-proxy",
                        "version": "1.0.0",
                    },
                },
            )

        # JSON-RPC notifications (no id) must not produce a response
        if "id" not in request or request_id is None:
            return None

        if method == "ping":
            return _jsonrpc_success_response(request_id, {})

        if method == "resources/list":
            return _jsonrpc_success_response(request_id, {"resources": []})

        if method == "prompts/list":
            return _jsonrpc_success_response(request_id, {"prompts": []})

        # Authoritative thread-id enforcement
        if not thread_id:
            return _jsonrpc_error_response(request_id, -32600, "Missing or invalid thread_id")

        if method in ("tools/call", "tools/list"):
            await self._refresh_active_capsule(thread_id)

        if method == "tools/call":
            return await self._proxy.handle_tool_call(request, thread_id)

        if method == "tools/list":
            allowed_tools = self._proxy.list_allowed_tools(thread_id)
            if allowed_tools is None:
                # No active capsule yet — return the full catalogue so Bob
                # connects and shows a green indicator before the first capsule
                # is issued.  Enforcement still happens at tools/call time.
                tools = list(TOOL_DEFINITIONS.values())
            else:
                tools = [
                    TOOL_DEFINITIONS.get(
                        tool_name,
                        {
                            "name": tool_name,
                            "description": f"Governed tool: {tool_name}",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    )
                    for tool_name in allowed_tools
                ]
            return _jsonrpc_success_response(
                request_id,
                {"tools": tools},
            )

        return _jsonrpc_error_response(request_id, -32601, f"Method not found: {method}")

    async def serve_stdio(
        self,
        thread_id: str,
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        """Run line-delimited JSON-RPC dispatch over stdin/stdout for a specific thread."""

        reader = input_stream or sys.stdin
        writer = output_stream or sys.stdout

        while True:
            line = await asyncio.to_thread(reader.readline)
            if not line:
                return

            payload = line.strip()
            if not payload:
                continue

            try:
                request = json.loads(payload)
            except json.JSONDecodeError:
                response = _jsonrpc_error_response(None, -32700, "Parse error")
            else:
                response = await self.dispatch(request, thread_id)

            if response is not None:
                encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=False)
                await asyncio.to_thread(writer.write, f"{encoded}\n")
                await asyncio.to_thread(writer.flush)

    def create_http_router(self) -> APIRouter:
        """Expose one HTTP JSON-RPC endpoint for network-mode local demos."""

        router = APIRouter(tags=["mcp"])

        @router.post("/mcp")
        async def mcp_dispatch(
            payload: dict[str, Any],
            x_thread_id: str | None = Header(default=None, alias="X-Thread-ID"),
        ) -> dict[str, Any]:
            if not x_thread_id:
                raise HTTPException(status_code=400, detail="Missing X-Thread-ID header")
            return await self.dispatch(payload, x_thread_id)

        return router


def create_app_mcp_router() -> APIRouter:
    """Return an MCP HTTP router that resolves the proxy from app state.

    This allows the FastAPI app to mount the JSON-RPC endpoint at import time
    while the enforcement proxy itself is constructed during startup.
    """

    router = APIRouter(tags=["mcp"])

    @router.post("/mcp")
    async def mcp_dispatch(
        request: Request,
        payload: dict[str, Any],
        x_thread_id: str | None = Header(default=None, alias="X-Thread-ID"),
    ) -> dict[str, Any]:
        proxy = getattr(request.app.state, "enforcement_proxy", None)
        if not isinstance(proxy, MCPEnforcementProxy):
            raise HTTPException(status_code=503, detail="Enforcement proxy unavailable")
        if not x_thread_id:
            raise HTTPException(status_code=400, detail="Missing X-Thread-ID header")

        store = getattr(request.app.state, "pending_store", None)
        loader: CapsuleLoader | None = None
        if store is not None:
            async def loader(_tid: str, _store=store) -> SignedCapsule | None:
                return await _store.latest_approved_for_thread(_tid)

        return await MCPServer(proxy, capsule_loader=loader).dispatch(payload, x_thread_id)

    return router


async def _serve_stdio(thread_id: str | None) -> None:
    """Start the stdio JSON-RPC server bound to the latest active capsule."""

    from app.audit.logger import AuditLogger
    from app.config import get_settings
    from app.enforcement.tool_provider import GovernedToolHandler
    from app.pending_store import PendingCapsuleStore

    settings = get_settings()
    audit_logger = AuditLogger(settings.database_path)
    await audit_logger.init_db()

    proxy = MCPEnforcementProxy(
        audit_logger=audit_logger,
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root),
    )
    store = PendingCapsuleStore(settings.database_path)
    await store.init_db()

    resolved_thread = thread_id or os.getenv("STC_THREAD_ID")
    if not resolved_thread or resolved_thread.startswith("${"):
        raise ValueError("STC_THREAD_ID must be provided as an environment variable or argument (e.g. owner/repo#N)")
    async def _load_active(_tid: str) -> SignedCapsule | None:
        return await store.latest_approved_for_thread(_tid)

    active_capsule = await store.latest_approved_for_thread(resolved_thread)
    if active_capsule is not None:
        try:
            proxy.register_capsule(active_capsule, resolved_thread)
        except ValueError as exc:
            logger.warning("Active capsule could not be registered: %s", exc)
    else:
        logger.warning(
            "No active capsule found for thread %s; tool calls will be blocked", resolved_thread
        )

    server = MCPServer(proxy, capsule_loader=_load_active)
    try:
        await server.serve_stdio(resolved_thread)
    finally:
        await asyncio.gather(
            audit_logger.close(),
            store.close(),
            return_exceptions=True,
        )


def main(argv: list[str] | None = None) -> None:
    """Console entrypoint used by Bob's MCP server registration."""

    parser = argparse.ArgumentParser(description="STC MCP enforcement server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport to serve on (stdio for Bob, http for local testing)",
    )
    parser.add_argument("--host", default=None, help="HTTP host (http transport only)")
    parser.add_argument("--port", type=int, default=None, help="HTTP port (http transport only)")
    parser.add_argument(
        "--thread-id",
        default=None,
        help="Thread/session identifier to bind the active capsule to",
    )
    args = parser.parse_args(argv)

    if args.transport == "http":
        import uvicorn
        from fastapi import FastAPI, Depends
        from app.auth import require_admin_auth
        
        http_app = FastAPI(title="STC MCP Server")
        http_app.include_router(create_app_mcp_router(), dependencies=[Depends(require_admin_auth)])
        
        host = args.host or "127.0.0.1"
        port = args.port or 3000
        
        uvicorn.run(http_app, host=host, port=port)
        return

    asyncio.run(_serve_stdio(args.thread_id))


if __name__ == "__main__":
    main()
