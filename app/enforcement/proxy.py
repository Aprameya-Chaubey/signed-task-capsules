"""Runtime MCP tool-call enforcement against active signed capsules."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable

from pydantic import ValidationError

from app.audit.logger import AuditLogger
from app.config import Settings
from app.enforcement.scope_checker import canonicalize_path, extract_paths, path_allowed
from app.governance.verifier import verify_capsule
from app.models import AuditEvent, AuditEventType, SignedCapsule, ToolCallDecision, ToolCallRequest


ToolHandler = Callable[[dict[str, Any], str, SignedCapsule], Any | Awaitable[Any]]


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


def _jsonrpc_success_response(
    request_id: str | int,
    result: Any,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


async def _default_tool_handler(request: dict[str, Any], connection_id: str, capsule: SignedCapsule) -> dict[str, Any]:
    _ = connection_id
    _ = capsule
    return {
        "ok": True,
        "forwarded": True,
        "request": request,
    }


class MCPEnforcementProxy:
    """Validate and forward MCP tool calls under per-session capsule constraints."""

    def __init__(
        self,
        audit_logger: AuditLogger,
        tool_handler: ToolHandler | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._audit_logger = audit_logger
        self._tool_handler = tool_handler or _default_tool_handler
        self._settings = settings
        self._capsules: dict[str, SignedCapsule] = {}

    def register_capsule(self, capsule: SignedCapsule, connection_id: str) -> None:
        """Validate and bind a signed capsule to one active connection."""

        if not connection_id:
            raise ValueError("connection_id must be non-empty")
        if capsule.is_expired():
            raise ValueError("Cannot register an expired capsule")
        if not verify_capsule(capsule, settings=self._settings):
            raise ValueError("Capsule signature verification failed")

        self._capsules[connection_id] = capsule

    def list_allowed_tools(self, connection_id: str) -> list[str] | None:
        """Return the currently allowed tool names for one connection."""

        capsule = self._capsules.get(connection_id)
        if capsule is None:
            return None
        if capsule.is_expired():
            return None
        return [tool.value for tool in capsule.allowed_tools]

    def current_capsule_id(self, connection_id: str) -> str | None:
        """Return the capsule id currently bound to a connection, if any."""

        capsule = self._capsules.get(connection_id)
        return capsule.capsule_id if capsule is not None else None

    async def handle_tool_call(self, request: dict[str, Any], connection_id: str) -> dict[str, Any]:
        """Evaluate one tools/call request against the active capsule."""

        request_id = request.get("id") if isinstance(request, dict) else None
        try:
            validated_request = ToolCallRequest.model_validate(request)
        except ValidationError:
            return _jsonrpc_error_response(request_id, -32600, "Invalid tools/call request")

        capsule = self._capsules.get(connection_id)
        if capsule is None:
            return _jsonrpc_error_response(
                validated_request.id,
                -32600,
                "No active capsule for session",
            )

        tool_name = validated_request.params.name
        matched_paths = [
            self._canonicalize_path(path)
            for path in self._extract_paths(validated_request.params.arguments)
        ]

        # Note: net_request destination validation is enforced via allowlist,
        # getaddrinfo-based DNS resolution with private-IP rejection, IP-pinned
        # connections, and per-redirect re-validation. See docs/known-limitations.md.

        if capsule.is_expired():
            reason = "Capsule has expired"
            await self._log_decision(
                capsule=capsule,
                tool_name=tool_name,
                allowed=False,
                block_reason=reason,
                matched_paths=matched_paths,
            )
            # MCP spec: structurally valid but blocked → success envelope with isError
            return _jsonrpc_success_response(
                validated_request.id,
                {"content": [{"type": "text", "text": self._blocked_message(capsule.capsule_id, reason)}], "isError": True},
            )

        allowed_tools = {allowed_tool.value for allowed_tool in capsule.allowed_tools}
        if tool_name not in allowed_tools:
            reason = f"Tool '{tool_name}' is not allowed"
            await self._log_decision(
                capsule=capsule,
                tool_name=tool_name,
                allowed=False,
                block_reason=reason,
                matched_paths=matched_paths,
            )
            return _jsonrpc_success_response(
                validated_request.id,
                {"content": [{"type": "text", "text": self._blocked_message(capsule.capsule_id, reason)}], "isError": True},
            )

        for matched_path in matched_paths:
            if not self._path_allowed(matched_path, capsule.target_paths):
                reason = f"Path '{matched_path}' is outside allowed target paths"
                await self._log_decision(
                    capsule=capsule,
                    tool_name=tool_name,
                    allowed=False,
                    block_reason=reason,
                    matched_paths=matched_paths,
                )
                return _jsonrpc_success_response(
                    validated_request.id,
                    {"content": [{"type": "text", "text": self._blocked_message(capsule.capsule_id, reason)}], "isError": True},
                )

        # Log the tool call attempt BEFORE executing the handler, so a
        # forensic record always exists even if the handler crashes or the
        # post-execution log fails (closes the fail-open audit evasion).
        await self._log_decision(
            capsule=capsule,
            tool_name=tool_name,
            allowed=True,
            block_reason="pre_execution_attempt",
            matched_paths=matched_paths,
        )

        try:
            forwarded_result = self._tool_handler(request, connection_id, capsule)
            if inspect.isawaitable(forwarded_result):
                forwarded_result = await forwarded_result

            ok = bool(forwarded_result.get("ok")) if isinstance(forwarded_result, dict) else False
            await self._log_decision(
                capsule=capsule,
                tool_name=tool_name,
                allowed=ok,
                block_reason=None if ok else forwarded_result.get("error", "handler_rejected"),
                matched_paths=matched_paths,
            )
            return _jsonrpc_success_response(validated_request.id, self._to_mcp_result(forwarded_result))
        except Exception as exc:
            await self._log_decision(
                capsule=capsule,
                tool_name=tool_name,
                allowed=False,
                block_reason=f"handler_exception: {type(exc).__name__}: {exc}",
                matched_paths=matched_paths,
            )
            return _jsonrpc_error_response(validated_request.id, -32603, "Internal tool error")

    async def _log_decision(
        self,
        capsule: SignedCapsule,
        tool_name: str,
        allowed: bool,
        block_reason: str | None,
        matched_paths: list[str],
    ) -> None:
        decision = ToolCallDecision(
            capsule_id=capsule.capsule_id,
            tool_name=tool_name,
            allowed=allowed,
            block_reason=block_reason,
            matched_paths=matched_paths,
        )

        await self._audit_logger.log(
            AuditEvent(
                capsule_id=decision.capsule_id,
                event_type=(
                    AuditEventType.TOOL_ALLOWED
                    if decision.allowed
                    else AuditEventType.TOOL_BLOCKED
                ),
                trust_tier=capsule.trust_tier,
                tool_name=decision.tool_name,
                target_path=("; ".join(decision.matched_paths) if decision.matched_paths else None),
                detail=decision.block_reason,
            )
        )

    @staticmethod
    def _to_mcp_result(handler_result: dict[str, Any]) -> dict[str, Any]:
        """Translate GovernedToolHandler's internal dict into an MCP content envelope.

        GovernedToolHandler returns {"ok": bool, "content": str, ...} or
        {"ok": False, "error": str, ...}.  The MCP spec requires the tools/call
        result to be {"content": [{"type": "text", "text": "..."}], "isError": bool}.
        """
        if not isinstance(handler_result, dict):
            return {"content": [{"type": "text", "text": str(handler_result)}], "isError": True}

        ok = bool(handler_result.get("ok"))

        if ok:
            # Successful tool execution — wrap content string in MCP array envelope
            raw = handler_result.get("content", "")
            if not isinstance(raw, str):
                raw = str(raw)
            return {"content": [{"type": "text", "text": raw}], "isError": False}
        else:
            # Tool returned an error — surface it as an MCP isError result
            error_msg = handler_result.get("error", "Tool execution failed")
            return {"content": [{"type": "text", "text": error_msg}], "isError": True}

    @staticmethod
    def _blocked_message(capsule_id: str, reason: str) -> str:
        return f"Capsule {capsule_id} blocked tool call: {reason}"

    @staticmethod
    def _extract_paths(arguments: dict[str, Any]) -> list[str]:
        return extract_paths(arguments)

    @staticmethod
    def _canonicalize_path(path: str) -> str:
        return canonicalize_path(path)

    @staticmethod
    def _path_allowed(canonical_path: str, allowed_patterns: list[str]) -> bool:
        return path_allowed(canonical_path, allowed_patterns)
