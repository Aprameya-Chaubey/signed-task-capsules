"""
Standalone synchronous MCP stdio server for IBM Bob / Cline integration.

This script deliberately avoids asyncio so it runs correctly even when
spawned by Bob/Cline with a minimal Windows environment that lacks the
SYSTEMROOT variable required by Python's asyncio WinError-10106 socket layer.

It reads the active approved capsule directly from SQLite (synchronously via
the sqlite3 stdlib module) and handles read_file / write_file tool calls.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Ensure stdin/stdout are UTF-8 on Windows regardless of the console code page.
# Bob spawns this process with a minimal environment; the default cp1252 encoding
# would silently crash when reading a file that contains characters such as
# U+2264 (≤) that are legal UTF-8 but undefined in cp1252.
# ---------------------------------------------------------------------------

def _reconfigure_stdio() -> None:
    """Switch sys.stdin and sys.stdout to UTF-8, replacing unencodable bytes."""
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Capsule / SQLite helpers
# ---------------------------------------------------------------------------

def _get_db_path() -> str:
    """Return the absolute SQLite database path used by the STC service."""
    base = Path(__file__).resolve().parent.parent.parent  # project root
    env_file = base / ".env"
    db_path = str((base / "data" / "audit.db").resolve())  # default
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("DATABASE_PATH="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                p = Path(val)
                db_path = str((base / p).resolve()) if not p.is_absolute() else str(p)
                break
    return db_path


def _get_workspace_root() -> Path:
    """Return the absolute workspace root used by the STC service."""
    base = Path(__file__).resolve().parent.parent.parent
    env_file = base / ".env"
    workspace_root = base
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("WORKSPACE_ROOT="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                p = Path(val)
                workspace_root = (base / p).resolve() if not p.is_absolute() else p
                break
    return workspace_root


def _is_expired(capsule: dict) -> bool:
    """Check if the capsule has expired."""
    try:
        from datetime import datetime, timezone
        inner = capsule.get("capsule", capsule)
        expiry_str = inner.get("expiry")
        if not expiry_str:
            return False
        expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > expiry_dt
    except Exception:
        return False


def _load_capsule(thread_id: str) -> dict | None:
    """Load the latest approved and unexpired capsule for thread_id from SQLite."""
    db_path = _get_db_path()
    if not Path(db_path).exists():
        sys.stderr.write(f"[stc-mcp] DB file not found: {db_path}\n")
        sys.stderr.flush()
        return None
    try:
        con = sqlite3.connect(db_path, timeout=5)
        con.row_factory = sqlite3.Row
        row = con.execute(
            """
            SELECT capsule_json FROM pending_capsules
            WHERE thread_id = ? AND status = 'approved'
            ORDER BY resolved_at DESC, created_at DESC LIMIT 1
            """,
            (thread_id,),
        ).fetchone()
        con.close()
        if row:
            capsule = json.loads(row["capsule_json"])
            if _is_expired(capsule):
                sys.stderr.write("[stc-mcp] Capsule is expired\n")
                sys.stderr.flush()
                return None
            return capsule
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[stc-mcp] SQLite error: {exc}\n")
        sys.stderr.flush()
    return None


def _log_audit(
    capsule_id: str | None,
    event_type: str,
    trust_tier: str | None,
    tool_name: str | None,
    target_path: str | None,
    detail: str | None,
) -> None:
    """Write an audit row synchronously into audit_events."""
    from datetime import datetime, timezone
    db_path = _get_db_path()
    try:
        con = sqlite3.connect(db_path, timeout=5)
        con.execute(
            """
            INSERT INTO audit_events
                (timestamp, capsule_id, event_type, trust_tier, tool_name, target_path, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                capsule_id,
                event_type,
                trust_tier,
                tool_name,
                target_path,
                detail,
            ),
        )
        con.commit()
        con.close()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[stc-mcp] audit write error: {exc}\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def _read_file(path_arg: str, capsule: dict, workspace_root: Path) -> dict:
    """Read a file if it is in the capsule's target_paths."""
    inner = capsule.get("capsule", capsule)
    capsule_id = inner.get("capsule_id", "")
    target_paths = inner.get("target_paths", [])

    # Normalise: strip leading slashes / backslashes for comparison
    norm_req = path_arg.lstrip("/\\").replace("\\", "/")
    allowed = any(
        norm_req == tp.lstrip("/\\").replace("\\", "/") or
        norm_req.startswith(tp.lstrip("/\\").replace("\\", "/").rstrip("/") + "/")
        for tp in target_paths
    )
    if not allowed:
        reason = f"Path '{path_arg}' is outside allowed target paths"
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Capsule {capsule_id} blocked tool call: {reason}"}],
        }

    full_path = workspace_root / path_arg
    try:
        full_path = full_path.resolve()
    except Exception:
        pass

    # Use is_relative_to() (Python 3.9+) instead of string-prefix check to
    # prevent false matches against paths like /workspace-suffix/evil.py.
    try:
        is_safe = full_path.is_relative_to(workspace_root)
    except Exception:
        is_safe = str(full_path).startswith(str(workspace_root) + os.sep)

    if not is_safe:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Capsule {capsule_id} blocked tool call: Path escape attempt blocked"}],
        }

    try:
        text = full_path.read_text(encoding="utf-8", errors="replace")
        return {"content": [{"type": "text", "text": text}]}
    except FileNotFoundError:
        return {"isError": True, "content": [{"type": "text", "text": f"File not found: {path_arg}"}]}
    except Exception as exc:
        return {"isError": True, "content": [{"type": "text", "text": f"Read error: {exc}"}]}


# ---------------------------------------------------------------------------
# Tool definitions (shown to Bob via tools/list)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS = [
    {
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
    {
        "name": "write_file",
        "description": "Write content to a file at the specified path within the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path to the file to write"},
                "content": {"type": "string", "description": "Content to write to the file"},
            },
            "required": ["path", "content"],
        },
    },
]


# ---------------------------------------------------------------------------
# Main dispatch loop
# ---------------------------------------------------------------------------

def main():
    thread_id = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--thread-id" and i + 1 < len(args):
            thread_id = args[i + 1]
    thread_id = thread_id or os.environ.get("STC_THREAD_ID", "")

    workspace_root = _get_workspace_root()

    sys.stderr.write(f"[stc-mcp] starting sync stdio server thread={thread_id!r} root={workspace_root}\n")
    sys.stderr.flush()

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            _send(_err(None, -32700, f"Parse error: {exc}"))
            continue

        req_id = req.get("id")
        method = req.get("method", "")

        # Notifications have no id — must NOT send a response
        if "id" not in req:
            continue

        if method == "initialize":
            pv = req.get("params", {}).get("protocolVersion", "2024-11-05")
            _send(_ok(req_id, {
                "protocolVersion": pv,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "stc-enforcement-proxy", "version": "1.0.0"},
            }))
            continue

        if method == "ping":
            _send(_ok(req_id, {}))
            continue

        if method == "resources/list":
            _send(_ok(req_id, {"resources": []}))
            continue

        if method == "prompts/list":
            _send(_ok(req_id, {"prompts": []}))
            continue

        if method == "tools/list":
            capsule = _load_capsule(thread_id) if thread_id else None
            if capsule is None:
                # Return the full tool list so Bob connects; enforcement happens at call time
                _send(_ok(req_id, {"tools": TOOL_DEFINITIONS}))
            else:
                inner = capsule.get("capsule", capsule)
                allowed = set(inner.get("allowed_tools", []))
                tools = [t for t in TOOL_DEFINITIONS if t["name"] in allowed]
                _send(_ok(req_id, {"tools": tools}))
            continue

        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments") or {}

            capsule = _load_capsule(thread_id) if thread_id else None
            if capsule is None:
                _log_audit(None, "tool_blocked", None, tool_name, arguments.get("path"), "No active capsule for thread")
                _send(_ok(req_id, {"isError": True, "content": [{"type": "text", "text": "Blocked: no active signed task capsule for this session."}]}))
                continue

            inner = capsule.get("capsule", capsule)
            capsule_id = inner.get("capsule_id")
            trust_tier = inner.get("trust_tier")
            allowed_tools = inner.get("allowed_tools", [])

            if tool_name not in allowed_tools:
                reason = f"Tool '{tool_name}' is not allowed"
                block_msg = f"Capsule {capsule_id} blocked tool call: {reason}"
                _log_audit(capsule_id, "tool_blocked", trust_tier, tool_name, arguments.get("path"), reason)
                _send(_ok(req_id, {"isError": True, "content": [{"type": "text", "text": block_msg}]}))
                continue

            if tool_name == "read_file":
                path_arg = arguments.get("path", "")
                result = _read_file(path_arg, capsule, workspace_root)
                blocked = result.get("isError", False)
                # Extract the raw reason from the block message for the audit detail.
                # The content text has format "Capsule <id> blocked tool call: <reason>"
                # or "File not found: ..." or "Read error: ...".
                if blocked:
                    content_text = result.get("content", [{}])[0].get("text", "")
                    prefix = f"Capsule {capsule_id} blocked tool call: "
                    reason_for_audit = content_text[len(prefix):] if content_text.startswith(prefix) else content_text
                else:
                    reason_for_audit = None
                _log_audit(
                    capsule_id=capsule_id,
                    event_type="tool_blocked" if blocked else "tool_allowed",
                    trust_tier=trust_tier,
                    tool_name=tool_name,
                    target_path=path_arg,
                    detail=reason_for_audit,
                )
                _send(_ok(req_id, result))
            else:
                _send(_ok(req_id, {"isError": True, "content": [{"type": "text", "text": f"Tool '{tool_name}' is not implemented in this sync proxy."}]}))
            continue

        # Unknown method
        _send(_err(req_id, -32601, f"Method not found: {method}"))


if __name__ == "__main__":
    main()
