"""
Demo webhook sender for the Signed Task Capsules recording.

This script does everything needed for the demo in one shot:
  1. Resets the session history for the demo thread (clean room)
  2. Sends a correctly-signed GitHub-style webhook
  3. If the response is 'issued' → done, capsule is live
  4. If the response is 'pending_approval' → auto-approves via the admin API
  5. Prints the final issued capsule JSON so it appears on screen during recording

Beat 5 command:
    python scripts/send_demo_webhook.py

Uses repository "owner/repo" and issue number 1, producing thread ID
"owner/repo#1" — this MUST match STC_THREAD_ID in .bob/mcp.json.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import uuid
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# Demo configuration — matches .bob/mcp.json and custom_modes.yaml
# ---------------------------------------------------------------------------
REPO_FULL_NAME = "owner/repo"
ISSUE_NUMBER = 1
ISSUE_BODY = "Please inspect README.md and fix the typo."
SERVER_URL = "http://localhost:8000"
THREAD_ID = f"{REPO_FULL_NAME}#{ISSUE_NUMBER}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_env_value(key: str, env_path: str = ".env") -> str:
    path = Path(env_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Could not find {env_path}. Run this script from your project root "
            "(the folder that directly contains .env)."
        )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*$", line)
        if match:
            return match.group(1).strip().strip('"').strip("'")
    raise KeyError(f"{key} not found in {env_path}")


def get_db_path() -> Path:
    val = load_env_value("DATABASE_PATH")
    p = Path(val)
    return (Path(".") / p).resolve() if not p.is_absolute() else p


def _safe_delete(con: sqlite3.Connection, sql: str, params: tuple = ()) -> None:
    """Execute a DELETE, silently ignoring 'no such table' errors on first run."""
    try:
        con.execute(sql, params)
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc).lower():
            raise


def clean_session(db_path: Path) -> None:
    """Delete all rows for the demo thread so the session counter resets to 0."""
    if not db_path.exists():
        return
    con = sqlite3.connect(str(db_path), timeout=10)
    # Wipe session tracker rows for this thread so capsule counter = 0
    _safe_delete(con, "DELETE FROM session_history WHERE thread_id = ?", (THREAD_ID,))
    _safe_delete(con, "DELETE FROM session_tools WHERE thread_id = ?", (THREAD_ID,))
    # Remove old capsules for this thread so the DB starts clean
    _safe_delete(
        con,
        "DELETE FROM pending_capsules WHERE thread_id = ? AND status != 'approved'",
        (THREAD_ID,),
    )
    # Remove any pending_approvals for this thread
    _safe_delete(con, "DELETE FROM pending_approvals WHERE thread_id = ?", (THREAD_ID,))
    # Remove audit rows so dashboard starts empty
    _safe_delete(con, "DELETE FROM audit_events")
    con.commit()
    con.close()
    print("[clean-room] OK  Database reset -- session history cleared, audit events wiped.")


def reset_server_session(admin_token: str) -> None:
    """Clear the server's in-memory session state for the demo thread.

    The server keeps escalation counters in memory; simply clearing the
    SQLite rows is not enough when the server is already running.
    This call hits the admin reset endpoint to wipe in-memory state too.
    """
    try:
        r = httpx.delete(
            f"{SERVER_URL}/sessions",
            params={"thread_id": THREAD_ID},
            headers={"X-Admin-Token": admin_token},
            timeout=10.0,
        )
        if r.status_code == 200:
            print("[clean-room] OK  Server in-memory session reset.")
        else:
            print(f"[clean-room] WARN  Session reset returned HTTP {r.status_code}: {r.text}")
    except Exception as exc:  # noqa: BLE001
        print(f"[clean-room] WARN  Could not reach server for session reset: {exc}")
        print("[clean-room]       (Start the server first: uvicorn app.main:app --port 8000)")


def send_webhook(secret: str) -> dict:
    payload = {
        "action": "opened",
        "issue": {"number": ISSUE_NUMBER, "body": ISSUE_BODY},
        "sender": {"login": "contributor"},
        "repository": {"full_name": REPO_FULL_NAME},
    }
    body = json.dumps(payload).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": str(uuid.uuid4()),
        "X-Hub-Signature-256": f"sha256={signature}",
    }
    print(f"[webhook] Sending to {SERVER_URL}/webhook as thread '{THREAD_ID}' ...")
    r = httpx.post(f"{SERVER_URL}/webhook", content=body, headers=headers, timeout=60.0)
    if r.status_code != 200:
        raise RuntimeError(f"Webhook returned HTTP {r.status_code}: {r.text}")
    return r.json()


def approve_capsule(capsule_id: str, admin_token: str) -> dict:
    print(f"[approval] Auto-approving capsule {capsule_id} ...")
    r = httpx.post(
        f"{SERVER_URL}/capsules/{capsule_id}/approve",
        headers={"X-Admin-Token": admin_token},
        timeout=60.0,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Approval returned HTTP {r.status_code}: {r.text}")
    return r.json()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    secret = load_env_value("GITHUB_WEBHOOK_SECRET")
    admin_token = load_env_value("ADMIN_API_TOKEN")
    db_path = get_db_path()

    # Step 1: Clean room (SQLite rows)
    clean_session(db_path)

    # Step 2: Reset the server's in-memory session state
    reset_server_session(admin_token)

    # Step 3: Send webhook
    result = send_webhook(secret)
    status = result.get("status")
    print(f"[webhook] Status: {status}")

    # Step 4: If pending, auto-approve
    if status == "pending_approval":
        capsule_id = result.get("capsule_id")
        if not capsule_id:
            raise RuntimeError("Got pending_approval but no capsule_id in response")
        result = approve_capsule(capsule_id, admin_token)
        status = result.get("status")
        print(f"[approval] Status: {status}")

    if status != "issued":
        raise RuntimeError(f"Unexpected final status: {status}\nFull response: {result}")

    # Step 5: Print clean output for the camera
    capsule = result.get("capsule", {})
    print()
    print("=" * 60)
    print("  [ISSUED]  SIGNED TASK CAPSULE")
    print("=" * 60)
    print(f"  capsule_id   : {capsule.get('capsule_id')}")
    print(f"  intent       : {capsule.get('intent')}")
    print(f"  allowed_tools: {capsule.get('allowed_tools')}")
    print(f"  target_paths : {capsule.get('target_paths')}")
    print(f"  trust_tier   : {capsule.get('trust_tier')}")
    print(f"  expiry       : {capsule.get('expiry')}")
    print("=" * 60)
    print()
    print("  Bob can now read README.md -- and nothing else.")
    print()


if __name__ == "__main__":
    main()
