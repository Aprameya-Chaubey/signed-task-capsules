"""Send one correctly-signed test 'issues' webhook to the local governance server.

Why this exists: a hand-built curl command can't easily produce a real
HMAC-SHA256 signature or the required X-GitHub-Delivery header, so a
placeholder request just gets rejected with 401/400 before your pipeline
even runs. This script reads your real GITHUB_WEBHOOK_SECRET out of .env
and builds a request your server will actually accept.

Usage (from your project root, with the server already running):
    python scripts/send_test_webhook.py

Uses repository "owner/repo" and issue number 1, which produces thread ID
"owner/repo#1" - this MUST match the STC_THREAD_ID hardcoded in
.bob/mcp.json for Bob to find the capsule this creates. If you change one,
change the other to match.
"""

import hashlib
import hmac
import json
import re
import uuid
from pathlib import Path

import httpx

REPO_FULL_NAME = "owner/repo"
ISSUE_NUMBER = 1
ISSUE_BODY = "Please inspect README.md and fix the typo."
SERVER_URL = "http://localhost:8000/webhook"


def load_env_value(key: str, env_path: str = ".env") -> str:
    """Minimal .env reader - avoids depending on the app package being importable."""
    path = Path(env_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Could not find {env_path} - run this script from your project root "
            "(the folder that directly contains .env)."
        )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*$", line)
        if match:
            return match.group(1).strip().strip('"').strip("'")
    raise KeyError(f"{key} not found in {env_path}")


def main() -> None:
    secret = load_env_value("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise SystemExit("GITHUB_WEBHOOK_SECRET is empty in .env - set it before running this.")

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

    print(f"Sending to {SERVER_URL} as thread '{REPO_FULL_NAME}#{ISSUE_NUMBER}' ...")
    response = httpx.post(SERVER_URL, content=body, headers=headers, timeout=30.0)
    print(f"Status: {response.status_code}")
    print(response.text)

    if response.status_code != 200:
        print(
            "\nNon-200 response - check the uvicorn terminal for a traceback, "
            "and confirm the server is running on port 8000."
        )


if __name__ == "__main__":
    main()
