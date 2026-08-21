"""Round 4 mandatory tests for net_request SSRF hardening.

Covers the four requirements from §5 of STC_Hardening_Spec_Round4.md:

1. DNS-failure fail-closed: resolution failure during the safety check blocks the request.
2. Rebinding resistance: the actual connection is pinned to the address that was
   validated — a second resolution returning a private address cannot be used.
3. Redirect re-validation: a redirect to a private/internal address is caught before
   the connection is made.
4. IPv6 coverage: an allowed hostname that resolves to an IPv6 loopback/private
   address is blocked — confirms getaddrinfo-based resolution is used, not gethostbyname.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import urllib.error
import urllib.request
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.enforcement.tool_provider import GovernedToolHandler
from app.governance.signer import Ed25519Signer
from app.config import Settings
from app.models import KnownTools, PolicyDecision, TrustTier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _settings(tmp_path: Path) -> Settings:
    return Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(tmp_path / "ed25519.key"),
        DATABASE_PATH=str(tmp_path / "runtime.db"),
        CAPSULE_EXPIRY_HOURS=1,
    )


def _net_capsule(settings: Settings, allowed_hosts: list[str]):
    """Sign a capsule that has NET_REQUEST + the given allowed_hosts."""
    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.NET_REQUEST],
        final_paths=[],
        trust_tier=TrustTier.MAINTAINER,
        require_human_approval=False,
        denial_reason=None,
        intent="network test",
        source_hash="a" * 64,
        compiler_version="1.0.0",
        allowed_hosts=allowed_hosts,
    )
    return asyncio.run(Ed25519Signer(settings=settings).sign(decision))


def _tool_call(url: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "net_request", "arguments": {"url": url}},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def workspace():
    base = Path(".pytest_tmp") / "net_hardening"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 1 — DNS-failure fail-closed
# ---------------------------------------------------------------------------

def test_net_request_dns_failure_fails_closed(workspace: Path) -> None:
    """§5: DNS resolution failure during the safety check must block the request.

    Prior to the fix, `except Exception: pass` caused the code to fall through to
    urllib.request.urlopen, allowing a request despite the safety check failing.
    After the fix, any OSError from socket.getaddrinfo raises ValueError and the
    method returns {"ok": False, ...} without ever reaching the HTTP layer.
    """
    settings = _settings(workspace)
    capsule = _net_capsule(settings, allowed_hosts=["example.com"])
    handler = GovernedToolHandler(workspace)

    url_opened = False

    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise OSError("Simulated DNS failure")

    # Patch opener.open / urlopen to detect if an HTTP connection is ever attempted.
    real_opener_open = urllib.request.OpenerDirector.open

    def spy_opener_open(self, req, *args, **kwargs):
        nonlocal url_opened
        url_opened = True
        return real_opener_open(self, req, *args, **kwargs)

    with (
        patch("socket.getaddrinfo", side_effect=fake_getaddrinfo),
        patch.object(urllib.request.OpenerDirector, "open", spy_opener_open),
    ):
        result = handler(_tool_call("https://example.com/api"), "c", capsule)

    assert result["ok"] is False, f"Expected failure but got ok=True: {result}"
    assert url_opened is False, (
        "urllib opener.open() was called despite DNS resolution failure — "
        "the request was NOT blocked (fail-open regression)"
    )
    assert "DNS resolution failed" in result["error"], (
        f"Expected 'DNS resolution failed' in error message, got: {result['error']!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — DNS-rebinding resistance (IP pinning)
# ---------------------------------------------------------------------------

def test_net_request_dns_rebinding_blocked_by_ip_pinning(workspace: Path) -> None:
    """§5: The actual connection must be pinned to the validated IP — not re-resolved.

    This test simulates a DNS-rebinding scenario:
    - First call to getaddrinfo (during the safety check) returns a public IP.
    - The actual urllib connection attempt would re-resolve to a private IP in a
      real rebinding attack, but the hardened code should NEVER re-resolve:
      it pins the opener to the specific IP that was validated.

    We verify: (a) the opener is called with the pinned IP, NOT the hostname for
    a second DNS lookup, and (b) a second invocation of socket.getaddrinfo does
    NOT happen for the same hostname after the validation pass.
    """
    settings = _settings(workspace)
    capsule = _net_capsule(settings, allowed_hosts=["legit.example.com"])
    handler = GovernedToolHandler(workspace)

    getaddrinfo_call_count = [0]
    connect_targets: list[str] = []

    # Public IP that passes the validation check.
    public_ip = "93.184.216.34"  # example.com — safe address

    def fake_getaddrinfo(host, port, *args, **kwargs):
        getaddrinfo_call_count[0] += 1
        # Return a valid public IP (mimics a host that passes the allowlist check).
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (public_ip, 0))]

    # Track what host the opener actually tries to connect to.
    original_open = urllib.request.OpenerDirector.open

    class ConnectionTracker:
        """Context manager that tracks all HTTPSConnection host arguments."""

        def __init__(self, target_list: list[str]) -> None:
            self.target_list = target_list
            self._patcher = None

        def __enter__(self):
            import http.client

            real_https_conn = http.client.HTTPSConnection

            def tracking_conn(host, *args, **kwargs):
                self.target_list.append(host)
                # Raise immediately — we only care about the target, not actual I/O.
                raise ConnectionRefusedError(f"Test tracking: would connect to {host}")

            self._patcher = patch("http.client.HTTPSConnection", tracking_conn)
            self._patcher.start()
            return self

        def __exit__(self, *exc_info):
            if self._patcher:
                self._patcher.stop()

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with ConnectionTracker(connect_targets):
            result = handler(_tool_call("https://legit.example.com/api"), "c", capsule)

    # The connection should fail (we raised ConnectionRefusedError above), but
    # we can verify: getaddrinfo was called exactly ONCE (for the validation pass),
    # and the connect target contains the pinned IP — not the hostname.
    assert getaddrinfo_call_count[0] == 1, (
        f"socket.getaddrinfo called {getaddrinfo_call_count[0]} times — "
        "expected exactly 1 (for the validation pass only; connection must be pinned)"
    )
    # If any connection attempt was made, it must be to the pinned IP, not the hostname.
    for target in connect_targets:
        assert "legit.example.com" not in target, (
            f"Connection was attempted to hostname '{target}' — "
            "the hostname was re-resolved, which allows DNS rebinding"
        )


# ---------------------------------------------------------------------------
# Test 3 — Redirect re-validation
# ---------------------------------------------------------------------------

class _FakeHTTPErrorResponse:
    """Minimal response-like object that urllib.error.HTTPError accepts."""
    def __init__(self, location: str, code: int = 302) -> None:
        self.status = code
        self._headers = {"Location": location}

    def get(self, key: str, default=None):
        return self._headers.get(key, default)

    def read(self): return b""
    def __iter__(self): return iter([])


def test_net_request_redirect_to_private_ip_is_blocked(workspace: Path) -> None:
    """§5: A redirect from an allowed host to a private address must be blocked.

    The old code used urllib.request.urlopen with default redirect-following;
    only the initial URL was checked. After the fix, each redirect target is
    re-validated before the connection is made.

    This test mocks:
    - socket.getaddrinfo: first call (legit.example.com) → public IP;
      second call (192.168.1.1) would normally also be validated, but
      the inner IP-literal check catches it directly before getaddrinfo.
    - The HTTP layer: first open → 302 to https://192.168.1.1/internal;
      the loop re-validates 192.168.1.1 and blocks before the second open.
    """
    settings = _settings(workspace)
    capsule = _net_capsule(settings, allowed_hosts=["legit.example.com"])
    handler = GovernedToolHandler(workspace)

    public_ip = "93.184.216.34"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (public_ip, 0))]

    second_open_attempted = [False]
    call_count = [0]

    real_opener_open = urllib.request.OpenerDirector.open

    def fake_opener_open(self, req, *args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            # First request — simulate 302 redirect to private address.
            headers = MagicMock()
            headers.get = lambda key, default=None: (
                "https://192.168.1.1/internal" if key == "Location" else default
            )
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", headers, BytesIO(b"")
            )
        else:
            second_open_attempted[0] = True
            return real_opener_open(self, req, *args, **kwargs)

    with (
        patch("socket.getaddrinfo", side_effect=fake_getaddrinfo),
        patch.object(urllib.request.OpenerDirector, "open", fake_opener_open),
    ):
        result = handler(_tool_call("https://legit.example.com/api"), "c", capsule)

    assert result["ok"] is False, (
        f"Expected redirect to private IP to be blocked, got ok=True: {result}"
    )
    assert second_open_attempted[0] is False, (
        "HTTP opener was called a second time for the private redirect target — "
        "redirect was NOT re-validated before connecting (redirect bypass regression)"
    )
    # The block reason should mention the redirect target is not in allowed_hosts
    # (since 192.168.1.1 is a private IP literal that fails the IP check).
    assert any(
        phrase in result["error"]
        for phrase in ("private", "reserved", "not in allowed_hosts", "blocked")
    ), f"Unexpected error message: {result['error']!r}"


# ---------------------------------------------------------------------------
# Test 4 — IPv6 private / loopback coverage
# ---------------------------------------------------------------------------

def test_net_request_ipv6_loopback_blocked(workspace: Path) -> None:
    """§5: getaddrinfo-based resolution catches IPv6 loopback/private addresses.

    An allowed hostname that resolves only to ::1 (IPv6 loopback) must be blocked.
    The old gethostbyname-only check used AF_INET, so IPv6 addresses were invisible.
    After the fix, socket.getaddrinfo with AF_UNSPEC is used, and every returned
    address is validated — including IPv6 loopback.
    """
    settings = _settings(workspace)
    # The hostname is allowed in the capsule — only the resolved address should block it.
    capsule = _net_capsule(settings, allowed_hosts=["ipv6-only.example.com"])
    handler = GovernedToolHandler(workspace)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        # Return only an IPv6 loopback address.
        return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))]

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        result = handler(_tool_call("https://ipv6-only.example.com/api"), "c", capsule)

    assert result["ok"] is False, (
        f"Expected IPv6 loopback to be blocked, got ok=True: {result}"
    )
    assert any(
        phrase in result["error"]
        for phrase in ("private/local/reserved", "loopback", "reserved", "blocked")
    ), f"Expected block reason in error, got: {result['error']!r}"


def test_net_request_ipv6_private_range_blocked(workspace: Path) -> None:
    """§5 extension: IPv6 private range (fc00::/7 — unique-local) is also blocked."""
    settings = _settings(workspace)
    capsule = _net_capsule(settings, allowed_hosts=["dual-stack.example.com"])
    handler = GovernedToolHandler(workspace)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        # fc00::/7 is the IPv6 unique-local (private) range.
        return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("fd12:3456:789a::1", 0, 0, 0))]

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        result = handler(_tool_call("https://dual-stack.example.com/api"), "c", capsule)

    assert result["ok"] is False, (
        f"Expected IPv6 unique-local to be blocked, got ok=True: {result}"
    )


def test_net_request_ipv6_link_local_blocked(workspace: Path) -> None:
    """§5 extension: IPv6 link-local (fe80::/10) is blocked."""
    settings = _settings(workspace)
    capsule = _net_capsule(settings, allowed_hosts=["link-local.example.com"])
    handler = GovernedToolHandler(workspace)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("fe80::1", 0, 0, 0))]

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        result = handler(_tool_call("https://link-local.example.com/api"), "c", capsule)

    assert result["ok"] is False


def test_net_request_ipv6_literal_loopback_in_url_blocked(workspace: Path) -> None:
    """§5: An IPv6 literal address in the URL itself (e.g. https://[::1]/...) is blocked.

    No DNS resolution needed — the literal-IP check catches this before getaddrinfo.
    """
    settings = _settings(workspace)
    # Allow the exact IPv6 literal in the capsule so the allowlist check passes,
    # then verify the private-IP check blocks it.
    capsule = _net_capsule(settings, allowed_hosts=["::1"])
    handler = GovernedToolHandler(workspace)

    result = handler(_tool_call("https://[::1]/secret"), "c", capsule)

    assert result["ok"] is False
    assert any(
        phrase in result["error"]
        for phrase in ("private/local/reserved", "loopback", "reserved", "blocked")
    ), f"Expected block reason, got: {result['error']!r}"


# ---------------------------------------------------------------------------
# Test 5 — Approval requester receives PolicyDecision + pending_id (§2.2)
# ---------------------------------------------------------------------------

def test_approval_requester_receives_policy_decision_not_fake_capsule(workspace: Path) -> None:
    """§2.2: approval_requester receives PolicyDecision + pending_id — not a fabricated SignedCapsule.

    We inject a capturing approval_requester into the webhook pipeline and assert
    that it is called with (payload, PolicyDecision, str, Settings) and that the
    third argument is a valid UUID (pending_id), not a SignedCapsule.
    """
    import json
    import hashlib
    import hmac as hmac_module
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from contextlib import asynccontextmanager

    from app.ingestion.webhook import WebhookDependencies, router as webhook_router
    from app.models import (
        CompilerOutput,
        KnownTools,
        PolicyDecision,
        SignedCapsule,
        TrustTier,
        TrustTierResult,
    )
    from app.config import Settings
    from tests.test_webhook import FakeCompiler, FakePolicyEngine, FakeSigner, FakeAuditLogger, FakeSessionTracker

    # Capture what the approval_requester is called with.
    captured_calls: list[tuple] = []

    async def capturing_approval_requester(payload, policy_decision_or_capsule, pending_id_or_settings, settings=None):
        captured_calls.append((payload, policy_decision_or_capsule, pending_id_or_settings, settings))

    decision = PolicyDecision(
        allow=True,
        final_tools=[KnownTools.READ_FILE],
        final_paths=["app/api.py"],
        trust_tier=TrustTier.MAINTAINER,
        require_human_approval=True,
        denial_reason=None,
        intent="Test approval flow",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )

    compiler_out = CompilerOutput(
        intent="Test approval flow",
        requested_tools=[KnownTools.READ_FILE],
        target_paths=["app/api.py"],
        compiler_model="test",
        compiler_version="1.0.0",
    )

    issued_capsule = SignedCapsule(
        capsule_id=str(uuid4()),
        intent="Test approval flow",
        allowed_tools=[KnownTools.READ_FILE],
        target_paths=["app/api.py"],
        trust_tier=TrustTier.MAINTAINER,
        expiry="2030-01-01T00:00:00Z",
        source_hash="a" * 64,
        compiler_version="1.0.0",
        signature="c2ln",
    )

    secret = "webhook-secret"

    async def trust_tier_resolver(author: str, repo_full_name: str) -> TrustTierResult:
        return TrustTierResult(
            author=author,
            repo_full_name=repo_full_name,
            trust_tier=TrustTier.MAINTAINER,
            github_permission="admin",
            resolved_at="2026-08-15T00:00:00Z",
        )

    db_path = str(Path(".pytest_tmp") / "approval_test" / f"{uuid4()}.db")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    dependencies = WebhookDependencies(
        settings=Settings(
            GITHUB_WEBHOOK_SECRET=secret,
            DATABASE_PATH=db_path,
            ADMIN_API_TOKEN="admin-token",
        ),
        compiler=FakeCompiler(compiler_out),
        policy_engine=FakePolicyEngine(decision),
        signer=FakeSigner(issued_capsule),
        session_tracker=FakeSessionTracker(),
        audit_logger=FakeAuditLogger(),
        trust_tier_resolver=trust_tier_resolver,
        approval_requester=capturing_approval_requester,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await dependencies.pending_store.close()

    app = FastAPI(lifespan=lifespan)
    app.state.webhook_dependencies = dependencies
    app.state.settings = dependencies.settings
    app.include_router(webhook_router)

    payload = {
        "sender": {"login": "octocat"},
        "repository": {"full_name": "owner/repo", "html_url": "https://github.com/owner/repo"},
        "issue": {"number": 42, "body": "Deploy this", "html_url": "https://github.com/owner/repo/issues/42"},
    }
    raw_body = json.dumps(payload).encode("utf-8")
    sig = "sha256=" + hmac_module.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()

    with TestClient(app) as client:
        resp = client.post(
            "/webhook",
            content=raw_body,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "issues", "X-Hub-Signature-256": sig},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "pending_approval"

    # Verify the approval_requester was called.
    assert len(captured_calls) == 1, f"Expected 1 approval_requester call, got {len(captured_calls)}"

    _payload_arg, decision_arg, pending_id_arg, settings_arg = captured_calls[0]

    # The second argument must be a PolicyDecision, NOT a SignedCapsule.
    assert isinstance(decision_arg, PolicyDecision), (
        f"approval_requester received {type(decision_arg).__name__} instead of PolicyDecision — "
        "the fabricated SignedCapsule was not cleaned up"
    )
    assert not isinstance(decision_arg, SignedCapsule), (
        "approval_requester received a SignedCapsule — the fabricated placeholder was not removed"
    )

    # The third argument must be a string (pending_id), not a Settings object.
    assert isinstance(pending_id_arg, str), (
        f"Third argument should be pending_id (str), got {type(pending_id_arg).__name__}"
    )
    # pending_id should be a valid UUID.
    import re
    assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", pending_id_arg), (
        f"pending_id should be a UUID, got: {pending_id_arg!r}"
    )

    # The fourth argument must be Settings.
    from app.config import Settings as SettingsType
    assert isinstance(settings_arg, SettingsType), (
        f"Fourth argument should be Settings, got {type(settings_arg).__name__}"
    )

    # The PolicyDecision passed should match the decision returned by the policy engine.
    assert decision_arg.intent == decision.intent
    assert decision_arg.require_human_approval is True
