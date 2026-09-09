import uuid
import pytest
import asyncio
from unittest.mock import patch
from app.enforcement.mcp_server import MCPServer
from app.enforcement.proxy import MCPEnforcementProxy
from app.enforcement.tool_provider import GovernedToolHandler
from app.models import SignedCapsule, TrustTier
from app.config import Settings
from datetime import datetime, timedelta, timezone



@pytest.mark.asyncio
async def test_mcp_real_proxy_tool_list_isolation():
    # Setup real proxy and server
    class MockAuditLogger:
        async def log(self, *args, **kwargs): pass
    
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp", signing_method="ed25519")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    from app.governance.signer import Ed25519Signer
    from app.models import PolicyDecision
    
    signer = Ed25519Signer(settings, create_if_missing=True)
    
    async def create_capsule(cid, tools):
        decision = PolicyDecision(
            allow=True,
            final_tools=tools,
            final_paths=[],
            trust_tier=TrustTier.CONTRIBUTOR,
            require_human_approval=False,
            denial_reason=None,
            intent='test',
            source_hash='a'*64,
            compiler_version='1.0.0',
        )
        with patch('app.governance.signer.uuid4', return_value=uuid.UUID(cid)):
            signed = await signer.sign(decision)
        return signed
    
    # Store to simulate database lookup
    store = {
        'thread-A': await create_capsule('11111111-1111-1111-1111-111111111111', ['read_file']),
        'thread-B': await create_capsule('22222222-2222-2222-2222-222222222222', ['write_file'])
    }
    
    async def mock_loader(thread_id: str) -> SignedCapsule | None:
        return store.get(thread_id)
        
    server = MCPServer(proxy, capsule_loader=mock_loader)
    
    # Thread A dispatch
    res_A = await server.dispatch({'jsonrpc': '2.0', 'method': 'tools/list', 'id': 1}, 'thread-A')
    assert "error" not in res_A
    tools_A = [t["name"] for t in res_A["result"]["tools"]]
    assert "read_file" in tools_A
    assert "write_file" not in tools_A
    
    # Thread B dispatch
    res_B = await server.dispatch({'jsonrpc': '2.0', 'method': 'tools/list', 'id': 2}, 'thread-B')
    assert "error" not in res_B
    tools_B = [t["name"] for t in res_B["result"]["tools"]]
    assert "write_file" in tools_B
    assert "read_file" not in tools_B

@pytest.mark.asyncio
async def test_mcp_concurrent_dispatch_isolation():
    class MockAuditLogger:
        async def log(self, *args, **kwargs): pass
        
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp", signing_method="ed25519")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    from app.governance.signer import Ed25519Signer
    from app.models import PolicyDecision
    
    signer = Ed25519Signer(settings, create_if_missing=True)
    
    async def create_capsule(cid, tools):
        decision = PolicyDecision(
            allow=True,
            final_tools=tools,
            final_paths=[],
            trust_tier=TrustTier.CONTRIBUTOR,
            require_human_approval=False,
            denial_reason=None,
            intent='test',
            source_hash='a'*64,
            compiler_version='1.0.0',
        )
        with patch('app.governance.signer.uuid4', return_value=uuid.UUID(cid)):
            signed = await signer.sign(decision)
        return signed
        
    store = {
        'thread-A': await create_capsule('11111111-1111-1111-1111-111111111111', ['read_file']),
        'thread-B': await create_capsule('22222222-2222-2222-2222-222222222222', ['write_file'])
    }
    
    async def mock_loader(thread_id: str) -> SignedCapsule | None:
        # add a small delay to induce concurrency
        await asyncio.sleep(0.01)
        return store.get(thread_id)
        
    server = MCPServer(proxy, capsule_loader=mock_loader)
    
    # Run concurrently
    res_A, res_B = await asyncio.gather(
        server.dispatch({'jsonrpc': '2.0', 'method': 'tools/list', 'id': 1}, 'thread-A'),
        server.dispatch({'jsonrpc': '2.0', 'method': 'tools/list', 'id': 2}, 'thread-B')
    )
    
    assert "error" not in res_A
    assert "error" not in res_B
    
    tools_A = [t["name"] for t in res_A["result"]["tools"]]
    tools_B = [t["name"] for t in res_B["result"]["tools"]]
    
    assert "read_file" in tools_A
    assert "write_file" not in tools_A
    
    assert "write_file" in tools_B
    assert "read_file" not in tools_B

@pytest.mark.asyncio
async def test_mcp_cross_thread_tool_and_path_denial():
    class MockAuditLogger:
        async def log(self, *args, **kwargs): pass
        
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp", signing_method="ed25519")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    from app.governance.signer import Ed25519Signer
    from app.models import PolicyDecision
    
    signer = Ed25519Signer(settings, create_if_missing=True)
    
    async def create_capsule(cid, tools, paths):
        decision = PolicyDecision(
            allow=True,
            final_tools=tools,
            final_paths=paths,
            trust_tier=TrustTier.CONTRIBUTOR,
            require_human_approval=False,
            denial_reason=None,
            intent='test',
            source_hash='a'*64,
            compiler_version='1.0.0',
        )
        with patch('app.governance.signer.uuid4', return_value=uuid.UUID(cid)):
            signed = await signer.sign(decision)
        return signed
        
    store = {
        'thread-A': await create_capsule('11111111-1111-1111-1111-111111111111', ['read_file'], ['src/**/*.py']),
        'thread-B': await create_capsule('22222222-2222-2222-2222-222222222222', ['write_file'], ['docs/**/*.md'])
    }
    
    async def mock_loader(thread_id: str) -> SignedCapsule | None:
        return store.get(thread_id)
        
    server = MCPServer(proxy, capsule_loader=mock_loader)
    
    # Thread A tries to write (which is B's tool)
    res = await server.dispatch({
        'jsonrpc': '2.0', 
        'method': 'tools/call', 
        'id': 1, 
        'params': {'name': 'write_file', 'arguments': {'path': 'docs/foo.md'}}
    }, 'thread-A')
    
    assert "result" in res
    assert res["result"]["isError"] is True
    assert "Tool 'write_file' is not allowed" in res["result"]["content"][0]["text"]
    
@pytest.mark.asyncio
async def test_mcp_unregistered_thread_fails_closed():
    """tools/list returns the full catalogue when no capsule is active (so Bob
    connects and stays green), but tools/call is still blocked with no capsule.
    Enforcement is fail-closed at call time, not at list time."""
    class MockAuditLogger:
        async def log(self, *args, **kwargs): pass
        
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    server = MCPServer(proxy, capsule_loader=lambda t: None)
    
    # tools/list with no capsule must succeed (returns full catalogue so Bob connects)
    res = await server.dispatch({'jsonrpc': '2.0', 'method': 'tools/list', 'id': 1}, 'unregistered-thread')
    assert "error" not in res
    assert "result" in res
    assert len(res["result"]["tools"]) > 0  # full catalogue returned

    # tools/call with no capsule must still be blocked (returns a JSON-RPC error)
    call_res = await server.dispatch({
        'jsonrpc': '2.0', 'method': 'tools/call', 'id': 2,
        'params': {'name': 'read_file', 'arguments': {'path': 'README.md'}}
    }, 'unregistered-thread')
    assert "error" in call_res
    assert "capsule" in call_res["error"]["message"].lower()
