import pytest
import asyncio
from unittest.mock import patch
from app.enforcement.mcp_server import MCPServer
from app.enforcement.proxy import MCPEnforcementProxy
from app.enforcement.tool_provider import GovernedToolHandler
from app.models import SignedCapsule, TrustTier
from app.config import Settings
from datetime import datetime, timedelta, timezone

@pytest.fixture(autouse=True)
def mock_verify_capsule():
    with patch('app.enforcement.proxy.verify_capsule', return_value=True):
        yield

@pytest.mark.asyncio
async def test_mcp_real_proxy_tool_list_isolation():
    # Setup real proxy and server
    class MockAuditLogger:
        async def log(self, *args, **kwargs): pass
    
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    def create_capsule(cid, tools):
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        return SignedCapsule(
            capsule_id=cid,
            intent='test',
            allowed_tools=tools,
            target_paths=[],
            trust_tier=TrustTier.CONTRIBUTOR,
            expiry=expiry,
            source_hash='a'*64,
            compiler_version='1.0.0',
            signature=b''
        )
    
    # Store to simulate database lookup
    store = {
        'thread-A': create_capsule('11111111-1111-1111-1111-111111111111', ['read_file']),
        'thread-B': create_capsule('22222222-2222-2222-2222-222222222222', ['write_file'])
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
        
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    def create_capsule(cid, tools):
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        return SignedCapsule(
            capsule_id=cid,
            intent='test',
            allowed_tools=tools,
            target_paths=[],
            trust_tier=TrustTier.CONTRIBUTOR,
            expiry=expiry,
            source_hash='a'*64,
            compiler_version='1.0.0',
            signature=b''
        )
        
    store = {
        'thread-A': create_capsule('11111111-1111-1111-1111-111111111111', ['read_file']),
        'thread-B': create_capsule('22222222-2222-2222-2222-222222222222', ['write_file'])
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
        
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    def create_capsule(cid, tools, paths):
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        return SignedCapsule(
            capsule_id=cid,
            intent='test',
            allowed_tools=tools,
            target_paths=paths,
            trust_tier=TrustTier.CONTRIBUTOR,
            expiry=expiry,
            source_hash='a'*64,
            compiler_version='1.0.0',
            signature=b''
        )
        
    store = {
        'thread-A': create_capsule('11111111-1111-1111-1111-111111111111', ['read_file'], ['src/**/*.py']),
        'thread-B': create_capsule('22222222-2222-2222-2222-222222222222', ['write_file'], ['docs/**/*.md'])
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
    
    assert "error" in res
    assert res["error"]["message"] == "Capsule 11111111-1111-1111-1111-111111111111 blocked tool call: Tool 'write_file' is not allowed"
    
@pytest.mark.asyncio
async def test_mcp_unregistered_thread_fails_closed():
    class MockAuditLogger:
        async def log(self, *args, **kwargs): pass
        
    settings = Settings(github_webhook_secret="secret", workspace_root="/tmp")
    proxy = MCPEnforcementProxy(
        audit_logger=MockAuditLogger(),
        settings=settings,
        tool_handler=GovernedToolHandler(settings.workspace_root)
    )
    
    server = MCPServer(proxy, capsule_loader=lambda t: None)
    
    res = await server.dispatch({'jsonrpc': '2.0', 'method': 'tools/list', 'id': 1}, 'unregistered-thread')
    assert "error" in res
    assert res["error"]["message"] == "No active capsule for thread"
