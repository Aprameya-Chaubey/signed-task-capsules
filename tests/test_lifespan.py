import uuid
import asyncio
import httpx
from app.main import lifespan
from fastapi import FastAPI
from unittest.mock import patch, AsyncMock, MagicMock


async def test_lifespan_manages_resources():
    app = FastAPI()
    
    with patch("app.main.AuditLogger.init_db", new_callable=AsyncMock) as mock_audit_init, \
         patch("app.main.AuditLogger.close", new_callable=AsyncMock) as mock_audit_close, \
         patch("app.main.PendingCapsuleStore.init_db", new_callable=AsyncMock) as mock_pending_init, \
         patch("app.main.PendingCapsuleStore.close", new_callable=AsyncMock) as mock_pending_close, \
         patch("app.main.SessionTracker.load", new_callable=AsyncMock) as mock_session_load, \
         patch("app.main.SessionTracker.persist", new_callable=AsyncMock) as mock_session_persist, \
         patch("httpx.AsyncClient.aclose", new_callable=AsyncMock) as mock_http_close:
        
        async with lifespan(app):
            # Assert init methods were called
            mock_audit_init.assert_called_once()
            mock_pending_init.assert_called_once()
            mock_session_load.assert_called_once()
            
            # Assert state was populated
            assert hasattr(app.state, "audit_logger")
            assert hasattr(app.state, "pending_store")
            assert hasattr(app.state, "http_client")
            assert isinstance(app.state.http_client, httpx.AsyncClient)
            
            # Assert close methods have not been called yet
            mock_audit_close.assert_not_called()
            mock_pending_close.assert_not_called()
            mock_session_persist.assert_not_called()
            mock_http_close.assert_not_called()
            
        # Assert close methods were called
        mock_audit_close.assert_called_once()
        mock_pending_close.assert_called_once()
        mock_session_persist.assert_called_once()
        mock_http_close.assert_called_once()

def test_lifespan_runner():
    asyncio.run(test_lifespan_manages_resources())
