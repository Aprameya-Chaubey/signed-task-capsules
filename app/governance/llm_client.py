"""Text-in/JSON-out clients for the compiler's supported LLM providers."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.config import Settings


logger = logging.getLogger(__name__)


class LLMClientError(RuntimeError):
    """Raised when an LLM provider cannot produce a usable completion."""


class LLMClient(ABC):
    """Provider-independent interface with no tool or function-call capability."""

    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        response_schema: dict[str, Any],
    ) -> str:
        """Return the provider's JSON text completion."""

    @abstractmethod
    async def aclose(self) -> None:
        """Close the underlying HTTP client, if owned by this instance."""


class OpenAIClient(LLMClient):
    """OpenAI-compatible Chat Completions client using strict JSON Schema output."""

    endpoint = "https://api.openai.com/v1/chat/completions"

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        if client is not None:
            self._owns_client = False
            self._client = client
        else:
            self._owns_client = True
            self._client = httpx.AsyncClient(timeout=30.0, transport=transport)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        response_schema: dict[str, Any],
    ) -> str:
        if not self._settings.llm_api_key:
            raise LLMClientError("LLM_API_KEY is not configured")

        payload = {
            "model": self._settings.llm_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "capsule_request",
                    "strict": True,
                    "schema": response_schema,
                },
            },
        }
        headers = {
            "Authorization": f"Bearer {self._settings.llm_api_key}",
            "Content-Type": "application/json",
        }
        response = await self._client.post(self.endpoint, headers=headers, json=payload)
        response.raise_for_status()

        try:
            return response.json()["choices"][0]["message"]["content"]
        except (IndexError, KeyError, TypeError) as exc:
            raise LLMClientError("OpenAI-compatible response had no message content") from exc


class WatsonxClient(LLMClient):
    """watsonx.ai text-chat client using JSON mode and local schema validation."""

    iam_endpoint = "https://iam.cloud.ibm.com/identity/token"
    default_base_url = "https://us-south.ml.cloud.ibm.com"
    api_version = "2025-10-25"

    def __init__(
        self,
        settings: Settings,
        *,
        project_id: str | None = None,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        # PLACEHOLDER: Requires watsonx.ai project ID. See .env.example.
        self._project_id = project_id if project_id is not None else settings.watsonx_project_id
        self._base_url = base_url or settings.watsonx_url or self.default_base_url
        if client is not None:
            self._owns_client = False
            self._client = client
        else:
            self._owns_client = True
            self._client = httpx.AsyncClient(timeout=30.0, transport=transport)
        self._iam_token: str | None = None
        self._iam_token_expires_at: float = 0.0
        self._token_lock = asyncio.Lock()
        if not self._project_id:
            logger.warning("WATSONX_PROJECT_ID not set — compiler will use safe fallback")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        response_schema: dict[str, Any],
    ) -> str:
        if not self._settings.llm_api_key:
            raise LLMClientError("LLM_API_KEY is not configured")
        if not self._project_id:
            raise LLMClientError("WATSONX_PROJECT_ID is not configured")

        schema_instruction = json.dumps(response_schema, separators=(",", ":"))
        watsonx_system_prompt = (
            f"{system_prompt}\nReturn JSON that conforms exactly to this schema: "
            f"{schema_instruction}"
        )
        token_request = {
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": self._settings.llm_api_key,
        }
        chat_payload = {
            "model_id": self._settings.llm_model,
            "project_id": self._project_id,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": watsonx_system_prompt},
                {
                    "role": "user",
                    "content": [{"type": "text", "text": user_message}],
                },
            ],
        }
        token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        chat_url = f"{self._base_url.rstrip('/')}/ml/v1/text/chat?version={self.api_version}"

        async with self._token_lock:
            if not self._iam_token or time.time() > self._iam_token_expires_at:
                token_response = await self._client.post(
                    self.iam_endpoint, headers=token_headers, data=token_request
                )
                token_response.raise_for_status()
                try:
                    data = token_response.json()
                    self._iam_token = data["access_token"]
                    self._iam_token_expires_at = time.time() + data.get("expires_in", 3600) - 60
                except (KeyError, TypeError) as exc:
                    raise LLMClientError("watsonx IAM response had no access token") from exc

        access_token = self._iam_token
        
        chat_response = await self._client.post(
            chat_url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            json=chat_payload,
        )
        chat_response.raise_for_status()

        try:
            return chat_response.json()["choices"][0]["message"]["content"]
        except (IndexError, KeyError, TypeError) as exc:
            raise LLMClientError("watsonx response had no message content") from exc


def create_llm_client(
    settings: Settings,
    *,
    client: httpx.AsyncClient | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> LLMClient:
    """Create the configured text-only LLM client."""

    if settings.llm_provider == "openai":
        return OpenAIClient(settings, client=client, transport=transport)
    if settings.llm_provider == "watsonx":
        return WatsonxClient(settings, client=client, transport=transport)
    raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")
