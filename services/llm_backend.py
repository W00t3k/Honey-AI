"""
Unified LLM backend — supports Groq, Ollama (local), and any OpenAI-compatible API.

LLMHoney showed that local models like Qwen2.5:1.5B and Phi3:3.8B offer the best
balance of accuracy and latency for high-volume honeypot simulation.  This module
lets operators switch backends without touching any other code.
"""

import json
import os
from typing import AsyncIterator, Optional

import httpx
from rich.console import Console

from services.config import get_config

console = Console()


# ── Backend registry ───────────────────────────────────────────────────────────

class LLMBackend:
    """Abstract base for all LLM backends."""

    name: str = "base"

    async def complete(
        self,
        messages: list[dict],
        *,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> str:
        raise NotImplementedError

    async def stream(
        self,
        messages: list[dict],
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        raise NotImplementedError

    async def close(self) -> None:
        pass


# ── Groq backend ───────────────────────────────────────────────────────────────

class GroqBackend(LLMBackend):
    """Groq Cloud API — high-speed inference on llama/mixtral."""

    name = "groq"
    _API_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._reload()

    def _reload(self):
        cfg = get_config()
        self.api_key = cfg.get("groq_api_key") or os.getenv("GROQ_API_KEY", "")
        self.model   = cfg.get("groq_chat_model", "llama-3.3-70b-versatile")
        self.enabled = bool(self.api_key) and cfg.get("groq_enabled", True)

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    async def complete(self, messages, *, system_prompt="", temperature=0.7, max_tokens=1024) -> str:
        if not self.enabled:
            return ""
        full = [{"role": "system", "content": system_prompt}] + messages[-20:] if system_prompt else messages[-20:]
        try:
            c = await self._client_()
            r = await c.post(
                self._API_URL,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": full, "stream": False,
                      "temperature": temperature, "max_tokens": max_tokens},
            )
            if r.status_code == 200:
                choices = r.json().get("choices", [])
                return (choices[0].get("message", {}).get("content") or "").strip()
            console.print(f"[red]Groq error {r.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]Groq complete error: {e}[/red]")
        return ""

    async def stream(self, messages, system_prompt="") -> AsyncIterator[str]:
        if not self.enabled:
            yield 'data: {"choices":[{"delta":{"content":"Unavailable"},"finish_reason":null}]}\n\n'
            yield "data: [DONE]\n\n"
            return
        full = [{"role": "system", "content": system_prompt}] + messages[-20:] if system_prompt else messages[-20:]
        try:
            c = await self._client_()
            async with c.stream(
                "POST", self._API_URL,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": full, "stream": True, "temperature": 0.7, "max_tokens": 1024},
            ) as resp:
                if resp.status_code != 200:
                    yield 'data: {"choices":[{"delta":{"content":"Connection error"},"finish_reason":null}]}\n\n'
                    yield "data: [DONE]\n\n"
                    return
                async for line in resp.aiter_lines():
                    if line:
                        yield f"{line}\n\n"
        except Exception as e:
            console.print(f"[red]Groq stream error: {e}[/red]")
            yield 'data: {"choices":[{"delta":{"content":"Stream error"},"finish_reason":null}]}\n\n'
            yield "data: [DONE]\n\n"

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


# ── Ollama backend ─────────────────────────────────────────────────────────────

class OllamaBackend(LLMBackend):
    """
    Ollama local inference — Qwen2.5, Phi3, Mistral, Llama, etc.

    Ollama exposes an OpenAI-compatible /v1/ endpoint when started with:
        OLLAMA_HOST=0.0.0.0 ollama serve

    Best models for honeypot simulation (from LLMHoney research):
        - Shell emulation: qwen2.5:1.5b  (fast, low RAM)
        - HTTP generation: phi3:3.8b     (good HTML/JSON output)
        - Analysis:        qwen2.5:7b    (accuracy vs latency tradeoff)
    """

    name = "ollama"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._reload()

    def _reload(self):
        cfg = get_config()
        self.base_url = cfg.get("ollama_base_url", "http://localhost:11434")
        self.model    = cfg.get("ollama_model", "qwen2.5:1.5b")
        self.enabled  = cfg.get("ollama_enabled", False)

    @property
    def _api_url(self):
        return f"{self.base_url.rstrip('/')}/v1/chat/completions"

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def complete(self, messages, *, system_prompt="", temperature=0.7, max_tokens=1024) -> str:
        if not self.enabled:
            return ""
        full = [{"role": "system", "content": system_prompt}] + messages[-20:] if system_prompt else messages[-20:]
        try:
            c = await self._client_()
            r = await c.post(
                self._api_url,
                headers={"Content-Type": "application/json"},
                json={"model": self.model, "messages": full, "stream": False,
                      "temperature": temperature, "max_tokens": max_tokens},
            )
            if r.status_code == 200:
                choices = r.json().get("choices", [])
                return (choices[0].get("message", {}).get("content") or "").strip()
            console.print(f"[yellow]Ollama error {r.status_code}: {r.text[:100]}[/yellow]")
        except httpx.ConnectError:
            console.print("[yellow]Ollama not reachable — is `ollama serve` running?[/yellow]")
        except Exception as e:
            console.print(f"[red]Ollama complete error: {e}[/red]")
        return ""

    async def stream(self, messages, system_prompt="") -> AsyncIterator[str]:
        if not self.enabled:
            yield 'data: {"choices":[{"delta":{"content":"Ollama unavailable"},"finish_reason":null}]}\n\n'
            yield "data: [DONE]\n\n"
            return
        full = [{"role": "system", "content": system_prompt}] + messages[-20:] if system_prompt else messages[-20:]
        try:
            c = await self._client_()
            async with c.stream(
                "POST", self._api_url,
                headers={"Content-Type": "application/json"},
                json={"model": self.model, "messages": full, "stream": True,
                      "temperature": 0.7, "max_tokens": 1024},
            ) as resp:
                async for line in resp.aiter_lines():
                    if line:
                        yield f"{line}\n\n"
        except Exception as e:
            console.print(f"[red]Ollama stream error: {e}[/red]")
            yield 'data: {"choices":[{"delta":{"content":"Ollama error"},"finish_reason":null}]}\n\n'
            yield "data: [DONE]\n\n"

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def list_models(self) -> list[str]:
        """Return available Ollama models (for settings UI)."""
        try:
            c = await self._client_()
            r = await c.get(f"{self.base_url.rstrip('/')}/api/tags", timeout=5.0)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
        return []


# ── Custom OpenAI-compatible backend ──────────────────────────────────────────

class OpenAICompatBackend(LLMBackend):
    """
    Any OpenAI-compatible API endpoint — vLLM, LM Studio, Together.ai, etc.
    """

    name = "openai_compat"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._reload()

    def _reload(self):
        cfg = get_config()
        self.base_url = cfg.get("custom_llm_base_url", "")
        self.api_key  = cfg.get("custom_llm_api_key", "none")
        self.model    = cfg.get("custom_llm_model", "default")
        self.enabled  = bool(self.base_url) and cfg.get("custom_llm_enabled", False)

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def complete(self, messages, *, system_prompt="", temperature=0.7, max_tokens=1024) -> str:
        if not self.enabled:
            return ""
        full = [{"role": "system", "content": system_prompt}] + messages[-20:] if system_prompt else messages[-20:]
        api_url = f"{self.base_url.rstrip('/')}/v1/chat/completions"
        try:
            c = await self._client_()
            r = await c.post(
                api_url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": full, "stream": False,
                      "temperature": temperature, "max_tokens": max_tokens},
            )
            if r.status_code == 200:
                choices = r.json().get("choices", [])
                return (choices[0].get("message", {}).get("content") or "").strip()
        except Exception as e:
            console.print(f"[red]Custom LLM error: {e}[/red]")
        return ""

    async def stream(self, messages, system_prompt="") -> AsyncIterator[str]:
        if not self.enabled:
            yield "data: [DONE]\n\n"
            return
        full = [{"role": "system", "content": system_prompt}] + messages[-20:] if system_prompt else messages[-20:]
        api_url = f"{self.base_url.rstrip('/')}/v1/chat/completions"
        try:
            c = await self._client_()
            async with c.stream(
                "POST", api_url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": full, "stream": True, "temperature": 0.7},
            ) as resp:
                async for line in resp.aiter_lines():
                    if line:
                        yield f"{line}\n\n"
        except Exception as e:
            yield "data: [DONE]\n\n"


# ── Backend selector ───────────────────────────────────────────────────────────

_backends: dict[str, LLMBackend] = {}


def get_backend(name: str | None = None) -> LLMBackend:
    """
    Return the requested backend (or the configured default).

    Priority when name is None:
        ollama (if enabled) → custom_llm (if enabled) → groq
    """
    global _backends
    cfg = get_config()

    if name is None:
        if cfg.get("ollama_enabled"):
            name = "ollama"
        elif cfg.get("custom_llm_enabled"):
            name = "openai_compat"
        else:
            name = "groq"

    if name not in _backends:
        if name == "groq":
            _backends[name] = GroqBackend()
        elif name == "ollama":
            _backends[name] = OllamaBackend()
        else:
            _backends[name] = OpenAICompatBackend()

    return _backends[name]


def get_ssh_backend() -> LLMBackend:
    """Return the backend configured for SSH shell emulation."""
    cfg = get_config()
    name = cfg.get("ssh_llm_backend")  # explicit override
    return get_backend(name)


def get_http_backend() -> LLMBackend:
    """Return the backend configured for dynamic HTTP responses (Galah-style)."""
    cfg = get_config()
    name = cfg.get("http_llm_backend")
    return get_backend(name)


def reload_all_backends() -> None:
    """Force-reload all cached backends (called after config change)."""
    global _backends
    for b in _backends.values():
        if hasattr(b, "_reload"):
            b._reload()
