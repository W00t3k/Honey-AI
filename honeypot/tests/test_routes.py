import unittest
from unittest.mock import patch

import httpx

from main import app


class _FakeGroqChat:
    async def stream(self, messages):
        yield 'data: {"choices":[{"delta":{"content":"hello"},"index":0,"finish_reason":null}]}\n\n'
        yield "data: [DONE]\n\n"


class _FakeLogger:
    async def log_request(self, *args, **kwargs):
        return 1


class RouteBehaviorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_ollama_api_chat_route_still_exists(self):
        with patch("routers.recon.get_logger", return_value=_FakeLogger()):
            response = await self.client.post("/api/chat", json={
                "model": "llama3.2:latest",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": False,
            })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"].split(";")[0], "application/json")
        body = response.json()
        self.assertIn("model", body)
        self.assertIn("message", body)

    async def test_public_ui_chat_uses_separate_route(self):
        with patch("main.get_logger", return_value=_FakeLogger()):
            with patch("services.groq_chat.get_groq_chat", return_value=_FakeGroqChat()):
                response = await self.client.post("/ui/api/chat", json={
                    "messages": [{"role": "user", "content": "hello"}],
                })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"].split(";")[0], "text/event-stream")
        self.assertIn("data: [DONE]", response.text)

    async def test_mcp_initialize_returns_server_info(self):
        with patch("routers.mcp.get_logger", return_value=_FakeLogger()):
            response = await self.client.post("/mcp", json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            })

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertIn("serverInfo", body["result"])
        self.assertIn("instructions", body["result"])


if __name__ == "__main__":
    unittest.main()
