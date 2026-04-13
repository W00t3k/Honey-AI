import unittest

from services.agent_trap import AgentTrapService


class AgentTrapTests(unittest.TestCase):
    def test_verify_endpoint_marks_redirect_trap_hit(self):
        service = AgentTrapService()

        baseline = service.check_incoming(ip="127.0.0.1", path="/ui/api/chat")
        signal = service.check_incoming(ip="127.0.0.1", path="/v1/verify/test-token")

        self.assertEqual(baseline.agent_type, "unknown")
        self.assertFalse(baseline.trap_hit)
        self.assertEqual(signal.agent_type, "llm_agent")
        self.assertTrue(signal.trap_hit)
        self.assertEqual(signal.trap_type, "redirect")
        self.assertIsNotNone(signal.response_delta_ms)
        self.assertGreaterEqual(signal.confidence, 0.9)


if __name__ == "__main__":
    unittest.main()
