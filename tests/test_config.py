import unittest

from services.config import _normalize_canary_tokens, HoneypotConfig, ConfigService


class ConfigNormalizationTests(unittest.TestCase):
    def test_normalize_legacy_canary_string_list(self):
        tokens = _normalize_canary_tokens([
            "sk-proj-abc123",
            {"label": "Prod", "token": "sk-proj-def456"},
            "sk-proj-abc123",
        ])

        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0]["label"], "Imported Canary")
        self.assertEqual(tokens[1]["label"], "Prod")
        self.assertTrue(all("id" in token for token in tokens))

    def test_config_normalizes_delay_bounds_and_ports(self):
        service = object.__new__(ConfigService)
        service.config = HoneypotConfig(
            response_delay_min_ms=900,
            response_delay_max_ms=100,
            additional_ports=[443, 443, "8443", 70000, 0],
            canary_tokens=["sk-test-1"],
        )

        service._normalize_config()

        self.assertEqual(service.config.response_delay_min_ms, 900)
        self.assertEqual(service.config.response_delay_max_ms, 900)
        self.assertEqual(service.config.additional_ports, [443, 8443])
        self.assertEqual(service.config.canary_tokens[0]["token"], "sk-test-1")

    def test_config_removes_ssh_port_from_additional_ports(self):
        service = object.__new__(ConfigService)
        service.config = HoneypotConfig(
            ssh_honeypot_enabled=True,
            ssh_listen_port=2222,
            additional_ports=[2222, 8080, "2222", 8443],
        )

        service._normalize_config()

        self.assertEqual(service.config.additional_ports, [8080, 8443])


if __name__ == "__main__":
    unittest.main()
