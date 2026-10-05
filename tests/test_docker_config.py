import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class DockerConfigTests(unittest.TestCase):
    def test_compose_has_local_only_gateway_and_healthy_app_services(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        services = compose["services"]
        self.assertTrue({"database", "honeypot", "backend", "frontend", "reverse-proxy"}.issubset(services))
        self.assertEqual(services["reverse-proxy"]["ports"], ["127.0.0.1:8080:8080"])
        for name in ("honeypot", "backend", "frontend"):
            self.assertIn("healthcheck", services[name])
        self.assertIn("honeybot_data:/data", services["honeypot"]["volumes"])
        self.assertIn("honeybot_data:/data", services["backend"]["volumes"])
        self.assertIn("honeybot_data:/data:ro", services["frontend"]["volumes"])
        self.assertEqual(services["backend"]["environment"]["LLM_ENABLED"], "${LLM_ENABLED:-false}")

    def test_image_runs_as_non_root_and_proxy_exposes_backend_paths(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        proxy = (ROOT / "docker" / "nginx.conf").read_text(encoding="utf-8")
        self.assertIn("USER honeybot", dockerfile)
        self.assertIn("location /api/", proxy)
        self.assertIn("location /docs", proxy)
        self.assertIn("location /honeypot/", proxy)


if __name__ == "__main__":
    unittest.main()
