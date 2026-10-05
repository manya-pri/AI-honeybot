import json
import os
import unittest
from unittest.mock import patch
from urllib.error import URLError

from agent import OpenAICompatibleProvider, ThreatAssessment, agent_status, assess, configured_provider


VALID = {
    "threat_type": "reconnaissance", "confidence": 0.91, "behaviours": ["Repeated sensitive endpoint probes"],
    "risk_assessment": "Repeated endpoint probes with elevated risk.",
    "recommended_action": "adaptive_deception", "evidence_summary": "Five probes across three paths.",
}
LOCAL = {"threat_type": "suspicious_access", "confidence": 0.7, "behaviours": ["probe"],
         "recommended_action": "monitor", "reason": "local score 55", "model": "RandomForestClassifier"}


class FakeResponse:
    def __init__(self, payload):
        self.data = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self.data


class AgentTests(unittest.TestCase):
    def test_disabled_llm_uses_local_agent(self):
        with patch.dict(os.environ, {"LLM_ENABLED": "false"}, clear=True):
            result = assess({"risk_score": 55}, LOCAL)
            self.assertEqual(agent_status()["agent_mode"], "local")
        self.assertEqual(result["agent_mode"], "local")
        self.assertFalse(result["llm_used"])

    def test_enabled_llm_returns_validated_structured_assessment(self):
        provider_payload = {"choices": [{"message": {"content": json.dumps(VALID)}}]}
        context = {"attacker_profile": {"total_events": 5}, "recent_events": [
            {"endpoint": "/login", "details": {"body": {"password": "must-not-leave-host"}}}],
            "risk_score": 70, "behavioural_features": {"failed_login_count": 4},
            "ml_classification": {"label": "brute_force"}, "behavioural_cluster": "brute-force-like",
            "deception_state": {"mode": "expanded"}, "previous_response": "MONITORED"}
        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_API_KEY": "test-key", "LLM_MODEL": "test-model"}, clear=True):
            with patch("agent.urlopen", return_value=FakeResponse(provider_payload)) as call:
                result = assess(context, LOCAL)
        self.assertEqual(result["agent_mode"], "llm")
        self.assertTrue(result["llm_used"])
        self.assertEqual(result["recommended_action"], "adaptive_deception")
        request = call.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        sent_context = json.loads(body["messages"][1]["content"])
        self.assertEqual(set(sent_context), {"attacker_profile", "recent_events", "risk_score", "behavioural_features",
                                             "ml_classification", "behavioural_cluster", "deception_state", "previous_response"})
        self.assertEqual(sent_context["behavioural_cluster"], "brute-force-like")
        self.assertNotIn("must-not-leave-host", body["messages"][1]["content"])

    def test_missing_key_reports_local_fallback(self):
        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_MODEL": "test-model"}, clear=True):
            result = assess({}, LOCAL)
        self.assertEqual(result["agent_mode"], "local")
        self.assertIn("API_KEY is missing", result["fallback_reason"])

    def test_provider_network_failure_falls_back_without_crashing(self):
        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_API_KEY": "k", "LLM_MODEL": "m"}, clear=True):
            with patch("agent.urlopen", side_effect=URLError("offline")):
                result = assess({"risk_score": 55}, LOCAL)
        self.assertEqual(result["agent_mode"], "local")
        self.assertFalse(result["llm_used"])
        self.assertIn("LLM unavailable", result["fallback_reason"])

    def test_invalid_structured_response_falls_back(self):
        invalid = {"choices": [{"message": {"content": json.dumps({**VALID, "recommended_action": "run_shell"})}}]}
        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_API_KEY": "k", "LLM_MODEL": "m"}, clear=True):
            with patch("agent.urlopen", return_value=FakeResponse(invalid)):
                result = assess({}, LOCAL)
        self.assertEqual(result["agent_mode"], "local")
        self.assertIn("LLM unavailable", result["fallback_reason"])

    def test_provider_requires_api_key_and_secure_url(self):
        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_MODEL": "m"}, clear=True):
            self.assertIsNone(configured_provider()[0])
        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_API_KEY": "k", "LLM_MODEL": "m",
                                     "LLM_BASE_URL": "http://api.example.test/v1"}, clear=True):
            self.assertIsNone(configured_provider()[0])

    def test_response_model_rejects_uncontrolled_actions_and_extra_fields(self):
        with self.assertRaises(ValueError):
            ThreatAssessment.model_validate({**VALID, "recommended_action": "shell"})
        with self.assertRaises(ValueError):
            ThreatAssessment.model_validate({**VALID, "chain_of_thought": "private reasoning"})


if __name__ == "__main__":
    unittest.main()
