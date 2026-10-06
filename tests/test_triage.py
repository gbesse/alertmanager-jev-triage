import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from jev import normalize
from triage import enrich, forward, make_app, open_state, validate_url


class TriageTests(unittest.TestCase):
    def setUp(self):
        with open("examples/policy.json", encoding="utf-8") as source:
            self.policy = json.load(source)
        with open("examples/alerts.json", encoding="utf-8") as source:
            self.payload = json.load(source)

    def test_caches_decision_and_preserves_original_alerts(self):
        judge = Mock(return_value=normalize("incident", 0.96, self.policy))
        with open_state(":memory:") as db:
            first = enrich(self.payload, db, self.policy, judge)
            second = enrich(self.payload, db, self.policy, judge)
        self.assertEqual(judge.call_count, 1)
        self.assertEqual(first["alerts"], self.payload["alerts"])
        self.assertEqual(second["jevDecision"]["outcome"], "incident")

    def test_jev_failure_still_forwards_review(self):
        with open_state(":memory:") as db:
            result = enrich(self.payload, db, self.policy,
                            lambda _: (_ for _ in ()).throw(OSError("Jev offline")))
        self.assertEqual(result["jevDecision"]["outcome"], "review")
        self.assertEqual(result["jevDecision"]["choice"], "unavailable")

    def test_resolved_and_truncated_skip_jev(self):
        with open_state(":memory:") as db:
            resolved = enrich({**self.payload, "status": "resolved"}, db, self.policy,
                              lambda _: self.fail("Jev should not run"))
            truncated = enrich({**self.payload, "truncatedAlerts": 5}, db, self.policy,
                               lambda _: self.fail("Jev should not run"))
        self.assertEqual(resolved["jevDecision"]["outcome"], "resolved")
        self.assertEqual(truncated["jevDecision"]["outcome"], "review")

    def test_large_group_is_forwardable_without_jev(self):
        large = {**self.payload, "alerts": self.payload["alerts"] * 101}
        with open_state(":memory:") as db:
            result = enrich(large, db, self.policy,
                            lambda _: self.fail("Jev should not run"))
        self.assertEqual(len(result["alerts"]), 101)
        self.assertEqual(result["jevDecision"]["outcome"], "review")

    def test_http_auth_and_downstream_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            send = Mock(side_effect=OSError("downstream offline"))
            app = make_app(str(Path(folder) / "state.sqlite"), "0123456789abcdef",
                           self.policy, lambda _: normalize("incident", 0.96, self.policy), send)
            body = json.dumps(self.payload).encode()
            def call(auth):
                status = []
                environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/webhook",
                           "HTTP_AUTHORIZATION": auth, "CONTENT_LENGTH": str(len(body)),
                           "wsgi.input": io.BytesIO(body)}
                b"".join(app(environ, lambda code, headers: status.append(code)))
                return status[0]
            self.assertEqual(call(""), "401 Unauthorized")
            self.assertEqual(call("Bearer 0123456789abcdef"), "503 Service Unavailable")
            self.assertEqual(send.call_count, 1)

    def test_downstream_url_restrictions(self):
        self.assertEqual(validate_url("http://127.0.0.1:9001/events"),
                         "http://127.0.0.1:9001/events")
        with self.assertRaises(ValueError):
            validate_url("http://example.org/events")

    def test_forward_preserves_alerts_and_adds_decision(self):
        requests = []
        def open_response(request, timeout):
            requests.append(request)
            return io.BytesIO(b"{}")
        with open_state(":memory:") as db:
            payload = enrich(self.payload, db, self.policy,
                             lambda _: normalize("incident", 0.96, self.policy))
        forward("https://receiver.example.org/events", payload, "fake-token",
                opener=open_response)
        posted = json.loads(requests[0].data)
        self.assertEqual(posted["alerts"], self.payload["alerts"])
        self.assertEqual(posted["jevDecision"]["outcome"], "incident")


if __name__ == "__main__":
    unittest.main()
