import io
import json
import unittest

from jev import DecisionError, evaluate, normalize


class JevContractTests(unittest.TestCase):
    def setUp(self):
        with open("examples/policy.json", encoding="utf-8") as source:
            self.policy = json.load(source)

    def test_choice_response_contract(self):
        choice = next(item for item in self.policy["criteria"] if item != "other")
        response = {"model": self.policy["model"], "answers": {
            self.policy["question"]: {"choice": choice, "probabilities": {choice: 0.97}}}}
        requests = []
        def open_response(request, timeout):
            requests.append(request)
            return io.BytesIO(json.dumps(response).encode())
        result = evaluate("Synthetic test input", self.policy, "fake-key", opener=open_response)
        self.assertEqual(result["outcome"], choice)
        self.assertEqual(len(requests), 1)
        self.assertEqual(json.loads(requests[0].data)["questions"][self.policy["question"]]["type"], "choice")

    def test_uncertain_and_malformed_probabilities(self):
        choice = next(item for item in self.policy["criteria"] if item != "other")
        self.assertEqual(normalize(choice, 0.5, self.policy)["outcome"], "review")
        for invalid in (True, -0.1, 1.1, float("nan")):
            with self.assertRaises(DecisionError):
                normalize(choice, invalid, self.policy)


if __name__ == "__main__":
    unittest.main()
