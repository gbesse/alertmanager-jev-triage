"""Small, validated TypeSafe Jev choice adapter shared by the five example integrations."""
import json
import math
import ssl
from urllib.request import Request, urlopen

API_URL = "https://api.typesafe.ai/v1/systemone"


class DecisionError(Exception):
    pass


def _open(request, timeout):
    try:
        import certifi
    except ImportError:
        return urlopen(request, timeout=timeout)
    return urlopen(request, timeout=timeout,
                   context=ssl.create_default_context(cafile=certifi.where()))


def evaluate(text, policy, api_key, *, opener=None):
    if not isinstance(text, str) or not text.strip() or len(text) > 16000:
        raise DecisionError("invalid_text")
    if not api_key:
        raise DecisionError("missing_key")
    question = policy["question"]
    request = Request(API_URL, data=json.dumps({
        "model": policy["model"],
        "state": {"text": text},
        "questions": {question: {"type": "choice", "instructions": policy["instructions"],
                                 "criteria": policy["criteria"]}},
    }).encode(), headers={"Authorization": "Bearer " + api_key,
                       "Content-Type": "application/json"}, method="POST")
    if opener is None:
        opener = _open
    try:
        with opener(request, timeout=20) as response:
            body = json.load(response)
    except Exception as exc:
        raise DecisionError("request_failed") from exc
    if not isinstance(body, dict) or body.get("model") != policy["model"]:
        raise DecisionError("model_mismatch")
    answers = body.get("answers")
    answer = answers.get(question) if isinstance(answers, dict) else None
    if not isinstance(answer, dict):
        raise DecisionError("invalid_answer")
    choice = answer.get("choice")
    probabilities = answer.get("probabilities")
    probability = probabilities.get(choice) if isinstance(probabilities, dict) else None
    return normalize(choice, probability, policy)


def normalize(choice, probability, policy):
    if (choice not in policy["criteria"] or isinstance(probability, bool)
            or not isinstance(probability, (int, float)) or not math.isfinite(probability)
            or not 0 <= probability <= 1):
        raise DecisionError("invalid_answer")
    outcome = choice if choice != "other" and probability >= policy["threshold"] else "review"
    return {"choice": choice, "probability": float(probability), "outcome": outcome,
            "policy_version": policy["version"]}


def fixture_evaluator(fixtures, policy):
    def judge(text):
        item = fixtures.get(text)
        if not isinstance(item, dict):
            raise DecisionError("missing_fixture")
        return normalize(item.get("choice"), item.get("probability"), policy)
    return judge
