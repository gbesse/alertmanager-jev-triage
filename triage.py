"""Fail-open Jev enrichment for Prometheus Alertmanager webhook groups."""
import argparse
from contextlib import contextmanager
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server

from jev import evaluate, fixture_evaluator

MAX_BODY = 1024 * 1024


def validate_url(url):
    parsed = urlsplit(url)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.scheme not in ("http", "https") or parsed.path in ("", "/")
            or (parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"))):
        raise ValueError("invalid_downstream_url")
    return url


@contextmanager
def open_state(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS decisions (digest TEXT NOT NULL, policy_version TEXT NOT NULL, choice TEXT NOT NULL, outcome TEXT NOT NULL, probability REAL NOT NULL, PRIMARY KEY(digest,policy_version))")
    try:
        yield db
    finally:
        db.close()


def _validate(payload):
    if (not isinstance(payload, dict) or payload.get("version") != "4"
            or not isinstance(payload.get("groupKey"), str) or not payload["groupKey"]
            or payload.get("status") not in ("firing", "resolved")
            or not isinstance(payload.get("alerts"), list)
            or not payload["alerts"]
            or isinstance(payload.get("truncatedAlerts", 0), bool)
            or not isinstance(payload.get("truncatedAlerts", 0), int)
            or payload.get("truncatedAlerts", 0) < 0):
        raise ValueError("invalid_alert_group")
    for alert in payload["alerts"]:
        if (not isinstance(alert, dict) or not isinstance(alert.get("labels"), dict)
                or not isinstance(alert.get("annotations"), dict)
                or not isinstance(alert.get("fingerprint"), str)):
            raise ValueError("invalid_alert")


def group_text(payload):
    fields = []
    for alert in payload["alerts"][:10]:
        labels, annotations = alert["labels"], alert["annotations"]
        for key in ("alertname", "service", "severity"):
            value = labels.get(key)
            if isinstance(value, str):
                fields.append(key + ": " + value[:500])
        for key in ("summary", "description"):
            value = annotations.get(key)
            if isinstance(value, str):
                fields.append(key + ": " + value[:1000])
    return "\n".join(fields)[:16000] or "No descriptive labels or annotations."


def enrich(payload, db, policy, judge):
    _validate(payload)
    digest_input = {"groupKey": payload["groupKey"], "status": payload["status"],
                    "alerts": [{"fingerprint": alert["fingerprint"],
                                "labels": alert["labels"], "annotations": alert["annotations"]}
                               for alert in payload["alerts"]]}
    digest = hashlib.sha256(json.dumps(digest_input, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    if payload["status"] == "resolved":
        decision = {"choice": "resolved", "outcome": "resolved", "probability": None,
                    "policy_version": policy["version"]}
    elif payload.get("truncatedAlerts", 0) or len(payload["alerts"]) > 10:
        decision = {"choice": "incomplete", "outcome": "review", "probability": None,
                    "policy_version": policy["version"]}
    else:
        old = db.execute("SELECT choice,outcome,probability FROM decisions WHERE digest=? AND policy_version=?",
                         (digest, policy["version"])).fetchone()
        if old:
            decision = {"choice": old[0], "outcome": old[1], "probability": old[2],
                        "policy_version": policy["version"]}
        else:
            try:
                decision = judge(group_text(payload))
            except Exception:
                # Preserve the page path even if Jev is unavailable.
                decision = {"choice": "unavailable", "outcome": "review", "probability": None,
                            "policy_version": policy["version"]}
            else:
                db.execute("INSERT INTO decisions VALUES(?,?,?,?,?)",
                           (digest, policy["version"], decision["choice"],
                            decision["outcome"], decision["probability"]))
                db.commit()
    return {**payload, "jevDecision": {"id": digest, **decision}}


def forward(url, payload, token="", *, opener=urlopen):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(validate_url(url), data=json.dumps(payload).encode(),
                      headers=headers, method="POST")
    with opener(request, timeout=15) as response:
        response.read()


def make_app(state_path, token, policy, judge, send):
    if not isinstance(token, str) or len(token) < 16:
        raise ValueError("invalid_webhook_token")

    def app(environ, start_response):
        if environ.get("REQUEST_METHOD") != "POST" or environ.get("PATH_INFO") != "/webhook":
            start_response("404 Not Found", [("Content-Type", "application/json")]); return [b"{}"]
        if not hmac.compare_digest(environ.get("HTTP_AUTHORIZATION", ""), "Bearer " + token):
            start_response("401 Unauthorized", [("Content-Type", "application/json")]); return [b"{}"]
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = -1
        if length < 1 or length > MAX_BODY:
            start_response("413 Payload Too Large", [("Content-Type", "application/json")]); return [b"{}"]
        try:
            payload = json.loads(environ["wsgi.input"].read(length))
            with open_state(state_path) as db:
                output = enrich(payload, db, policy, judge)
        except (json.JSONDecodeError, ValueError):
            start_response("400 Bad Request", [("Content-Type", "application/json")]); return [b"{}"]
        except Exception:
            start_response("503 Service Unavailable", [("Content-Type", "application/json")]); return [b"{}"]
        try:
            send(output)
        except Exception:
            start_response("503 Service Unavailable", [("Content-Type", "application/json")]); return [b"{}"]
        body = json.dumps({"status": "forwarded", "decision": output["jevDecision"]}).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(body)))])
        return [body]
    return app


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--demo", action="store_true")
    modes.add_argument("--serve", action="store_true")
    parser.add_argument("--state", default=".local/decisions.sqlite")
    args = parser.parse_args()
    with open("examples/policy.json", encoding="utf-8") as source:
        policy = json.load(source)
    if args.demo:
        with open("examples/alerts.json", encoding="utf-8") as source:
            payload = json.load(source)
        with open("examples/fixtures.json", encoding="utf-8") as source:
            judge = fixture_evaluator(json.load(source), policy)
        with open_state(":memory:") as db:
            print(json.dumps(enrich(payload, db, policy, judge)["jevDecision"], indent=2))
        return
    key = os.environ["TYPESAFE_API_KEY"]
    downstream = validate_url(os.environ["JEV_DOWNSTREAM_URL"])
    downstream_token = os.environ.get("JEV_DOWNSTREAM_TOKEN", "")
    app = make_app(args.state, os.environ["ALERTMANAGER_WEBHOOK_TOKEN"], policy,
                   lambda text: evaluate(text, policy, key),
                   lambda payload: forward(downstream, payload, downstream_token))
    with make_server("127.0.0.1", int(os.environ.get("PORT", "8095")), app) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
