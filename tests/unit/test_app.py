import json
import logging

import pytest

from sci_app.config import Config
from sci_app.logging_setup import JsonFormatter
from sci_app.main import SECURITY_HEADERS, create_app

TOKEN = "k" * 40


class FakeSecrets:
    def __init__(self, tokens=None, fail=False):
        self.tokens = tokens if tokens is not None else [TOKEN]
        self.fail = fail

    def api_tokens(self):
        if self.fail:
            raise RuntimeError("secrets manager unavailable")
        return self.tokens


class FakeDb:
    def __init__(self, healthy=True):
        self.healthy = healthy
        self.notes = []

    def ping(self):
        if not self.healthy:
            raise ConnectionError("db down")

    def list_notes(self, limit):
        return self.notes[:limit]

    def create_note(self, title, body):
        self.notes.append({"id": len(self.notes) + 1, "title": title, "body": body})
        return len(self.notes)


@pytest.fixture
def cfg():
    return Config.from_env({"APP_RUNTIME": "test", "MAX_BODY_BYTES": "2048"})


@pytest.fixture
def db():
    return FakeDb()


@pytest.fixture
def client(cfg, db):
    return create_app(cfg, FakeSecrets(), db).test_client()


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_health_is_public_and_hardened(client):
    resp = client.get("/health")
    assert resp.status_code == 200 and resp.get_json() == {"status": "ok"}
    for header, value in SECURITY_HEADERS.items():
        assert resp.headers[header] == value
    assert "Server" not in resp.headers


def test_ready_reflects_database(cfg):
    assert create_app(cfg, FakeSecrets(), FakeDb()).test_client().get("/ready").status_code == 200
    assert create_app(cfg, FakeSecrets(), FakeDb(healthy=False)).test_client().get("/ready").status_code == 503


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}])
def test_api_requires_valid_token(client, headers):
    resp = client.get("/api/notes", headers=headers)
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"].startswith("Bearer")


def test_auth_failure_is_logged_as_security_event(client, caplog):
    with caplog.at_level(logging.WARNING, logger="sci_app"):
        client.get("/api/notes", headers={"Authorization": "Bearer nope", "X-Forwarded-For": "1.1.1.1, 203.0.113.9"})
    events = [r for r in caplog.records if getattr(r, "event", None) == "auth_failure"]
    assert len(events) == 1
    record = events[0]
    assert record.source_ip == "203.0.113.9"  # right-most XFF entry (added by the ALB)
    assert record.reason == "invalid_token"
    rendered = JsonFormatter().format(record)
    assert json.loads(rendered)["event"] == "auth_failure"
    assert "nope" not in rendered  # the presented token is never logged


def test_create_and_list_notes(client, db):
    resp = client.post("/api/notes", json={"title": "t", "body": "b"}, headers=AUTH)
    assert resp.status_code == 201 and resp.get_json() == {"id": 1}
    listed = client.get("/api/notes?limit=10", headers=AUTH).get_json()["notes"]
    assert listed[0]["title"] == "t"


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"title": "", "body": "b"}, 400),
        ({"title": "t" * 201, "body": "b"}, 400),
        ({"title": "t", "body": 5}, 400),
        (["not", "an", "object"], 400),
    ],
)
def test_input_validation(client, payload, status):
    assert client.post("/api/notes", json=payload, headers=AUTH).status_code == status


def test_rejects_non_json_and_oversized(client):
    assert client.post("/api/notes", data="x", headers=AUTH).status_code == 415
    big = {"title": "t", "body": "b" * 4000}
    assert client.post("/api/notes", data=json.dumps(big) * 2, headers={**AUTH, "Content-Type": "application/json"}).status_code == 413


@pytest.mark.parametrize("limit", ["0", "101", "abc"])
def test_limit_validation(client, limit):
    assert client.get(f"/api/notes?limit={limit}", headers=AUTH).status_code == 400


def test_secret_backend_failure_fails_closed(cfg):
    client = create_app(cfg, FakeSecrets(fail=True), FakeDb()).test_client()
    assert client.get("/api/notes", headers=AUTH).status_code == 503


def test_errors_do_not_leak_internals(cfg):
    class ExplodingDb(FakeDb):
        def list_notes(self, limit):
            raise ValueError("SELECT secret FROM internal")

    client = create_app(cfg, FakeSecrets(), ExplodingDb()).test_client()
    resp = client.get("/api/notes", headers=AUTH)
    assert resp.status_code == 500
    assert resp.get_json() == {"error": "internal error"}
    assert b"SELECT" not in resp.data


def test_unknown_route_and_method(client):
    assert client.get("/nope").status_code == 404
    assert client.delete("/api/notes", headers=AUTH).status_code == 405
