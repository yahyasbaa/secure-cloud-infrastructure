import json

import pytest

from sci_app.config import Config
from sci_app.secret_store import SecretProvider


class FakeError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class FakeSecretsManager:
    def __init__(self, values):
        self.values = values
        self.calls = 0

    def get_secret_value(self, SecretId, VersionStage):
        self.calls += 1
        key = (SecretId, VersionStage)
        if key not in self.values:
            raise FakeError("ResourceNotFoundException")
        return {"SecretString": self.values[key]}


def cfg(**kw):
    base = dict(
        runtime="aws", aws_region="us-east-1", app_secret_arn="app", db_secret_arn="db",
        local_api_token=None, db_host="h", db_port=5432, db_name="app", db_user=None,
        db_password=None, db_sslmode="verify-full", db_sslrootcert="/ca.pem",
        secret_cache_ttl_seconds=300, max_body_bytes=1024,
    )
    base.update(kw)
    return Config(**base)


def test_returns_current_and_previous_tokens():
    sm = FakeSecretsManager({("app", "AWSCURRENT"): "new" * 12, ("app", "AWSPREVIOUS"): "old" * 12})
    sp = SecretProvider(cfg(), client_factory=lambda: sm)
    assert sp.api_tokens() == ["new" * 12, "old" * 12]


def test_missing_previous_version_is_fine():
    sm = FakeSecretsManager({("app", "AWSCURRENT"): "new" * 12})
    assert SecretProvider(cfg(), client_factory=lambda: sm).api_tokens() == ["new" * 12]


def test_missing_current_version_raises():
    sm = FakeSecretsManager({})
    with pytest.raises(FakeError):
        SecretProvider(cfg(), client_factory=lambda: sm).api_tokens()


def test_cache_and_invalidate():
    sm = FakeSecretsManager({("db", "AWSCURRENT"): json.dumps({"username": "u", "password": "p"})})
    sp = SecretProvider(cfg(), client_factory=lambda: sm)
    assert sp.db_credentials() == ("u", "p")
    assert sp.db_credentials() == ("u", "p")
    assert sm.calls == 1
    sp.invalidate()
    sp.db_credentials()
    assert sm.calls == 2


def test_local_runtime_uses_env_values():
    local = cfg(runtime="local", local_api_token="l" * 40, db_user="u", db_password="p")
    sp = SecretProvider(local, client_factory=lambda: pytest.fail("must not call AWS locally"))
    assert sp.api_tokens() == ["l" * 40]
    assert sp.db_credentials() == ("u", "p")
