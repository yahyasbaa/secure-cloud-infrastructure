import pytest

from sci_app.config import Config, ConfigError

TOKEN = "t" * 40


def aws_env(**overrides):
    env = {
        "APP_RUNTIME": "aws",
        "AWS_REGION": "us-east-1",
        "APP_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app",
        "DB_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:db",
        "DB_HOST": "db.internal",
        "DB_SSLROOTCERT": "/etc/ssl/rds/global-bundle.pem",
    }
    env.update(overrides)
    return env


def test_aws_runtime_valid():
    cfg = Config.from_env(aws_env())
    assert cfg.db_sslmode == "verify-full"


@pytest.mark.parametrize("missing", ["APP_SECRET_ARN", "DB_SECRET_ARN", "DB_HOST", "AWS_REGION"])
def test_aws_runtime_requires_settings(missing):
    env = aws_env()
    env.pop(missing)
    with pytest.raises(ConfigError, match=missing):
        Config.from_env(env)


@pytest.mark.parametrize("var", ["APP_API_TOKEN", "DB_PASSWORD"])
def test_aws_runtime_refuses_plaintext_secrets(var):
    with pytest.raises(ConfigError, match="must not be set"):
        Config.from_env(aws_env(**{var: TOKEN}))


def test_aws_runtime_requires_verified_tls_to_database():
    with pytest.raises(ConfigError, match="verify-full"):
        Config.from_env(aws_env(DB_SSLMODE="require"))
    env = aws_env()
    env.pop("DB_SSLROOTCERT")
    with pytest.raises(ConfigError, match="DB_SSLROOTCERT"):
        Config.from_env(env)


def test_local_runtime_requires_strong_token():
    with pytest.raises(ConfigError):
        Config.from_env({"APP_RUNTIME": "local", "APP_API_TOKEN": "short"})
    assert Config.from_env({"APP_RUNTIME": "local", "APP_API_TOKEN": TOKEN}).local_api_token == TOKEN


def test_unknown_runtime_rejected():
    with pytest.raises(ConfigError):
        Config.from_env({"APP_RUNTIME": "prod"})
