"""Runtime configuration.

All configuration comes from environment variables. Secrets are NEVER read from
environment variables in the ``aws`` runtime: there the variables only carry
Secrets Manager ARNs and the values are fetched at runtime with the instance
role. The ``local`` runtime (docker compose on a laptop) is the only place a
token may come from the environment, and it is refused anywhere else.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

VALID_RUNTIMES = ("local", "aws", "test")


class ConfigError(RuntimeError):
    """Raised when the configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class Config:
    runtime: str
    aws_region: str | None
    app_secret_arn: str | None
    db_secret_arn: str | None
    local_api_token: str | None
    db_host: str | None
    db_port: int
    db_name: str
    db_user: str | None
    db_password: str | None
    db_sslmode: str
    db_sslrootcert: str | None
    secret_cache_ttl_seconds: int
    max_body_bytes: int

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        e = dict(os.environ if env is None else env)
        runtime = e.get("APP_RUNTIME", "local")
        if runtime not in VALID_RUNTIMES:
            raise ConfigError(f"APP_RUNTIME must be one of {VALID_RUNTIMES}")

        cfg = cls(
            runtime=runtime,
            aws_region=e.get("AWS_REGION"),
            app_secret_arn=e.get("APP_SECRET_ARN"),
            db_secret_arn=e.get("DB_SECRET_ARN"),
            local_api_token=e.get("APP_API_TOKEN"),
            db_host=e.get("DB_HOST"),
            db_port=int(e.get("DB_PORT", "5432")),
            db_name=e.get("DB_NAME", "app"),
            db_user=e.get("DB_USER"),
            db_password=e.get("DB_PASSWORD"),
            db_sslmode=e.get("DB_SSLMODE", "verify-full"),
            db_sslrootcert=e.get("DB_SSLROOTCERT"),
            secret_cache_ttl_seconds=int(e.get("SECRET_CACHE_TTL_SECONDS", "300")),
            max_body_bytes=int(e.get("MAX_BODY_BYTES", "16384")),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.runtime == "aws":
            missing = [
                name
                for name, value in (
                    ("APP_SECRET_ARN", self.app_secret_arn),
                    ("DB_SECRET_ARN", self.db_secret_arn),
                    ("DB_HOST", self.db_host),
                    ("AWS_REGION", self.aws_region),
                )
                if not value
            ]
            if missing:
                raise ConfigError(f"missing required settings: {', '.join(missing)}")
            if self.local_api_token or self.db_password:
                raise ConfigError(
                    "APP_API_TOKEN / DB_PASSWORD must not be set in the aws runtime; "
                    "secrets are read from Secrets Manager"
                )
            if self.db_sslmode != "verify-full":
                raise ConfigError("DB_SSLMODE must be verify-full in the aws runtime")
            if not self.db_sslrootcert:
                raise ConfigError("DB_SSLROOTCERT is required in the aws runtime")
        elif self.runtime == "local":
            if not self.local_api_token or len(self.local_api_token) < 32:
                raise ConfigError("APP_API_TOKEN must be set (>= 32 chars) for the local runtime")
        if self.max_body_bytes <= 0 or self.secret_cache_ttl_seconds < 0:
            raise ConfigError("numeric settings must be positive")
