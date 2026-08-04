"""Secret retrieval with a short in-memory cache.

* App API token: stored in Secrets Manager as a plain string. Both the
  AWSCURRENT and AWSPREVIOUS versions are accepted so that a rotation does
  not lock out clients that still hold the previous token (grace period).
* Database credentials: the RDS-managed master secret (JSON with
  ``username``/``password``). RDS rotates it automatically; the cache is
  invalidated on authentication errors so the app picks up the new value.

Secret values are never logged.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable

from .config import Config


class SecretProvider:
    def __init__(self, cfg: Config, client_factory: Callable[[], Any] | None = None) -> None:
        self._cfg = cfg
        self._client_factory = client_factory
        self._client: Any = None
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], tuple[float, str | None]] = {}

    def _sm(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                import boto3  # imported lazily so local runs do not need AWS config

                self._client = boto3.client("secretsmanager", region_name=self._cfg.aws_region)
        return self._client

    def _get(self, secret_id: str, stage: str) -> str | None:
        key = (secret_id, stage)
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < self._cfg.secret_cache_ttl_seconds:
                return hit[1]
        try:
            resp = self._sm().get_secret_value(SecretId=secret_id, VersionStage=stage)
            value: str | None = resp.get("SecretString")
        except Exception as exc:  # botocore ClientError without importing botocore
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if stage != "AWSCURRENT" and code == "ResourceNotFoundException":
                value = None  # no previous version exists yet
            else:
                raise
        with self._lock:
            self._cache[key] = (now, value)
        return value

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()

    def api_tokens(self) -> list[str]:
        """Return every currently-valid API token (current first)."""
        if self._cfg.runtime != "aws":
            return [self._cfg.local_api_token] if self._cfg.local_api_token else []
        assert self._cfg.app_secret_arn
        tokens = []
        for stage in ("AWSCURRENT", "AWSPREVIOUS"):
            value = self._get(self._cfg.app_secret_arn, stage)
            if value:
                tokens.append(value.strip())
        return tokens

    def db_credentials(self) -> tuple[str, str]:
        if self._cfg.runtime != "aws":
            if not (self._cfg.db_user and self._cfg.db_password):
                raise RuntimeError("DB_USER / DB_PASSWORD are required outside AWS")
            return self._cfg.db_user, self._cfg.db_password
        assert self._cfg.db_secret_arn
        raw = self._get(self._cfg.db_secret_arn, "AWSCURRENT")
        if not raw:
            raise RuntimeError("database secret is empty")
        data = json.loads(raw)
        return data["username"], data["password"]
