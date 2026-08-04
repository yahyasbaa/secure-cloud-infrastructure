"""Minimal data-access layer. All SQL is parameterised; no string formatting."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .config import Config
from .secret_store import SecretProvider

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS notes (
    id         BIGSERIAL PRIMARY KEY,
    title      VARCHAR(200) NOT NULL,
    body       VARCHAR(4000) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


class Database:
    def __init__(self, cfg: Config, secrets: SecretProvider) -> None:
        self._cfg = cfg
        self._secrets = secrets
        self._schema_ready = False

    def _connect(self) -> Any:
        import psycopg

        user, password = self._secrets.db_credentials()
        params: dict[str, Any] = {
            "host": self._cfg.db_host,
            "port": self._cfg.db_port,
            "dbname": self._cfg.db_name,
            "user": user,
            "password": password,
            "sslmode": self._cfg.db_sslmode,
            "connect_timeout": 5,
            "application_name": "sci-app",
        }
        if self._cfg.db_sslrootcert:
            params["sslrootcert"] = self._cfg.db_sslrootcert
        try:
            return psycopg.connect(**params)
        except psycopg.OperationalError:
            # Credentials may have been rotated by RDS: refresh once and retry.
            self._secrets.invalidate()
            user, password = self._secrets.db_credentials()
            params.update(user=user, password=password)
            return psycopg.connect(**params)

    @contextmanager
    def connection(self) -> Iterator[Any]:
        conn = self._connect()
        try:
            if not self._schema_ready:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA_SQL)
                conn.commit()
                self._schema_ready = True
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def ping(self) -> None:
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()

    def list_notes(self, limit: int) -> list[dict[str, Any]]:
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, body, created_at FROM notes ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            return [
                {"id": r[0], "title": r[1], "body": r[2], "created_at": r[3].isoformat()}
                for r in cur.fetchall()
            ]

    def create_note(self, title: str, body: str) -> int:
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO notes (title, body) VALUES (%s, %s) RETURNING id",
                (title, body),
            )
            row = cur.fetchone()
            return int(row[0])
