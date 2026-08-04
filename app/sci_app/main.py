"""HTTP API.

Routes
  GET  /health      liveness (no dependencies) - used by the ALB health check
  GET  /ready       readiness (verifies database connectivity)
  GET  /api/notes   list notes            (bearer token required)
  POST /api/notes   create a note         (bearer token required)
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .auth import extract_bearer, token_is_valid
from .config import Config
from .db import Database
from .logging_setup import security_event
from .secret_store import SecretProvider

log = logging.getLogger("sci_app")

MAX_TITLE = 200
MAX_BODY = 4000

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def client_ip() -> str:
    # The ALB appends the real client address as the right-most X-Forwarded-For
    # entry. Left-most entries are client-controlled and must not be trusted.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[-1].strip()[:64]
    return (request.remote_addr or "unknown")[:64]


def create_app(
    cfg: Config | None = None,
    secrets: SecretProvider | None = None,
    db: Any | None = None,
) -> Flask:
    cfg = cfg or Config.from_env()
    secrets = secrets or SecretProvider(cfg)
    db = db if db is not None else Database(cfg, secrets)

    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=cfg.max_body_bytes, JSON_SORT_KEYS=False)

    def require_auth() -> Response | None:
        token = extract_bearer(request.headers.get("Authorization"))
        try:
            valid = secrets.api_tokens()
        except Exception:
            log.exception("secret_lookup_failed", extra={"event": "secret_lookup_failed"})
            return _error(503, "service unavailable")
        if not token_is_valid(token, valid):
            security_event(
                log,
                "auth_failure",
                source_ip=client_ip(),
                path=request.path,
                method=request.method,
                reason="missing_token" if token is None else "invalid_token",
                user_agent=(request.headers.get("User-Agent") or "")[:200],
            )
            resp = _error(401, "unauthorized")
            resp.headers["WWW-Authenticate"] = 'Bearer realm="sci"'
            return resp
        g.authenticated = True
        return None

    @app.after_request
    def add_security_headers(resp: Response) -> Response:
        for header, value in SECURITY_HEADERS.items():
            resp.headers.setdefault(header, value)
        resp.headers.pop("Server", None)
        return resp

    @app.errorhandler(404)
    def not_found(_: Exception) -> Response:
        return _error(404, "not found")

    @app.errorhandler(405)
    def method_not_allowed(_: Exception) -> Response:
        return _error(405, "method not allowed")

    @app.errorhandler(413)
    def too_large(_: Exception) -> Response:
        security_event(log, "request_too_large", source_ip=client_ip(), path=request.path)
        return _error(413, "request too large")

    @app.errorhandler(Exception)
    def unhandled(exc: Exception) -> Response:
        if isinstance(exc, HTTPException):
            return _error(exc.code or 500, (exc.name or "error").lower())
        # Never leak stack traces or internals to the client.
        log.error("unhandled_error", extra={"event": "unhandled_error", "exc_type": type(exc).__name__})
        return _error(500, "internal error")

    @app.get("/health")
    def health() -> Response:
        return jsonify(status="ok")

    @app.get("/ready")
    def ready() -> Response | tuple[Response, int]:
        try:
            db.ping()
        except Exception as exc:
            log.error("readiness_failed", extra={"event": "readiness_failed", "exc_type": type(exc).__name__})
            return jsonify(status="unavailable"), 503
        return jsonify(status="ready")

    @app.get("/api/notes")
    def list_notes() -> Response | tuple[Response, int]:
        denied = require_auth()
        if denied is not None:
            return denied
        try:
            limit = int(request.args.get("limit", "50"))
        except ValueError:
            return _error(400, "limit must be an integer")
        if not 1 <= limit <= 100:
            return _error(400, "limit must be between 1 and 100")
        return jsonify(notes=db.list_notes(limit))

    @app.post("/api/notes")
    def create_note() -> Response | tuple[Response, int]:
        denied = require_auth()
        if denied is not None:
            return denied
        if not request.is_json:
            return _error(415, "content-type must be application/json")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error(400, "body must be a JSON object")
        title, body = data.get("title"), data.get("body")
        if not isinstance(title, str) or not 1 <= len(title) <= MAX_TITLE:
            return _error(400, f"title must be a string of 1-{MAX_TITLE} characters")
        if not isinstance(body, str) or not 1 <= len(body) <= MAX_BODY:
            return _error(400, f"body must be a string of 1-{MAX_BODY} characters")
        note_id = db.create_note(title, body)
        log.info("note_created", extra={"event": "note_created", "note_id": note_id})
        return jsonify(id=note_id), 201

    return app


def _error(status: int, message: str) -> Response:
    resp = jsonify(error=message)
    resp.status_code = status
    return resp
