"""Gunicorn configuration (executed in the master process at start-up)."""

import json
import os
import ssl

from sci_app.tls import ensure_self_signed

bind = f"0.0.0.0:{os.environ.get('PORT', '8443')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class = "gthread"
threads = 4
timeout = 30
graceful_timeout = 20
keepalive = 65  # > ALB idle timeout default is 60s; avoids 502s on reused connections
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
worker_tmp_dir = "/tmp"
forwarded_allow_ips = "*"  # only the ALB can reach the port (security group)
proxy_allow_ips = "*"
accesslog = "-"
errorlog = "-"
access_log_format = json.dumps(
    {
        "event": "http_access",
        "remote": "%({x-forwarded-for}i)s",
        "method": "%(m)s",
        "path": "%(U)s",
        "status": "%(s)s",
        "bytes": "%(B)s",
        "duration_us": "%(D)s",
        "user_agent": "%(a)s",
    }
)

if os.environ.get("TLS_ENABLED", "true").lower() == "true":
    tls_dir = os.environ.get("TLS_DIR", "/tmp/tls")
    os.makedirs(tls_dir, mode=0o700, exist_ok=True)
    certfile = os.path.join(tls_dir, "cert.pem")
    keyfile = os.path.join(tls_dir, "key.pem")
    ensure_self_signed(certfile, keyfile)

    def ssl_context(conf, default_ssl_context_factory):
        ctx = default_ssl_context_factory()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
