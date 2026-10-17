# syntax=docker/dockerfile:1.7
#
# Hardened application image.
#  * base image pinned by digest (reproducible, tamper-evident)
#  * dependencies installed with --require-hashes from app/requirements.txt
#  * multi-stage: no compiler, pip cache or build tooling in the runtime image
#  * runs as an unprivileged, non-login user (uid 10001)
#  * works with a read-only root filesystem (writes only to /tmp, a tmpfs)
#  * RDS CA bundle pinned by checksum so the app can use sslmode=verify-full

FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY app/requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.txt

FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS runtime
LABEL org.opencontainers.image.title="sci-app" \
      org.opencontainers.image.description="Secure Cloud Infrastructure demo API" \
      org.opencontainers.image.licenses="MIT"

# Patch OS packages at build time, then drop apt metadata.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app

# checkov:skip=CKV_DOCKER_4:ADD --checksum is the only Dockerfile instruction that fetches a remote file with integrity verification; COPY cannot fetch.
ADD --checksum=sha256:fe45bbebf92ad3e27a583bbb2ddd1553c521ed4d49af5514dc0a40372ea5395c \
    https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /etc/ssl/rds/global-bundle.pem
RUN chmod 0444 /etc/ssl/rds/global-bundle.pem

COPY --from=build /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=root:root --chmod=0555 app/sci_app ./sci_app
COPY --chown=root:root --chmod=0444 app/gunicorn.conf.py ./gunicorn.conf.py

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8443 \
    TLS_ENABLED=true \
    TLS_DIR=/tmp/tls \
    DB_SSLROOTCERT=/etc/ssl/rds/global-bundle.pem

USER 10001:10001
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import ssl,urllib.request;c=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE;urllib.request.urlopen('https://127.0.0.1:8443/health',context=c,timeout=4)"]

ENTRYPOINT ["gunicorn", "--config", "/srv/gunicorn.conf.py", "sci_app.wsgi:app"]
