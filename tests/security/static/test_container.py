"""Container image hardening (static Dockerfile checks)."""

from __future__ import annotations

import re

from .hcl import ROOT

DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text()


def test_base_image_pinned_by_digest():
    images = re.findall(r"^FROM\s+(\S+)", DOCKERFILE, re.M)
    assert images
    for image in images:
        assert "@sha256:" in image, f"unpinned base image: {image}"
        assert ":latest" not in image


def test_runs_as_non_root():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.M)
    assert users, "image must declare a USER"
    assert users[-1].split(":")[0] not in ("root", "0"), "final USER must not be root"


def test_remote_downloads_are_checksummed():
    for line in re.findall(r"^ADD\s+.*$", DOCKERFILE, re.M):
        if "http" in line:
            assert "--checksum=sha256:" in line, f"remote ADD without checksum: {line}"
    assert "curl " not in DOCKERFILE and "wget " not in DOCKERFILE


def test_dependencies_installed_with_hashes():
    assert "--require-hashes" in DOCKERFILE
    reqs = (ROOT / "app" / "requirements.txt").read_text()
    pinned = [ln for ln in reqs.splitlines() if re.match(r"^[a-z0-9_.-]+==", ln, re.I)]
    assert pinned and reqs.count("--hash=sha256:") >= len(pinned)


def test_healthcheck_and_no_secrets_in_env():
    assert "HEALTHCHECK" in DOCKERFILE
    env_block = " ".join(re.findall(r"^ENV .*?(?:\n(?:\s+.*\\?\n?)*)", DOCKERFILE, re.M))
    for word in ("PASSWORD", "TOKEN=", "SECRET="):
        assert word not in env_block


def test_build_context_is_allow_list():
    rules = [ln.strip() for ln in (ROOT / ".dockerignore").read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    assert rules[0] == "*", "dockerignore must exclude everything first, then allow-list"
    assert all(r.startswith("!") or r.startswith("**/") for r in rules[1:])
