"""Secrets must never be hard-coded (complements the gitleaks scan)."""

from __future__ import annotations

import re
from pathlib import Path

from .hcl import ROOT, load

EXCLUDED_DIRS = {".git", ".tools", ".local", ".terraform", "reports", "__pycache__", ".pytest_cache", "node_modules", ".venv"}

PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "hardcoded_password": re.compile(r"(?i)\b(password|passwd|secret|api_key|token)\s*[:=]\s*['\"][^'\"\s$<{]{8,}['\"]"),
}


def scan_text(text: str) -> list[str]:
    return [name for name, rx in PATTERNS.items() if rx.search(text)]


def repo_files() -> list[Path]:
    out = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or EXCLUDED_DIRS & set(path.relative_to(ROOT).parts):
            continue
        if path.suffix in {".png", ".jpg", ".gz", ".zip", ".pem"} or path.name == ".env":
            continue
        out.append(path)
    return out


def test_scanner_detects_planted_secrets():
    """Self-test so a broken regex cannot silently pass the repository."""
    fake_key = "AKIA" + "Q" * 16
    assert "aws_access_key_id" in scan_text(f"key = {fake_key}")
    assert "private_key" in scan_text("-----BEGIN " + "PRIVATE KEY-----")
    assert "hardcoded_password" in scan_text('password = "' + "hunter2hunter2" + '"')


def test_no_secrets_in_repository():
    hits = []
    for path in repo_files():
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        for name in scan_text(text):
            hits.append(f"{path.relative_to(ROOT)}: {name}")
    assert not hits, "possible hard-coded secrets:\n" + "\n".join(hits)


def test_env_example_has_only_placeholders():
    lines = [ln for ln in (ROOT / ".env.example").read_text().splitlines() if ln and not ln.startswith("#")]
    assert lines
    for line in lines:
        key, _, value = line.partition("=")
        if any(word in key for word in ("PASSWORD", "TOKEN", "SECRET", "KEY")):
            assert re.fullmatch(r"<[a-z0-9-]+>", value), f".env.example {key} must be a <placeholder>, got {value!r}"


def test_env_files_are_ignored():
    gitignore = (ROOT / ".gitignore").read_text().splitlines()
    for pattern in (".env", "*.tfstate", "*.tfvars.json", "backend.hcl"):
        assert any(line.strip() == pattern or line.strip().endswith(pattern) for line in gitignore), f"{pattern} not git-ignored"
    assert "!.env.example" in gitignore


def test_terraform_has_no_secret_inputs_or_literals():
    cfg = load()
    for db in cfg.resources("aws_db_instance"):
        assert "password" not in db.body, "RDS password must be managed by RDS, not Terraform"
    variables = (ROOT / "terraform" / "variables.tf").read_text()
    for forbidden in ("password", "secret_key", "access_key"):
        assert f'variable "{forbidden}' not in variables


def test_app_reads_secrets_from_secrets_manager_only():
    config_src = (ROOT / "app" / "sci_app" / "config.py").read_text()
    assert "must not be set in the aws runtime" in config_src
    user_data = (ROOT / "terraform" / "modules" / "compute" / "templates" / "user_data.sh.tftpl").read_text()
    assert "APP_SECRET_ARN" in user_data and "DB_SECRET_ARN" in user_data
    assert "DB_PASSWORD" not in user_data and "APP_API_TOKEN" not in user_data
