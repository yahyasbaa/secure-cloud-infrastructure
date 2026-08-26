"""Terraform configuration validity (fmt + validate) and repo hygiene."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from .hcl import ROOT, TF_ROOT, load

TERRAFORM = ROOT / ".tools" / "bin" / "terraform"
TF_BIN = str(TERRAFORM) if TERRAFORM.exists() else shutil.which("terraform")
needs_tf = pytest.mark.skipif(TF_BIN is None, reason="terraform binary not installed (run make tools)")


def _tf(*args: str, cwd=TF_ROOT) -> subprocess.CompletedProcess:
    env = dict(os.environ, TF_DATA_DIR=str(ROOT / ".local" / "tfdata-validate"), TF_IN_AUTOMATION="1")
    return subprocess.run([TF_BIN, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)


@pytest.mark.terraform
@needs_tf
def test_terraform_fmt():
    result = _tf("fmt", "-check", "-recursive", "-diff")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.terraform
@needs_tf
@pytest.mark.parametrize("module_root", ["terraform", "terraform/bootstrap"])
def test_terraform_validate(module_root):
    cwd = ROOT / module_root
    env_dir = ROOT / ".local" / f"tfdata-validate-{cwd.name}"
    env = dict(os.environ, TF_DATA_DIR=str(env_dir), TF_IN_AUTOMATION="1")
    init = subprocess.run([TF_BIN, "init", "-backend=false", "-input=false", "-no-color"], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    assert init.returncode == 0, init.stdout + init.stderr
    val = subprocess.run([TF_BIN, "validate", "-no-color"], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    assert val.returncode == 0, val.stdout + val.stderr


def test_provider_versions_are_pinned():
    providers = (TF_ROOT / "providers.tf").read_text()
    assert 'required_version = ">= 1.11.0, < 2.0.0"' in providers
    assert "~> 6." in providers
    assert (TF_ROOT / ".terraform.lock.hcl").exists(), "commit the dependency lock file"


def test_state_backend_is_remote_and_locked():
    providers = (TF_ROOT / "providers.tf").read_text()
    assert 'backend "s3"' in providers
    for env in ("local",):
        backend = (TF_ROOT / "environments" / env / "backend.hcl").read_text()
        assert "use_lockfile" in backend and "encrypt" in backend


def test_variables_documented_and_typed():
    cfg = load()
    for path in cfg.files:
        if path.name != "variables.tf":
            continue
        import hcl2

        with path.open() as fh:
            parsed = hcl2.load(fh)
        for entry in parsed.get("variable", []):
            for name, body in entry.items():
                assert "description" in body, f"{path}: variable {name} lacks a description"
                assert "type" in body, f"{path}: variable {name} lacks a type"


def test_no_local_state_committed():
    stray = [p for p in ROOT.rglob("*.tfstate*") if ".local" not in p.parts and ".terraform" not in p.parts]
    assert not stray, f"state files must never be in the repository: {stray}"
