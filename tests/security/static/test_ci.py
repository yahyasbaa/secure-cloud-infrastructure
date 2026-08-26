"""GitHub Actions supply-chain and credential hygiene."""

from __future__ import annotations

import re

import pytest
import yaml

from .hcl import ROOT

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _load(path):
    data = yaml.safe_load(path.read_text())
    # PyYAML parses the bare key `on` as boolean True
    data["on"] = data.pop(True, data.get("on"))
    return data


@pytest.fixture(params=WORKFLOWS, ids=lambda p: p.name)
def workflow(request):
    return request.param, _load(request.param)


def test_workflows_exist():
    names = {p.name for p in WORKFLOWS}
    assert {"ci.yml", "deploy.yml"} <= names


def test_actions_pinned_to_commit_sha(workflow):
    path, wf = workflow
    for job_name, job in wf["jobs"].items():
        if "uses" in job:  # reusable workflow call
            assert job["uses"].startswith("./"), f"{path.name}:{job_name} calls a remote workflow"
            continue
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses and not uses.startswith("./"):
                assert SHA_PIN.match(uses), f"{path.name}:{job_name} action not pinned to a commit SHA: {uses}"


def test_least_privilege_token(workflow):
    path, wf = workflow
    assert wf.get("permissions") == {"contents": "read"}, f"{path.name}: default token must be read-only"
    allowed = {"contents": {"read"}, "security-events": {"write"}, "id-token": {"write"}}
    for job_name, job in wf["jobs"].items():
        for scope, level in (job.get("permissions") or {}).items():
            assert level in allowed.get(scope, set()), f"{path.name}:{job_name} requests {scope}: {level}"


def test_no_dangerous_triggers(workflow):
    path, wf = workflow
    assert "pull_request_target" not in (wf["on"] or {}), f"{path.name}: pull_request_target is forbidden"


def test_no_static_aws_credentials():
    for path in WORKFLOWS:
        text = path.read_text()
        for needle in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "aws-access-key-id", "aws-secret-access-key", "secrets.AWS"):
            assert needle not in text, f"{path.name}: static AWS credentials referenced ({needle})"


def test_checkout_does_not_persist_credentials(workflow):
    path, wf = workflow
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, f"{path.name}: checkout persists the token"


def test_jobs_have_timeouts(workflow):
    path, wf = workflow
    for job_name, job in wf["jobs"].items():
        if "uses" not in job:
            assert "timeout-minutes" in job, f"{path.name}:{job_name} has no timeout"


def test_untrusted_input_not_interpolated_in_scripts(workflow):
    path, wf = workflow
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            script = step.get("run", "")
            assert "${{ github.event" not in script and "${{ github.head_ref" not in script, (
                f"{path.name}: untrusted context interpolated into a shell script; pass it via env"
            )


def test_deploy_uses_oidc_and_protected_environment():
    wf = _load(ROOT / ".github" / "workflows" / "deploy.yml")
    deploy = wf["jobs"]["deploy"]
    assert deploy["environment"] == "dev"
    assert deploy["permissions"]["id-token"] == "write"
    assert "ci" in deploy["needs"], "deployment must depend on the full CI pipeline"
    creds = [s for s in deploy["steps"] if "configure-aws-credentials" in str(s.get("uses", ""))]
    assert creds and "role-to-assume" in creds[0]["with"]


def test_ci_gates_have_no_continue_on_error():
    wf = _load(ROOT / ".github" / "workflows" / "ci.yml")
    for job_name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            if step.get("continue-on-error"):
                assert "upload-sarif" in str(step.get("uses", "")), f"{job_name}: a gate step may not continue on error"


def test_ci_covers_required_stages():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    for stage in ("make fmt-check", "make tf-validate", "security-scan.sh iac", "security-scan.sh secrets",
                  "security-scan.sh image", "make unit-test", "make security-test", "make docker-build"):
        assert stage in text, f"CI is missing stage: {stage}"
    build = _load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]["build"]
    assert set(build["needs"]) >= {"terraform", "iac-scan", "secret-scan", "sast", "tests", "container"}
