"""Documentation that the security model depends on must stay in sync with the code."""

from __future__ import annotations

import re

from .hcl import ROOT

DOCS = ROOT / "docs"


def test_every_alarm_is_documented():
    alarms_tf = (ROOT / "terraform" / "modules" / "monitoring" / "alarms.tf").read_text()
    log_alarms = re.findall(r'^\s+"([a-z0-9-]+)" = \{', alarms_tf, re.M)
    metric_alarms = re.findall(r'alarm_name\s+=\s+"\$\{var\.name\}-([a-z0-9-]+)"', alarms_tf)
    events_tf = (ROOT / "terraform" / "modules" / "monitoring" / "events.tf").read_text()
    rules = re.findall(r'name\s+=\s+"\$\{var\.name\}-([a-z0-9-]+)"', events_tf)
    doc = (DOCS / "monitoring.md").read_text()
    names = set(log_alarms) | set(metric_alarms) | set(rules)
    assert len(names) >= 25
    missing = sorted(n for n in names if f"`{n}`" not in doc)
    assert not missing, f"alarms/rules missing from docs/monitoring.md: {missing}"


REQUIRED_THREATS = [
    "Credential compromise",
    "Public exposure",
    "Privilege escalation",
    "Data exfiltration",
    "Misconfigured security groups",
    "Compromised application",
    "Malicious insider",
    "Cloud API abuse",
]


def test_threat_model_covers_required_threats():
    text = (DOCS / "threat-model.md").read_text()
    assert "STRIDE" in text
    sections = re.split(r"^### ", text, flags=re.M)
    for threat in REQUIRED_THREATS:
        match = [s for s in sections if s.split("\n", 1)[0].endswith(threat)]
        assert match, f"threat model lacks a section for: {threat}"
        body = match[0]
        for field in ("**Threat**", "**Likelihood**", "**Impact**", "**Preventive controls**", "**Detective controls**", "**Response**"):
            assert field in body, f"{threat}: missing {field}"


def test_encryption_doc_covers_each_data_store():
    text = (DOCS / "encryption.md").read_text()
    for item in ("RDS storage", "EBS", "Secrets Manager", "CloudTrail", "CloudWatch log groups", "S3", "ECR", "SNS"):
        assert item in text, f"encryption.md does not cover {item}"
    for column in ("Key", "Who can use", "Why"):
        assert column in text


def test_required_project_files_exist():
    for rel in ("README.md", "SECURITY.md", ".env.example", ".gitignore", "Makefile", "docs/threat-model.md",
                "docs/iam-model.md", "docs/network-security.md", "docs/encryption.md", "docs/monitoring.md",
                "docs/deployment.md", "docs/known-limitations.md", "docs/testing.md", "security/suppressions.md"):
        assert (ROOT / rel).is_file(), f"missing {rel}"


def test_makefile_exposes_required_targets():
    makefile = (ROOT / "Makefile").read_text()
    for target in ("validate", "security-test", "security-scan", "all", "local-stack", "destroy"):
        assert re.search(rf"^{target}:", makefile, re.M), f"make {target} missing"
