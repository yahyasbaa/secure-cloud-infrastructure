"""Every scanner suppression must carry a reason and be registered.

Suppressing a finding is a risk-acceptance decision. This test makes sure no
suppression can be added silently: each must state why on the same line and
be listed in security/suppressions.md.
"""

from __future__ import annotations

import re

from .hcl import ROOT

SCAN_DIRS = ["terraform", "app", "docker", ".github", "scripts"]
CHECKOV = re.compile(r"#\s*checkov:skip=([A-Z0-9_]+):(.*)$")
TFSEC = re.compile(r"#\s*tfsec:ignore:([a-z0-9-]+)(.*)$")
TRIVY = re.compile(r"trivy:ignore:(AVD-[A-Z]+-\d+)(.*)$")
NOSEMGREP = re.compile(r"nosemgrep(?::\s*([\w.-]+))?(.*)$")


def _suppressions():
    for d in SCAN_DIRS:
        for path in (ROOT / d).rglob("*"):
            if not path.is_file() or ".terraform" in path.parts or path.suffix in {".pyc"}:
                continue
            try:
                lines = path.read_text().splitlines()
            except UnicodeDecodeError:
                continue
            for n, line in enumerate(lines, 1):
                for kind, rx in (("checkov", CHECKOV), ("tfsec", TFSEC), ("trivy", TRIVY), ("semgrep", NOSEMGREP)):
                    m = rx.search(line)
                    if m:
                        yield kind, m.group(1) or "", m.group(2) or "", path.relative_to(ROOT), n


def test_suppressions_have_reasons():
    missing = []
    for kind, rule, reason, path, line in _suppressions():
        text = reason.strip(" :-")
        if len(text) < 15:
            missing.append(f"{path}:{line} {kind} {rule}")
    assert not missing, "suppressions without a written justification:\n" + "\n".join(missing)


def test_suppressions_are_registered():
    register = (ROOT / "security" / "suppressions.md").read_text()
    unregistered = sorted({f"{kind}:{rule}" for kind, rule, *_ in _suppressions() if rule and rule not in register})
    assert not unregistered, f"add these to security/suppressions.md: {unregistered}"


def test_no_blanket_skips_in_scanner_configs():
    import yaml

    checkov_cfg = yaml.safe_load((ROOT / "security" / "checkov.yaml").read_text())
    for key in ("skip-check", "skip-framework", "soft-fail-on", "skip-path"):
        assert key not in checkov_cfg, f"checkov.yaml must not use {key}; use reasoned inline skips"
    assert checkov_cfg["soft-fail"] is False
