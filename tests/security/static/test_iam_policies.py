"""IAM least-privilege tests (static, no AWS needed).

Detects:
  * "*" (or service:*) actions in any Allow statement
  * Resource "*" in identity policies, unless every action in the statement is
    one AWS does not allow to be scoped (checked against the policy_sentry IAM
    database, not a hand-maintained list)
  * administrator / power-user / full-access managed policy attachments
  * public or unconditioned trust relationships
  * IAM users and long-lived access keys
"""

from __future__ import annotations

import re

import pytest
from policy_sentry.querying.actions import get_action_data

from .hcl import ROOT, classify_policy_documents, load, resolve_list, statements

CFG = load()
GROUPS = classify_policy_documents(CFG)
FORBIDDEN_MANAGED = re.compile(r"(AdministratorAccess|PowerUserAccess|IAMFullAccess|FullAccess)", re.I)


def _all_statements(group: str):
    for doc in GROUPS[group]:
        for idx, stmt in enumerate(statements(doc)):
            yield doc, idx, stmt


def _effect(stmt) -> str:
    return stmt.get("effect", "Allow")


def _actions(doc, stmt) -> list[str]:
    acts = resolve_list(stmt.get("actions"), doc, CFG)
    assert acts is not None, f"{doc.address}: cannot resolve actions {stmt.get('actions')!r}"
    return acts


def _resources(stmt) -> list[str]:
    res = stmt.get("resources", [])
    return res if isinstance(res, list) else [res]


def _is_non_resource_scoped(action: str) -> bool:
    """True when AWS supports no resource-level permissions for the action."""
    service, name = action.split(":", 1)
    rows = get_action_data(service, name).get(service, [])
    assert rows, f"unknown IAM action {action} (typo or retired action?)"
    return all(r.get("resource_arn_format") == "*" for r in rows)


def test_policy_documents_found():
    assert len(GROUPS["identity"]) >= 7
    assert len(GROUPS["trust"]) >= 6
    assert not GROUPS["unused"], f"unused policy documents: {[d.address for d in GROUPS['unused']]}"


@pytest.mark.parametrize("group", ["identity", "trust", "resource"])
def test_no_wildcard_actions_in_allow_statements(group):
    offenders = []
    for doc, idx, stmt in _all_statements(group):
        if _effect(stmt) != "Allow":
            continue  # wildcards in Deny statements only make them stronger
        for action in _actions(doc, stmt):
            if "*" in action:
                offenders.append(f"{doc.address} statement[{idx}] {action}")
    assert not offenders, "wildcard actions in Allow statements:\n" + "\n".join(offenders)


def test_identity_policies_scope_resources():
    offenders = []
    for doc, idx, stmt in _all_statements("identity"):
        if _effect(stmt) != "Allow":
            continue
        if "*" in _resources(stmt):
            scoped = [a for a in _actions(doc, stmt) if not _is_non_resource_scoped(a)]
            if scoped:
                offenders.append(f"{doc.address} {stmt.get('sid')}: {scoped} support resource-level permissions but use Resource '*'")
    assert not offenders, "\n".join(offenders)


def test_identity_statements_are_explicit():
    """Every identity statement names its Sid, Effect, Actions and Resources."""
    problems = []
    for doc, idx, stmt in _all_statements("identity"):
        for key in ("sid", "effect", "actions", "resources"):
            if key not in stmt:
                problems.append(f"{doc.address} statement[{idx}] missing {key}")
    assert not problems, "\n".join(problems)


def test_identity_actions_exist():
    """Catches typos: every action must exist in the IAM reference database."""
    for doc, _, stmt in _all_statements("identity"):
        for action in _actions(doc, stmt):
            service, name = action.split(":", 1)
            assert get_action_data(service, name).get(service), f"{doc.address}: unknown action {action}"


def test_every_identity_sid_is_documented():
    doc_text = (ROOT / "docs" / "iam-model.md").read_text()
    missing = sorted(
        {stmt["sid"] for _, _, stmt in _all_statements("identity") if stmt.get("sid") and f"`{stmt['sid']}`" not in doc_text}
    )
    assert not missing, f"undocumented IAM statements in docs/iam-model.md: {missing}"


def test_privileged_wildcard_resources_are_justified():
    """Identity statements on Resource '*' must be explained in docs/iam-model.md."""
    doc_text = (ROOT / "docs" / "iam-model.md").read_text()
    for doc, _, stmt in _all_statements("identity"):
        if _effect(stmt) == "Allow" and "*" in _resources(stmt):
            sid = stmt.get("sid")
            section = doc_text.split(f"`{sid}`", 1)
            assert len(section) == 2 and "resource-level" in section[1][:600].lower(), (
                f"{sid}: Resource '*' needs a 'resource-level' justification next to it in docs/iam-model.md"
            )


def test_no_admin_managed_policies():
    offenders = []
    for rtype in ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment"):
        for b in CFG.resources(rtype):
            if FORBIDDEN_MANAGED.search(str(b.body.get("policy_arn", ""))):
                offenders.append(b.address)
    for b in CFG.resources("aws_iam_role"):
        for arn in b.body.get("managed_policy_arns", []) or []:
            if FORBIDDEN_MANAGED.search(str(arn)):
                offenders.append(b.address)
    assert not offenders, f"administrative managed policies attached: {offenders}"


def test_no_aws_managed_policies_at_all():
    """All permissions are customer-written so they can be reviewed line by line."""
    attachments = [b.address for t in ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment") for b in CFG.resources(t)]
    assert not attachments, f"unexpected managed policy attachments: {attachments}"


def test_no_iam_users_or_access_keys():
    found = [b.address for t in ("aws_iam_user", "aws_iam_access_key", "aws_iam_user_login_profile") for b in CFG.resources(t)]
    assert not found, f"long-lived IAM users/keys are forbidden (use roles + OIDC): {found}"


def test_trust_policies_have_no_public_principals():
    offenders = []
    for doc, idx, stmt in _all_statements("trust"):
        for principal in stmt.get("principals", []):
            ids = principal.get("identifiers", [])
            if principal.get("type") == "*" or "*" in (ids if isinstance(ids, list) else [ids]):
                offenders.append(f"{doc.address} statement[{idx}]")
    assert not offenders, f"public trust relationships: {offenders}"


def _conditions(stmt) -> dict[str, tuple[str, list]]:
    return {c["variable"]: (c["test"], c["values"]) for c in stmt.get("condition", [])}


def test_trust_policy_conditions():
    """Each trust relationship is narrowed to its intended caller."""
    for doc, idx, stmt in _all_statements("trust"):
        conds = _conditions(stmt)
        for principal in stmt.get("principals", []):
            ptype = principal["type"]
            if ptype == "Federated":
                aud = [v for k, v in conds.items() if k.endswith(":aud")]
                sub = [v for k, v in conds.items() if k.endswith(":sub")]
                assert aud and aud[0][0] == "StringEquals", f"{doc.address}: OIDC trust needs StringEquals on :aud"
                assert sub and sub[0][0] == "StringEquals", f"{doc.address}: OIDC trust needs StringEquals (not StringLike) on :sub"
                assert all("*" not in v for v in sub[0][1]), f"{doc.address}: OIDC :sub must not contain wildcards"
            elif ptype == "AWS":
                assert conds.get("aws:MultiFactorAuthPresent", (None, []))[1] == ["true"], f"{doc.address}: human role trust must require MFA"
            elif ptype == "Service":
                ids = principal["identifiers"]
                if ids == ["ec2.amazonaws.com"]:
                    continue  # EC2 instance profiles cannot carry source conditions
                assert {"aws:SourceAccount", "aws:SourceArn"} & set(conds), (
                    f"{doc.address}: service trust needs aws:SourceAccount/aws:SourceArn (confused deputy protection)"
                )


def test_roles_limit_session_duration():
    for role in CFG.resources("aws_iam_role"):
        assert role.body.get("max_session_duration", 3600) <= 3600, f"{role.address}: sessions longer than 1h"


def test_endpoint_policies_restrict_to_account():
    for doc in GROUPS["resource"]:
        if "endpoint" not in doc.name:
            continue
        for stmt in statements(doc):
            conds = _conditions(stmt)
            assert "aws:PrincipalAccount" in conds, f"{doc.address}: endpoint policy must restrict aws:PrincipalAccount"


def test_kms_key_policies_have_no_wildcard_principals():
    for doc in GROUPS["resource"]:
        if not doc.name.endswith("_key"):
            continue
        for stmt in statements(doc):
            for principal in stmt.get("principals", []):
                ids = principal.get("identifiers", [])
                assert "*" not in ids, f"{doc.address}: KMS key policy grants to '*'"


def test_secretsmanager_access_requires_kms_via_service():
    app = CFG.find("data", "aws_iam_policy_document", "app", ROOT / "terraform" / "modules" / "iam")
    assert app is not None
    kms = [s for s in statements(app) if any(a.startswith("kms:") for a in _actions(app, s))]
    assert kms, "app role must be able to decrypt its secrets"
    for stmt in kms:
        assert _actions(app, stmt) == ["kms:Decrypt"]
        assert "kms:ViaService" in _conditions(stmt), "kms:Decrypt must be limited to calls via Secrets Manager"
        assert stmt["resources"] == ["${var.data_kms_key_arn}"], "kms:Decrypt must target only the data key"
