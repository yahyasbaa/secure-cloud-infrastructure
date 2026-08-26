"""Posture tests against a *deployed* stack.

The same suite runs against:
  * the local moto stack   (SCI_TARGET=local, set by scripts/local-stack.sh)
  * a real AWS environment (SCI_TARGET=aws,   set by scripts/cloud-test.sh)

SCI_NAME is the resource name prefix (e.g. sci-dev). SCI_STATE_JSON optionally
points at `terraform show -json` output for the secret-in-state check.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import boto3
import pytest
from policy_sentry.querying.actions import get_action_data

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("SCI_TARGET"), reason="set SCI_TARGET=local|aws to run live posture tests"),
]

NAME = os.environ.get("SCI_NAME", "sci-dev")
TARGET = os.environ.get("SCI_TARGET", "")
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def aws():
    session = boto3.session.Session()
    return lambda svc: session.client(svc)


@pytest.fixture(scope="module")
def vpc(aws):
    vpcs = aws("ec2").describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [f"{NAME}-vpc"]}])["Vpcs"]
    assert len(vpcs) == 1, f"VPC {NAME}-vpc not found"
    return vpcs[0]


@pytest.fixture(scope="module")
def security_groups(aws, vpc):
    sgs = aws("ec2").describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}])["SecurityGroups"]
    return {sg["GroupName"]: sg for sg in sgs}


# --------------------------------------------------------------------- data
def test_database_not_publicly_accessible_and_encrypted(aws):
    db = aws("rds").describe_db_instances(DBInstanceIdentifier=f"{NAME}-db")["DBInstances"][0]
    assert db["PubliclyAccessible"] is False
    assert db["StorageEncrypted"] is True
    assert db.get("KmsKeyId"), "database must use a KMS key"
    assert db["IAMDatabaseAuthenticationEnabled"] is True
    assert db["BackupRetentionPeriod"] >= 1
    assert db.get("MasterUserSecret", {}).get("SecretArn"), "master password must be RDS-managed"


def test_database_subnets_are_private(aws, vpc):
    ec2 = aws("ec2")
    db = aws("rds").describe_db_instances(DBInstanceIdentifier=f"{NAME}-db")["DBInstances"][0]
    subnet_ids = [s["SubnetIdentifier"] for s in db["DBSubnetGroup"]["Subnets"]]
    _assert_no_internet_route(ec2, subnet_ids)


def _assert_no_internet_route(ec2, subnet_ids):
    for subnet_id in subnet_ids:
        tables = ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])["RouteTables"]
        assert tables, f"{subnet_id} has no explicit route table"
        for table in tables:
            for route in table["Routes"]:
                gw = route.get("GatewayId", "") or ""
                assert not gw.startswith("igw-"), f"{subnet_id} routes to an internet gateway"
                assert not route.get("NatGatewayId"), f"{subnet_id} routes to a NAT gateway"


def test_app_subnets_are_private(aws, vpc):
    ec2 = aws("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "tag:Tier", "Values": ["app", "db"]}])["Subnets"]
    assert len(subnets) >= 4
    for s in subnets:
        assert s["MapPublicIpOnLaunch"] is False
    _assert_no_internet_route(ec2, [s["SubnetId"] for s in subnets])


# ------------------------------------------------------------------ compute
def test_launch_template_hardening(aws):
    ec2 = aws("ec2")
    lt = ec2.describe_launch_template_versions(LaunchTemplateName=f"{NAME}-app", Versions=["$Latest"])["LaunchTemplateVersions"][0]
    data = lt["LaunchTemplateData"]
    assert data["MetadataOptions"]["HttpTokens"] == "required"
    assert data["MetadataOptions"]["HttpPutResponseHopLimit"] == 1
    for ni in data["NetworkInterfaces"]:
        assert ni["AssociatePublicIpAddress"] is False
    for bdm in data["BlockDeviceMappings"]:
        assert bdm["Ebs"]["Encrypted"] is True and bdm["Ebs"].get("KmsKeyId")
    assert "KeyName" not in data, "no SSH key pairs"


def test_running_instances_have_no_public_ip(aws):
    reservations = aws("ec2").describe_instances(
        Filters=[{"Name": "tag:Name", "Values": [f"{NAME}-app"]}, {"Name": "instance-state-name", "Values": ["pending", "running"]}]
    )["Reservations"]
    for res in reservations:
        for inst in res["Instances"]:
            assert not inst.get("PublicIpAddress"), f"{inst['InstanceId']} has a public IP"


def test_load_balancer_https_only(aws):
    elb = aws("elbv2")
    lb = elb.describe_load_balancers(Names=[f"{NAME}-alb"])["LoadBalancers"][0]
    listeners = elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
    assert [(l["Protocol"], l["Port"]) for l in listeners] == [("HTTPS", 443)]
    assert listeners[0]["SslPolicy"].startswith("ELBSecurityPolicy-TLS13-1-2")
    attrs = {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(LoadBalancerArn=lb["LoadBalancerArn"])["Attributes"]}
    assert attrs.get("routing.http.drop_invalid_header_fields.enabled") == "true"
    assert attrs.get("access_logs.s3.enabled") == "true"


def test_waf_protects_load_balancer(aws):
    elb = aws("elbv2")
    lb = elb.describe_load_balancers(Names=[f"{NAME}-alb"])["LoadBalancers"][0]
    acl = aws("wafv2").get_web_acl_for_resource(ResourceArn=lb["LoadBalancerArn"]).get("WebACL")
    assert acl and acl["Name"] == f"{NAME}-web-acl"


# ------------------------------------------------------------------ network
def test_security_groups_are_restrictive(security_groups):
    alb, app, db = security_groups[f"{NAME}-alb"], security_groups[f"{NAME}-app"], security_groups[f"{NAME}-db"]
    for name, sg in security_groups.items():
        for perm in sg["IpPermissions"]:
            open_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            if open_world:
                assert name == f"{NAME}-alb" and perm["FromPort"] == 443 and perm["ToPort"] == 443, f"{name} open to the internet"
            assert perm.get("IpProtocol") != "-1", f"{name} allows all protocols"
    # app accepts only from the ALB; db only from the app tier
    assert all(p["UserIdGroupPairs"][0]["GroupId"] == alb["GroupId"] for p in app["IpPermissions"])
    assert all(p["UserIdGroupPairs"][0]["GroupId"] == app["GroupId"] for p in db["IpPermissions"])
    assert [p["FromPort"] for p in db["IpPermissions"]] == [5432]
    assert db["IpPermissionsEgress"] == [], "database security group must have no egress"


def test_flow_logs_enabled(aws, vpc):
    logs = aws("ec2").describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}])["FlowLogs"]
    assert logs and logs[0]["TrafficType"] == "ALL"


# ---------------------------------------------------------------------- IAM
def _non_scopable(action: str) -> bool:
    service, name = action.split(":", 1)
    rows = get_action_data(service, name).get(service, [])
    return bool(rows) and all(r.get("resource_arn_format") == "*" for r in rows)


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _project_roles(iam):
    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        roles += [r for r in page["Roles"] if r["RoleName"].startswith(f"{NAME}-")]
    return roles


def test_iam_roles_least_privilege(aws):
    iam = aws("iam")
    roles = _project_roles(iam)
    assert {f"{NAME}-app", f"{NAME}-deployment", f"{NAME}-monitoring", f"{NAME}-security-audit"} <= {r["RoleName"] for r in roles}
    for role in roles:
        attached = iam.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]
        assert not attached, f"{role['RoleName']} has managed policies attached: {attached}"
        for pname in iam.list_role_policies(RoleName=role["RoleName"])["PolicyNames"]:
            doc = iam.get_role_policy(RoleName=role["RoleName"], PolicyName=pname)["PolicyDocument"]
            doc = json.loads(doc) if isinstance(doc, str) else doc
            for stmt in _as_list(doc["Statement"]):
                if stmt["Effect"] != "Allow":
                    continue
                actions = _as_list(stmt["Action"])
                assert not any("*" in a for a in actions), f"{role['RoleName']}/{pname}: wildcard action"
                if "*" in _as_list(stmt["Resource"]):
                    scoped = [a for a in actions if not _non_scopable(a)]
                    assert not scoped, f"{role['RoleName']}/{pname} {stmt.get('Sid')}: {scoped} on Resource '*'"


def test_iam_trust_relationships(aws):
    iam = aws("iam")
    for role in _project_roles(iam):
        doc = role["AssumeRolePolicyDocument"]
        doc = json.loads(doc) if isinstance(doc, str) else doc
        for stmt in _as_list(doc["Statement"]):
            principal = stmt.get("Principal")
            assert principal != "*", f"{role['RoleName']}: public trust"
            for ids in (principal or {}).values():
                assert "*" not in _as_list(ids), f"{role['RoleName']}: wildcard principal"
            if "Federated" in principal:
                subs = stmt["Condition"]["StringEquals"]
                assert any(k.endswith(":sub") for k in subs), f"{role['RoleName']}: OIDC trust without sub condition"
            if "AWS" in principal:
                assert stmt["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] == "true"


# ---------------------------------------------------------- storage / crypto
LOG_BUCKET_KINDS = ("-s3-access-logs-", "-cloudtrail-", "-alb-logs-")


def _project_buckets(s3):
    return [
        b["Name"]
        for b in s3.list_buckets()["Buckets"]
        if b["Name"].startswith(f"{NAME}-") and any(k in b["Name"] for k in LOG_BUCKET_KINDS)
    ]


def test_buckets_not_public_and_encrypted(aws):
    s3 = aws("s3")
    buckets = _project_buckets(s3)
    assert len(buckets) == 3
    for b in buckets:
        pab = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
        assert all(pab[k] for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")), b
        rules = s3.get_bucket_encryption(Bucket=b)["ServerSideEncryptionConfiguration"]["Rules"]
        assert rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] in ("aws:kms", "AES256")
        assert s3.get_bucket_versioning(Bucket=b).get("Status") == "Enabled"
        policy = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])
        assert any(st.get("Sid") == "DenyInsecureTransport" for st in policy["Statement"]), b
        for st in policy["Statement"]:
            if st["Effect"] == "Allow":
                assert st.get("Principal") not in ("*", {"AWS": "*"}), f"{b}: public Allow"


def test_cloudtrail_bucket_uses_kms(aws):
    s3 = aws("s3")
    bucket = next(b for b in _project_buckets(s3) if "-cloudtrail-" in b)
    rule = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"


def test_kms_keys_rotate(aws):
    kms = aws("kms")
    aliases = {a["AliasName"]: a for a in kms.list_aliases()["Aliases"]}
    for alias in (f"alias/{NAME}-data", f"alias/{NAME}-logs"):
        assert alias in aliases, f"{alias} missing"
        key_id = aliases[alias]["TargetKeyId"]
        assert kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is True


def test_secrets_use_customer_managed_key(aws):
    sm = aws("secretsmanager")
    secret = sm.describe_secret(SecretId=f"{NAME}/app/api-token")
    data_key = aws("kms").describe_key(KeyId=f"alias/{NAME}-data")["KeyMetadata"]
    assert secret.get("KmsKeyId") in (data_key["Arn"], data_key["KeyId"], f"alias/{NAME}-data")


def test_secret_value_not_in_terraform_state(aws):
    state_file = os.environ.get("SCI_STATE_JSON") or str(ROOT / "reports" / f"{TARGET}-state.json")
    if not Path(state_file).exists():
        pytest.skip("no state export available")
    value = aws("secretsmanager").get_secret_value(SecretId=f"{NAME}/app/api-token")["SecretString"]
    assert len(value) >= 32
    assert value not in Path(state_file).read_text(), "application token leaked into Terraform state"


# ------------------------------------------------------------ logging/alerts
def test_cloudtrail_enabled(aws):
    ct = aws("cloudtrail")
    trail = ct.describe_trails(trailNameList=[f"{NAME}-trail"])["trailList"][0]
    assert trail["IsMultiRegionTrail"] is True
    assert trail["LogFileValidationEnabled"] is True
    assert trail.get("KmsKeyId")
    assert trail.get("CloudWatchLogsLogGroupArn")
    assert ct.get_trail_status(Name=trail["TrailARN"])["IsLogging"] is True


def test_log_groups_encrypted_with_retention(aws):
    logs = aws("logs")
    groups = []
    for prefix in (f"/{NAME}/", f"/aws/rds/instance/{NAME}-db/", f"aws-waf-logs-{NAME}"):
        groups += logs.describe_log_groups(logGroupNamePrefix=prefix)["logGroups"]
    assert len(groups) >= 6
    for g in groups:
        assert g.get("kmsKeyId"), f"{g['logGroupName']} not KMS-encrypted"
        assert g.get("retentionInDays"), f"{g['logGroupName']} has no retention"


def test_security_alarms_exist_and_notify(aws):
    cw = aws("cloudwatch")
    alarms = []
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNamePrefix=f"{NAME}-"):
        alarms += page["MetricAlarms"]
    names = {a["AlarmName"] for a in alarms}
    for required in ("unauthorized-api-calls", "console-signin-failures", "app-auth-failures", "db-auth-failures",
                     "security-group-changes", "iam-policy-changes", "unexpected-secret-access", "alb-request-anomaly"):
        assert f"{NAME}-{required}" in names, f"missing alarm {required}"
    topic = f":{NAME}-security-alarms"
    for alarm in alarms:
        assert any(a.endswith(topic) for a in alarm["AlarmActions"]), f"{alarm['AlarmName']} does not notify"


def test_metric_filters_feed_alarms(aws):
    logs = aws("logs")
    filters = logs.describe_metric_filters(logGroupName=f"/{NAME}/cloudtrail")["metricFilters"]
    names = {f["filterName"] for f in filters}
    assert f"{NAME}-security-group-changes" in names and f"{NAME}-iam-policy-changes" in names
    app_filters = logs.describe_metric_filters(logGroupName=f"/{NAME}/app")["metricFilters"]
    assert any('auth_failure' in f["filterPattern"] for f in app_filters)
