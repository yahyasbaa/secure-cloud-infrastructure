"""Audit logging and detection coverage (static)."""

from __future__ import annotations

import re

from .hcl import ROOT, load

CFG = load()


def test_cloudtrail_enabled_and_hardened():
    trails = CFG.resources("aws_cloudtrail")
    assert len(trails) == 1
    t = trails[0].body
    assert t["is_multi_region_trail"] is True
    assert t["include_global_service_events"] is True
    assert t["enable_log_file_validation"] is True
    assert t.get("enable_logging", True) is True
    assert "cloud_watch_logs_group_arn" in t and "cloud_watch_logs_role_arn" in t
    selector = t["event_selector"][0]
    assert selector["read_write_type"] == "All" and selector["include_management_events"] is True


def test_cloudtrail_logs_cannot_be_deleted():
    doc = next(d for d in CFG.data("aws_iam_policy_document") if d.name == "cloudtrail_bucket")
    dyn = doc.body["dynamic"][0]["statement"]["content"][0]
    assert dyn["sid"] == "DenyLogDeletion" and dyn["effect"] == "Deny"
    assert "s3:DeleteObject" in dyn["actions"]


def test_vpc_flow_logs_enabled():
    logs = CFG.resources("aws_flow_log")
    assert logs and logs[0].body["traffic_type"] == "ALL"
    assert logs[0].body["vpc_id"] == "${aws_vpc.this.id}"


def test_alb_waf_and_database_logging():
    alb = CFG.resources("aws_lb")[0].body
    assert alb["access_logs"][0]["enabled"] is True and alb["connection_logs"][0]["enabled"] is True
    assert CFG.resources("aws_wafv2_web_acl_logging_configuration")
    db = CFG.resources("aws_db_instance")[0].body
    assert set(db["enabled_cloudwatch_logs_exports"]) == {"postgresql", "upgrade"}
    assert db["monitoring_interval"] > 0


def test_bucket_access_logging():
    logging = CFG.resources("aws_s3_bucket_logging")
    logged = {b.body["bucket"].split(".")[1] for b in logging}
    targets = {b.body["target_bucket"].split(".")[1] for b in logging}
    for bucket in CFG.resources("aws_s3_bucket"):
        if bucket.name in targets:
            continue  # access-log target buckets cannot log to themselves
        assert bucket.name in logged, f"{bucket.address}: no server access logging"


REQUIRED_DETECTIONS = {
    "app-auth-failures": "repeated authentication failures (application)",
    "console-signin-failures": "repeated authentication failures (console)",
    "db-auth-failures": "repeated authentication failures (database)",
    "unauthorized-api-calls": "unauthorized API calls",
    "security-group-changes": "security group changes",
    "iam-policy-changes": "IAM policy changes",
    "unexpected-secret-access": "unusual access patterns",
    "cloudtrail-changes": "audit trail tampering",
    "root-account-usage": "root user activity",
}


def test_required_security_alarms_exist():
    text = (ROOT / "terraform" / "modules" / "monitoring" / "alarms.tf").read_text()
    defined = set(re.findall(r'^\s+"([a-z0-9-]+)" = \{', text, re.M))
    missing = {k: v for k, v in REQUIRED_DETECTIONS.items() if k not in defined}
    assert not missing, f"missing detections: {missing}"
    assert "ANOMALY_DETECTION_BAND" in text, "an anomaly-detection alarm is required for unusual access patterns"


def test_alarms_notify():
    for alarm in CFG.resources("aws_cloudwatch_metric_alarm"):
        assert alarm.body.get("alarm_actions") == ["${aws_sns_topic.alarms.arn}"], f"{alarm.address}: no notification"
