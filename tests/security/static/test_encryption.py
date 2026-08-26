"""Encryption-at-rest and in-transit tests (static)."""

from __future__ import annotations

from .hcl import load

CFG = load()


def test_kms_keys_rotate_and_have_policies():
    keys = CFG.resources("aws_kms_key")
    stack_keys = {k.name for k in keys if k.module_dir.name == "security"}
    assert stack_keys == {"data", "logs"}, "expected separate data and logs keys in the main stack"
    for key in keys:
        assert key.body.get("enable_key_rotation") is True, f"{key.address}: rotation disabled"
        window = key.body.get("deletion_window_in_days", 0)
        if window == "${var.key_deletion_window_days}":
            text = (key.module_dir / "variables.tf").read_text()
            assert "default     = 30" in text and "key_deletion_window_days >= 7" in text
        else:
            assert window >= 7, f"{key.address}: deletion window too short"
        assert "policy" in key.body, f"{key.address}: explicit key policy required"


def test_database_encrypted():
    for db in CFG.resources("aws_db_instance"):
        assert db.body["storage_encrypted"] is True
        assert db.body["kms_key_id"] == "${var.data_kms_key_arn}"
        assert db.body["master_user_secret_kms_key_id"] == "${var.data_kms_key_arn}"


def test_ebs_encrypted():
    for lt in CFG.resources("aws_launch_template"):
        for bdm in lt.body["block_device_mappings"]:
            ebs = bdm["ebs"][0]
            assert ebs["encrypted"] is True and ebs["kms_key_id"] == "${var.data_kms_key_arn}"


def test_every_bucket_has_encryption():
    buckets = {b.name for b in CFG.resources("aws_s3_bucket")}
    encrypted = {
        e.body["bucket"].split(".")[1] for e in CFG.resources("aws_s3_bucket_server_side_encryption_configuration")
    }
    assert buckets <= encrypted, f"buckets without encryption config: {buckets - encrypted}"


def test_every_log_group_encrypted_with_retention():
    groups = CFG.resources("aws_cloudwatch_log_group")
    assert len(groups) >= 6
    for g in groups:
        assert g.body.get("kms_key_id", "").startswith("${var.logs_kms_key_arn"), f"{g.address}: not KMS encrypted"
        assert "retention_in_days" in g.body, f"{g.address}: unbounded retention"


def test_secrets_use_customer_managed_key():
    for s in CFG.resources("aws_secretsmanager_secret"):
        assert s.body.get("kms_key_id") == "${aws_kms_key.data.arn}", f"{s.address}: must use the data CMK"


def test_secret_value_is_write_only():
    for v in CFG.resources("aws_secretsmanager_secret_version"):
        assert "secret_string" not in v.body and "secret_binary" not in v.body, f"{v.address}: value would be stored in state"
        assert "secret_string_wo" in v.body


def test_sns_ecr_cloudtrail_encrypted():
    for t in CFG.resources("aws_sns_topic"):
        assert t.body.get("kms_master_key_id"), f"{t.address}: SNS topic not encrypted"
    for r in CFG.resources("aws_ecr_repository"):
        assert r.body["encryption_configuration"][0]["encryption_type"] == "KMS"
    for t in CFG.resources("aws_cloudtrail"):
        assert t.body.get("kms_key_id") == "${var.logs_kms_key_arn}"


def test_tls_everywhere():
    for tg in CFG.resources("aws_lb_target_group"):
        assert tg.body["protocol"] == "HTTPS", "ALB -> target traffic must be TLS"
    pg = CFG.resources("aws_db_parameter_group")[0]
    params = {p["name"]: p["value"] for p in pg.body["parameter"]}
    assert params["rds.force_ssl"] == "1"
    for policy in ("access_logs", "alb_logs", "cloudtrail_bucket"):
        doc = next(d for d in CFG.data("aws_iam_policy_document") if d.name == policy)
        sids = [s.get("sid") for s in doc.body["statement"]]
        assert "DenyInsecureTransport" in sids, f"{policy}: bucket must deny non-TLS requests"
