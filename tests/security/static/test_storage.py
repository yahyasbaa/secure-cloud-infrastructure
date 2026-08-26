"""S3 exposure tests (static)."""

from __future__ import annotations

from .hcl import load

CFG = load()


def _bucket_name(ref: str) -> str:
    return ref.split(".")[1]


def test_every_bucket_blocks_public_access():
    blocks = {_bucket_name(p.body["bucket"]): p.body for p in CFG.resources("aws_s3_bucket_public_access_block")}
    for bucket in CFG.resources("aws_s3_bucket"):
        pab = blocks.get(bucket.name)
        assert pab, f"{bucket.address}: no public access block"
        for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
            assert pab[flag] is True, f"{bucket.address}: {flag} not enabled"


def test_acls_disabled_and_versioned():
    owners = {_bucket_name(o.body["bucket"]): o.body for o in CFG.resources("aws_s3_bucket_ownership_controls")}
    versions = {_bucket_name(v.body["bucket"]): v.body for v in CFG.resources("aws_s3_bucket_versioning")}
    for bucket in CFG.resources("aws_s3_bucket"):
        assert owners[bucket.name]["rule"][0]["object_ownership"] == "BucketOwnerEnforced"
        assert versions[bucket.name]["versioning_configuration"][0]["status"] == "Enabled"


def test_no_public_acl_or_website():
    assert not CFG.resources("aws_s3_bucket_acl"), "ACLs must not be used (BucketOwnerEnforced)"
    assert not CFG.resources("aws_s3_bucket_website_configuration")


def test_bucket_policies_do_not_grant_public_access():
    for doc in CFG.data("aws_iam_policy_document"):
        for stmt in doc.body.get("statement", []):
            if stmt.get("effect", "Allow") != "Allow":
                continue
            for principal in stmt.get("principals", []):
                if "*" in principal.get("identifiers", []):
                    conds = {c["variable"] for c in stmt.get("condition", [])}
                    assert "aws:PrincipalAccount" in conds, f"{doc.address}: Allow to '*' without account restriction"


def test_log_buckets_not_force_destroyed_by_default():
    for bucket in CFG.resources("aws_s3_bucket"):
        # absent (= false) or driven by the explicit teardown switch only
        assert bucket.body.get("force_destroy", False) in (False, "${var.force_destroy_buckets}"), bucket.address
