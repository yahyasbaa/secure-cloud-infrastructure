#!/usr/bin/env bash
# Removes the Terraform state backend created by `make bootstrap`.
# Run ONLY after every environment has been destroyed: this deletes all state
# history. The state bucket is protected with prevent_destroy, so both
# buckets are emptied (all versions) and deleted here explicitly and removed
# from the bootstrap state; `terraform destroy` then deletes the remaining
# resources (the KMS key enters its 30-day pending-deletion window).
#   CONFIRM=destroy-state scripts/destroy-bootstrap.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF="${ROOT}/.tools/bin/terraform"
PY="${ROOT}/.tools/venvs/dev/bin/python"
export TF_DATA_DIR="${ROOT}/.local/tfdata-bootstrap"
[[ "${CONFIRM:-}" == "destroy-state" ]] || { echo "Refusing: set CONFIRM=destroy-state" >&2; exit 1; }
tf() { "${TF}" -chdir="${ROOT}/terraform/bootstrap" "$@"; }

tf init -input=false -no-color >/dev/null
state_bucket="$(tf output -raw state_bucket)"
logs_bucket="$(tf output -raw state_logs_bucket)"

"${PY}" - "${state_bucket}" "${logs_bucket}" <<'PY'
import sys
import time

import boto3

s3 = boto3.client("s3")


def empty(bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objects), 1000):
            resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects[i : i + 1000], "Quiet": True})
            if resp.get("Errors"):
                sys.exit(f"cannot delete objects in {bucket}: {resp['Errors'][0]}")


# State bucket first (it is the source of access-log deliveries), then the
# log bucket, retrying because S3 delivers access logs with a delay. Bucket
# policies are removed first: they are about to be deleted anyway and their
# deny statements would otherwise apply to the cleanup itself.
for bucket in sys.argv[1:]:
    s3.delete_bucket_policy(Bucket=bucket)
    for attempt in range(40):
        empty(bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            print(f"deleted {bucket}")
            break
        except s3.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketNotEmpty":
                raise
            time.sleep(15)
    else:
        sys.exit(f"could not empty {bucket}; re-run the script later")
PY

# The buckets and their sub-resources are gone; forget them so
# prevent_destroy does not block destroying the remaining resources.
for suffix in state state_logs; do
  for type in aws_s3_bucket aws_s3_bucket_ownership_controls aws_s3_bucket_public_access_block aws_s3_bucket_versioning \
    aws_s3_bucket_server_side_encryption_configuration aws_s3_bucket_logging aws_s3_bucket_lifecycle_configuration aws_s3_bucket_policy; do
    tf state rm -no-color -backup=- "${type}.${suffix}" >/dev/null 2>&1 || true
  done
done
tf destroy -input=false -auto-approve -no-color | tail -n 1
