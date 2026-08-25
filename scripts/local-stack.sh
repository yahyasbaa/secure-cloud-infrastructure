#!/usr/bin/env bash
# LOCAL validation mode: deploys the complete Terraform stack into a moto AWS
# emulator on the loopback interface, runs the live posture tests against it,
# then destroys it. No AWS account or credentials are involved.
#
#   scripts/local-stack.sh all       # up -> init -> plan -> apply -> test -> destroy -> down
#   scripts/local-stack.sh up|init|plan|apply|test|destroy|down
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${ROOT}/.tools"
STATE_DIR="${ROOT}/.local"
REPORTS="${ROOT}/reports"
TF="${TOOLS}/bin/terraform"
PY="${TOOLS}/venvs/dev/bin/python"
MOTO_PORT="${MOTO_PORT:-4567}"
SHIM_PORT="${SHIM_PORT:-4566}"
mkdir -p "${STATE_DIR}" "${REPORTS}"

# Dummy credentials: moto accepts anything. They are not secrets.
export AWS_ACCESS_KEY_ID="local-moto"
export AWS_SECRET_ACCESS_KEY="local-moto"
export AWS_REGION="us-east-1"
export AWS_DEFAULT_REGION="us-east-1"
# "localhost" (not 127.0.0.1) so S3 Control's <account-id>.<host> prefix
# resolves (RFC 6761: *.localhost is loopback).
export AWS_ENDPOINT_URL="http://localhost:${SHIM_PORT}"
export TF_DATA_DIR="${STATE_DIR}/tfdata"
export TF_IN_AUTOMATION=1
export TF_INPUT=0
export SCI_TARGET=local
export SCI_NAME=sci-local

tf() { "${TF}" -chdir="${ROOT}/terraform" "$@"; }

up() {
  if [[ -f "${STATE_DIR}/moto.pid" ]] && kill -0 "$(cat "${STATE_DIR}/moto.pid")" 2>/dev/null; then
    echo ">> moto already running"
  else
    echo ">> starting moto on 127.0.0.1:${MOTO_PORT} (+ CBOR shim on ${SHIM_PORT})"
    "${TOOLS}/bin/moto_server" -H 127.0.0.1 -p "${MOTO_PORT}" >"${STATE_DIR}/moto.log" 2>&1 &
    echo $! >"${STATE_DIR}/moto.pid"
    "${PY}" "${ROOT}/scripts/moto_cbor_shim.py" "${SHIM_PORT}" "${MOTO_PORT}" >"${STATE_DIR}/shim.log" 2>&1 &
    echo $! >"${STATE_DIR}/shim.pid"
  fi
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:${SHIM_PORT}/moto-api/" >/dev/null && break
    sleep 0.5
  done
  curl -sf "http://127.0.0.1:${SHIM_PORT}/moto-api/" >/dev/null || { echo "moto did not start" >&2; exit 1; }
  "${PY}" - <<'PY'
import boto3
s3 = boto3.client("s3")
existing = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
if "sci-local-tfstate" not in existing:
    s3.create_bucket(Bucket="sci-local-tfstate")
    s3.put_bucket_versioning(Bucket="sci-local-tfstate", VersioningConfiguration={"Status": "Enabled"})
print(">> state bucket ready")
PY
}

init() {
  tf init -no-color -reconfigure -backend-config=environments/local/backend.hcl >/dev/null
  echo ">> terraform init (S3 backend in moto) ok"
}

plan() {
  tf plan -no-color -var-file=environments/local/terraform.tfvars -out="${STATE_DIR}/local.tfplan" >"${STATE_DIR}/plan.log"
  tf show -json "${STATE_DIR}/local.tfplan" >"${REPORTS}/local-plan.json"
  grep -E "^Plan:" "${STATE_DIR}/plan.log"
}

apply() {
  tf apply -no-color -auto-approve "${STATE_DIR}/local.tfplan" | tail -n 3
  tf show -json >"${REPORTS}/local-state.json"
  tf output -json >"${REPORTS}/local-outputs.json"
}

test_live() {
  "${TOOLS}/bin/pytest" -q "${ROOT}/tests/security/live" --junitxml="${REPORTS}/junit-live-local.xml"
}

destroy() {
  tf destroy -no-color -auto-approve -var-file=environments/local/terraform.tfvars | tail -n 1
}

down() {
  for svc in shim moto; do
    if [[ -f "${STATE_DIR}/${svc}.pid" ]]; then
      kill "$(cat "${STATE_DIR}/${svc}.pid")" 2>/dev/null || true
      rm -f "${STATE_DIR}/${svc}.pid"
    fi
  done
  echo ">> moto stopped"
}

case "${1:-all}" in
  up) up ;;
  init) init ;;
  plan) plan ;;
  apply) apply ;;
  test) test_live ;;
  destroy) destroy ;;
  down) down ;;
  all)
    trap down EXIT
    up
    init
    plan
    apply
    test_live
    destroy
    ;;
  *) echo "usage: $0 {all|up|init|plan|apply|test|destroy|down}" >&2; exit 2 ;;
esac
