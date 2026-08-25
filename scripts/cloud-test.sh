#!/usr/bin/env bash
# Runs the live posture tests and an HTTPS smoke test against a REAL AWS
# deployment (the same tests the local mode runs against moto).
#   scripts/cloud-test.sh [env]          (default: dev)
# Requires read access to the account (e.g. the security-audit role) and to
# the Terraform state for the secret-in-state check.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV="${1:-dev}"
TF="${ROOT}/.tools/bin/terraform"
export SCI_TARGET=aws
export SCI_NAME="sci-${ENV}"
export TF_DATA_DIR="${ROOT}/.local/tfdata-${ENV}"
mkdir -p "${ROOT}/reports"

# State contains resource metadata (and the dev self-signed TLS key): keep it
# in a private temp file that is always removed.
umask 077
state="$(mktemp)"
trap 'rm -f "${state}"' EXIT
"${TF}" -chdir="${ROOT}/terraform" show -json >"${state}"
export SCI_STATE_JSON="${state}"

"${ROOT}/.tools/bin/pytest" -q "${ROOT}/tests/security/live" --junitxml="${ROOT}/reports/junit-live-aws.xml"

alb="$("${TF}" -chdir="${ROOT}/terraform" output -raw alb_dns_name)"
echo ">> HTTPS checks against https://${alb}"
code="$(curl -sk -o /dev/null -w '%{http_code}' "https://${alb}/health")"
[[ "${code}" == "200" ]] || { echo "health check returned ${code}" >&2; exit 1; }
code="$(curl -sk -o /dev/null -w '%{http_code}' "https://${alb}/api/notes")"
[[ "${code}" == "401" ]] || { echo "unauthenticated API returned ${code}, expected 401" >&2; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${alb}/health" || true)"
[[ "${code}" == "000" ]] || { echo "plaintext HTTP answered (${code}); expected no listener" >&2; exit 1; }
echo ">> cloud posture + HTTPS checks passed"
