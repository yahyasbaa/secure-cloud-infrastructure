#!/usr/bin/env bash
# Builds, scans, pushes and rolls out the application image.
#   scripts/deploy-image.sh <name-prefix> <image-tag>     e.g. sci-dev 3f2c1ab
# Requires AWS credentials for the deployment role (CI obtains them via OIDC).
# Gates: the image must pass the Trivy scan before it is pushed, and ECR's own
# scan-on-push must report no CRITICAL findings before it is rolled out.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:?usage: $0 <name-prefix> <image-tag>}"
TAG="${2:?usage: $0 <name-prefix> <image-tag>}"
TRIVY="${ROOT}/.tools/bin/trivy"
REGION="${AWS_REGION:?AWS_REGION must be set}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REPO="${NAME}-app"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
IMAGE="${REGISTRY}/${REPO}:${TAG}"

echo ">> build ${IMAGE}"
docker build -f "${ROOT}/docker/Dockerfile" -t "${IMAGE}" "${ROOT}"

echo ">> pre-push vulnerability gate"
"${TRIVY}" image --quiet --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 "${IMAGE}"

echo ">> push"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
docker push "${IMAGE}"
docker logout "${REGISTRY}"

echo ">> ECR scan-on-push gate"
aws ecr wait image-scan-complete --repository-name "${REPO}" --image-id "imageTag=${TAG}"
critical="$(aws ecr describe-image-scan-findings --repository-name "${REPO}" --image-id "imageTag=${TAG}" \
  --query 'imageScanFindings.findingSeverityCounts.CRITICAL' --output text)"
if [[ "${critical}" != "None" && "${critical}" != "0" ]]; then
  echo "ECR reports ${critical} CRITICAL findings - not deploying" >&2
  exit 1
fi

echo ">> publish tag and roll out"
aws ssm put-parameter --name "/${NAME}/app/image-tag" --value "${TAG}" --type String --overwrite >/dev/null
refresh_id="$(aws autoscaling start-instance-refresh --auto-scaling-group-name "${REPO}" \
  --preferences '{"MinHealthyPercentage":50,"InstanceWarmup":120}' --query InstanceRefreshId --output text)"
for _ in $(seq 1 90); do
  status="$(aws autoscaling describe-instance-refreshes --auto-scaling-group-name "${REPO}" \
    --instance-refresh-ids "${refresh_id}" --query 'InstanceRefreshes[0].Status' --output text)"
  echo "   instance refresh: ${status}"
  case "${status}" in
    Successful) echo ">> deployed ${TAG}"; exit 0 ;;
    Failed | Cancelled | RollbackSuccessful | RollbackFailed) echo "rollout ${status}" >&2; exit 1 ;;
  esac
  sleep 20
done
echo "timed out waiting for instance refresh" >&2
exit 1
