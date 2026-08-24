#!/usr/bin/env bash
# Runs every security scanner, writes machine-readable reports to reports/,
# prints a summary and exits non-zero if ANY scanner reports a finding that
# breaches its gate. Used by `make security-scan` and by CI.
#
#   scripts/security-scan.sh [all|iac|secrets|code|deps|image|workflows]
#
# Gates (what fails the build):
#   checkov / tfsec / trivy config / tflint : any failed check (all severities)
#   gitleaks                                : any secret
#   semgrep                                 : any ERROR/WARNING finding
#   trivy fs (dependencies)                 : HIGH or CRITICAL vulnerability
#   trivy image                             : HIGH or CRITICAL with a fix available
#   actionlint                              : any workflow error
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/.tools/bin"
OUT="${ROOT}/reports"
IMAGE="${IMAGE:-sci-app:local}"
mkdir -p "${OUT}"
cd "${ROOT}"

declare -a RESULTS=()
FAILED=0

record() { # name exit-code
  if [[ "$2" -eq 0 ]]; then RESULTS+=("PASS  $1"); else RESULTS+=("FAIL  $1"); FAILED=1; fi
}

need() {
  [[ -x "${BIN}/$1" ]] || { echo "missing ${BIN}/$1 - run 'make tools'" >&2; exit 2; }
}

checkov_scan() {
  need checkov
  echo ">> checkov (terraform, dockerfile, github actions, secrets)"
  "${BIN}/checkov" --config-file security/checkov.yaml \
    -d terraform -d docker -d .github --skip-path '\.terraform' \
    -o cli -o json -o sarif --output-file-path console,"${OUT}/checkov.json","${OUT}/checkov.sarif" \
    >"${OUT}/checkov.txt" 2>&1
  local rc=$?
  tail -n 3 "${OUT}/checkov.txt"
  record "checkov" "${rc}"
}

tfsec_scan() {
  need tfsec
  echo ">> tfsec"
  "${BIN}/tfsec" terraform --no-color --no-module-downloads --exclude-path .terraform \
    --format json,sarif --out "${OUT}/tfsec" >/dev/null 2>&1
  "${BIN}/tfsec" terraform --no-color --no-module-downloads --exclude-path .terraform --concise-output >"${OUT}/tfsec.txt" 2>&1
  local rc=$?
  tail -n 2 "${OUT}/tfsec.txt"
  record "tfsec" "${rc}"
}

trivy_config_scan() {
  need trivy
  echo ">> trivy config (terraform + Dockerfile)"
  local rc=0 target
  for target in terraform docker; do
    "${BIN}/trivy" config --quiet --exit-code 1 --severity LOW,MEDIUM,HIGH,CRITICAL \
      --skip-dirs '**/.terraform' --format json --output "${OUT}/trivy-config-${target}.json" "${target}" || rc=1
  done
  "${BIN}/trivy" config --quiet --exit-code 0 --skip-dirs '**/.terraform' --format sarif --output "${OUT}/trivy-config.sarif" terraform
  record "trivy config" "${rc}"
}

tflint_scan() {
  need tflint
  echo ">> tflint (+ AWS ruleset)"
  export TFLINT_PLUGIN_DIR="${ROOT}/.tools/tflint-plugins"
  (cd terraform && "${BIN}/tflint" --init >/dev/null && "${BIN}/tflint" --recursive --format json >"${OUT}/tflint.json")
  record "tflint" "$?"
}

gitleaks_scan() {
  need gitleaks
  # .env holds locally generated secrets for docker compose and is allow-listed
  # for the working-tree scan; it must therefore never be tracked by git.
  if git rev-parse --git-dir >/dev/null 2>&1 && git ls-files --error-unmatch .env >/dev/null 2>&1; then
    echo "!! .env is tracked by git - remove it from the index and rotate its secrets" >&2
    record "gitleaks (.env tracked)" 1
  fi
  echo ">> gitleaks (working tree)"
  "${BIN}/gitleaks" dir . --config security/gitleaks.toml --redact --no-banner \
    --report-format sarif --report-path "${OUT}/gitleaks.sarif" --exit-code 1
  local rc=$?
  if git rev-parse --git-dir >/dev/null 2>&1 && git rev-parse HEAD >/dev/null 2>&1; then
    echo ">> gitleaks (git history)"
    "${BIN}/gitleaks" git . --config security/gitleaks.toml --redact --no-banner \
      --report-format json --report-path "${OUT}/gitleaks-history.json" --exit-code 1
    rc=$((rc | $?))
  fi
  record "gitleaks" "${rc}"
}

semgrep_scan() {
  need semgrep
  echo ">> semgrep (custom rules + community packs)"
  local configs=(--config security/semgrep)
  if [[ "${SEMGREP_OFFLINE:-0}" != "1" ]]; then
    configs+=(--config p/python --config p/flask --config p/secrets --config p/dockerfile --config p/github-actions)
  fi
  "${BIN}/semgrep" scan "${configs[@]}" --metrics=off --error --severity ERROR --severity WARNING \
    --exclude .tools --exclude .local --exclude reports --exclude tests \
    --json --output "${OUT}/semgrep.json" --sarif-output "${OUT}/semgrep.sarif" \
    app docker scripts .github >"${OUT}/semgrep.txt" 2>&1
  local rc=$?
  grep -E "Ran [0-9]+ rules|findings" "${OUT}/semgrep.txt" | tail -n 2
  record "semgrep" "${rc}"
}

deps_scan() {
  need trivy
  echo ">> trivy fs (Python dependency vulnerabilities)"
  "${BIN}/trivy" fs --quiet --scanners vuln --exit-code 1 --severity HIGH,CRITICAL \
    --format json --output "${OUT}/trivy-deps.json" app
  record "trivy deps" "$?"
}

image_scan() {
  need trivy
  if ! command -v docker >/dev/null 2>&1; then
    echo ">> docker not available: image scan skipped" && RESULTS+=("SKIP  trivy image (no docker)") && return
  fi
  if [[ "${SKIP_IMAGE_BUILD:-0}" != "1" ]]; then
    echo ">> building ${IMAGE}"
    docker build -q -f docker/Dockerfile -t "${IMAGE}" . >/dev/null || { record "docker build" 1; return; }
  fi
  echo ">> trivy image ${IMAGE}"
  "${BIN}/trivy" image --quiet --scanners vuln,secret,misconfig --ignore-unfixed --exit-code 1 \
    --severity HIGH,CRITICAL --format json --output "${OUT}/trivy-image.json" "${IMAGE}"
  local rc=$?
  "${BIN}/trivy" image --quiet --format cyclonedx --output "${OUT}/sbom-image.cdx.json" "${IMAGE}" || true
  "${BIN}/trivy" image --quiet --exit-code 0 --format sarif --output "${OUT}/trivy-image.sarif" "${IMAGE}" || true
  record "trivy image" "${rc}"
}

workflows_scan() {
  need actionlint
  echo ">> actionlint"
  "${BIN}/actionlint" -shellcheck= -no-color .github/workflows/*.yml >"${OUT}/actionlint.txt" 2>&1
  record "actionlint" "$?"
}

case "${1:-all}" in
  iac) checkov_scan; tfsec_scan; trivy_config_scan; tflint_scan ;;
  secrets) gitleaks_scan ;;
  code) semgrep_scan ;;
  deps) deps_scan ;;
  image) image_scan ;;
  workflows) workflows_scan ;;
  all)
    checkov_scan; tfsec_scan; trivy_config_scan; tflint_scan
    gitleaks_scan; semgrep_scan; deps_scan; workflows_scan; image_scan
    ;;
  *) echo "usage: $0 [all|iac|secrets|code|deps|image|workflows]" >&2; exit 2 ;;
esac

echo
echo "================ security scan summary ================"
printf '%s\n' "${RESULTS[@]}"
echo "reports: ${OUT}"
echo "======================================================="
exit "${FAILED}"
