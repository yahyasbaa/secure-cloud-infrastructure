#!/usr/bin/env bash
# HTTPS smoke test against a running instance of the application.
#   scripts/smoke-test.sh [base-url]      (default https://127.0.0.1:8443)
# The API token is read from .env (local) or from the APP_API_TOKEN
# environment variable; it is never printed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${1:-https://127.0.0.1:8443}"
TOKEN="${APP_API_TOKEN:-$(grep -E '^APP_API_TOKEN=' "${ROOT}/.env" | cut -d= -f2-)}"
# -k: the local/dev endpoint uses a self-signed certificate.
CURL=(curl -sk --max-time 10 -o /dev/null -w '%{http_code}')
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then echo "PASS  $1 ($3)"; else echo "FAIL  $1 (expected $2, got $3)"; fail=1; fi
}

for _ in $(seq 1 60); do
  [[ "$("${CURL[@]}" "${BASE}/health" || true)" == "200" ]] && break
  sleep 1
done

check "GET /health" 200 "$("${CURL[@]}" "${BASE}/health")"
check "GET /ready (database reachable)" 200 "$("${CURL[@]}" "${BASE}/ready")"
check "API without token is rejected" 401 "$("${CURL[@]}" "${BASE}/api/notes")"
check "API with wrong token is rejected" 401 "$("${CURL[@]}" -H 'Authorization: Bearer wrong-token' "${BASE}/api/notes")"
check "create note with token" 201 "$("${CURL[@]}" -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d '{"title":"smoke","body":"test"}' "${BASE}/api/notes")"
check "list notes with token" 200 "$("${CURL[@]}" -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/notes")"
check "invalid input rejected" 400 "$("${CURL[@]}" -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d '{"title":""}' "${BASE}/api/notes")"
headers="$(curl -skI --max-time 10 "${BASE}/health")"
for h in strict-transport-security x-content-type-options content-security-policy x-frame-options; do
  if grep -qi "^${h}:" <<<"${headers}"; then echo "PASS  header ${h}"; else echo "FAIL  header ${h} missing"; fail=1; fi
done
tls="$(curl -sk --max-time 10 --tlsv1.1 --tls-max 1.1 -o /dev/null -w '%{http_code}' "${BASE}/health" || true)"
check "TLS 1.1 refused" 000 "${tls}"
exit "${fail}"
