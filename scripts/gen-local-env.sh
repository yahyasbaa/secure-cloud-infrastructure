#!/usr/bin/env bash
# Creates .env for local docker compose runs with freshly generated random
# secrets. Never overwrites an existing .env. The file is created mode 0600.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/.env"
if [[ -f "${ENV_FILE}" ]]; then
  echo ".env already exists - leaving it untouched"
  exit 0
fi
umask 077
python3 - "${ROOT}/.env.example" "${ENV_FILE}" <<'PY'
import re, secrets, sys
src, dst = sys.argv[1:]
out = []
for line in open(src):
    m = re.match(r"^([A-Z_]+)=<generate-(\d+)-random-chars>$", line.strip())
    if m:
        out.append(f"{m.group(1)}={secrets.token_urlsafe(int(m.group(2)))[: int(m.group(2))]}\n")
    else:
        out.append(line)
open(dst, "w").write("".join(out))
PY
echo "created ${ENV_FILE} (mode 600) with random secrets"
