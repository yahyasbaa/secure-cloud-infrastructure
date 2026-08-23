#!/usr/bin/env bash
# Installs every tool the project needs into ./.tools (no sudo, no global changes).
#
#   scripts/install-tools.sh                 # everything
#   scripts/install-tools.sh terraform dev   # only the named components
#   components: terraform tfsec trivy gitleaks tflint actionlint dev checkov semgrep
#
# Supply-chain controls:
#   * every binary is pinned to an exact version
#   * every download is verified against a SHA256 embedded in this file
#     (taken from the vendor's published checksum file at pin time), so a
#     tampered or re-tagged release fails closed
#   * Python scanners live in isolated virtualenvs with pinned versions
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${ROOT}/.tools"
BIN="${TOOLS}/bin"
mkdir -p "${BIN}" "${TOOLS}/dl" "${TOOLS}/venvs"

TERRAFORM_VERSION="1.16.5"
TFSEC_VERSION="1.28.14"
TRIVY_VERSION="0.75.0"
GITLEAKS_VERSION="8.30.1"
TFLINT_VERSION="0.64.0"
ACTIONLINT_VERSION="1.7.12"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "${arch}" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;;
esac
case "${os}" in
  linux | darwin) ;;
  *) echo "unsupported OS: ${os}" >&2; exit 1 ;;
esac
plat="${os}_${arch}"

# sha256 lookup table: "<tool>:<platform>" -> hash
sha() {
  case "$1" in
    terraform:linux_amd64) echo 2bc2fcfff033265c9e02ca0351f01794eb122f62a9b2a49a3294b9e49eaab5e4 ;;
    terraform:linux_arm64) echo 61a50b00485ee4810cf20581ef080fc54d34d666e175c58d9a10501c65c1ccde ;;
    terraform:darwin_amd64) echo 9809158e481cf2d3a8433e59179f397b8edb5172397711bd98f6bb32edcaf53b ;;
    terraform:darwin_arm64) echo ecdef65e24193d627f27c39baeda31295f08c938d8a3d4764f442fb916d4b7dc ;;
    tfsec:linux_amd64) echo 329ae7f67f2f1813ebe08de498719ea7003c75d3ca24bb0b038369062508008e ;;
    tfsec:linux_arm64) echo 13dcbd3602027be49ce6cab7e1c24b0a8e833f0143fe327b0a13b87686541ce0 ;;
    tfsec:darwin_amd64) echo 0aeef31f83d6f44ba9ba5b6cbb954304c772dee73ac704e38896940f94af887a ;;
    tfsec:darwin_arm64) echo f39d59a3f9be4eeb3d965657653ad62243103a3d921ce52ca8f907cff45896f5 ;;
    trivy:linux_amd64) echo c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f ;;
    trivy:linux_arm64) echo a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3 ;;
    trivy:darwin_amd64) echo 291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4 ;;
    trivy:darwin_arm64) echo 4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568 ;;
    gitleaks:linux_amd64) echo 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
    gitleaks:linux_arm64) echo e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
    gitleaks:darwin_amd64) echo dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
    gitleaks:darwin_arm64) echo b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
    tflint:linux_amd64) echo cca9d13e2e1d7a2c627af60ff899a3c9b74212899416aeb96ec764d2ef954537 ;;
    tflint:linux_arm64) echo 560da89aacf59389d4eb029730dd5b109b7288096c32f2726a0d9e783a5ea8eb ;;
    tflint:darwin_amd64) echo 0f3a9fd17526014646a2dfc3f9122f7b4161abe3d6b0f0f03f9014483ddf4d19 ;;
    tflint:darwin_arm64) echo 2496e9cb3d24992d553b45e7c87a0fdc9449ca975233876247a9bfeda857e6c0 ;;
    actionlint:linux_amd64) echo 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 ;;
    actionlint:linux_arm64) echo 325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6 ;;
    actionlint:darwin_amd64) echo 5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644 ;;
    actionlint:darwin_arm64) echo aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f ;;
    *) echo "no pinned checksum for $1" >&2; return 1 ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# fetch <tool> <url> -> path of verified archive
fetch() {
  local tool="$1" url="$2" out expected actual
  out="${TOOLS}/dl/$(basename "${url}")"
  expected="$(sha "${tool}:${plat}")"
  if [[ ! -f "${out}" ]] || [[ "$(sha256_of "${out}")" != "${expected}" ]]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "${out}" "${url}"
  fi
  actual="$(sha256_of "${out}")"
  if [[ "${actual}" != "${expected}" ]]; then
    rm -f "${out}"
    echo "CHECKSUM MISMATCH for ${tool}: expected ${expected} got ${actual}" >&2
    exit 1
  fi
  echo "${out}"
}


install_zip() { # tool url binary
  local f; f="$(fetch "$1" "$2")"
  python3 - "$f" "${BIN}" "$3" <<'PY'
import sys, zipfile, os
zf, dest, name = sys.argv[1:]
with zipfile.ZipFile(zf) as z:
    with z.open(name) as src, open(os.path.join(dest, name), "wb") as dst:
        dst.write(src.read())
os.chmod(os.path.join(dest, name), 0o755)
PY
}

install_tgz() { # tool url binary
  local f; f="$(fetch "$1" "$2")"
  tar -xzf "$f" -C "${BIN}" "$3"
  chmod 0755 "${BIN}/$3"
}

echo ">> platform ${plat}"

COMPONENTS=("$@")
want() { [[ ${#COMPONENTS[@]} -eq 0 ]] || [[ " ${COMPONENTS[*]} " == *" $1 "* ]]; }

if want terraform; then
  echo ">> terraform ${TERRAFORM_VERSION}"
  install_zip terraform "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_${plat}.zip" terraform
fi

if want tfsec; then
  echo ">> tfsec ${TFSEC_VERSION}"
  install_tgz tfsec "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec_${TFSEC_VERSION}_${plat}.tar.gz" tfsec
fi

if want trivy; then
  echo ">> trivy ${TRIVY_VERSION}"
  case "${plat}" in
    linux_amd64) tplat="Linux-64bit" ;; linux_arm64) tplat="Linux-ARM64" ;;
    darwin_amd64) tplat="macOS-64bit" ;; darwin_arm64) tplat="macOS-ARM64" ;;
  esac
  install_tgz trivy "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${tplat}.tar.gz" trivy
fi

if want gitleaks; then
  echo ">> gitleaks ${GITLEAKS_VERSION}"
  gplat="${plat/amd64/x64}"
  install_tgz gitleaks "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${gplat}.tar.gz" gitleaks
fi

if want tflint; then
  echo ">> tflint ${TFLINT_VERSION}"
  install_zip tflint "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_${plat}.zip" tflint
fi

if want actionlint; then
  echo ">> actionlint ${ACTIONLINT_VERSION}"
  install_tgz actionlint "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_${plat}.tar.gz" actionlint
fi

# Python tooling: one venv per tool family so their dependency trees never conflict.
mkvenv() { # name requirements-file
  local v="${TOOLS}/venvs/$1"
  [[ -x "${v}/bin/python" ]] || python3 -m venv "${v}"
  "${v}/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade pip
  local extra=()
  grep -q -- '--hash=' "$2" && extra=(--require-hashes)
  "${v}/bin/python" -m pip install --quiet --disable-pip-version-check "${extra[@]}" -r "$2"
}

# Expose venv console scripts through wrappers that run them with the venv's
# interpreter, so the tools work even when the checkout path contains spaces.
wrap() { # name venv script
  cat > "${BIN}/$1" <<EOF
#!/usr/bin/env bash
d="\$(cd "\$(dirname "\$0")/../venvs/$2/bin" && pwd)"
exec "\$d/python" "\$d/$3" "\$@"
EOF
  chmod 0755 "${BIN}/$1"
}

if want dev; then
  echo ">> python dev/test venv"
  mkvenv dev "${ROOT}/app/requirements.txt"
  "${TOOLS}/venvs/dev/bin/python" -m pip install --quiet --disable-pip-version-check -r "${ROOT}/requirements-dev.txt"
  wrap pytest dev pytest
  wrap moto_server dev moto_server
fi
if want checkov; then
  echo ">> checkov venv"
  mkvenv checkov "${ROOT}/security/requirements-checkov.txt"
  wrap checkov checkov checkov
fi
if want semgrep; then
  echo ">> semgrep venv"
  mkvenv semgrep "${ROOT}/security/requirements-semgrep.txt"
  wrap semgrep semgrep semgrep
fi

echo ">> installed tool versions"
for t in terraform tfsec trivy gitleaks tflint actionlint checkov semgrep pytest; do
  [[ -x "${BIN}/${t}" ]] || continue
  case "${t}" in
    terraform) "${BIN}/terraform" version | sed -n 1p ;;
    gitleaks) echo "gitleaks $("${BIN}/gitleaks" version)" ;;
    tfsec) echo "tfsec $("${BIN}/tfsec" --version)" ;;
    *) echo "${t} $("${BIN}/${t}" --version 2>&1 | sed -n 1p)" ;;
  esac
done
