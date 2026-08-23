# Secure Cloud Infrastructure - task runner.
# `make help` lists every target. All tools are pinned and installed into
# ./.tools by `make tools`; nothing is installed globally.

SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# Paths are quoted everywhere because the checkout directory may contain spaces.
ROOT     := $(CURDIR)
BIN      := "$(ROOT)/.tools/bin"
TF       := "$(ROOT)/.tools/bin/terraform"
PYTEST   := "$(ROOT)/.tools/bin/pytest"
ENV      ?= dev
IMAGE    ?= sci-app:local
TAG      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo manual)
COMPOSE  := docker compose -f docker/docker-compose.yml --env-file .env
TFVARS   := environments/$(ENV)/terraform.tfvars
ENV_DATA := "$(ROOT)/.local/tfdata-$(ENV)"

# Disposable-environment teardown overrides (see `make destroy`).
TEARDOWN_VARS := -var db_deletion_protection=false -var alb_deletion_protection=false \
                 -var db_skip_final_snapshot=true -var allow_force_destroy=true

export TF_IN_AUTOMATION := 1

.PHONY: help tools fmt fmt-check tf-validate tf-test tflint unit-test security-test test \
        security-scan iac-scan secret-scan sast deps-scan image-scan workflow-lint \
        docker-build local-env run-local stop-local smoke local-stack validate all \
        bootstrap backend-config destroy-bootstrap init plan apply destroy cloud-test deploy-image rotate-token lock clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

reports:
	@mkdir -p reports

##@ Setup
tools: ## Install pinned, checksum-verified tools into ./.tools
	scripts/install-tools.sh

##@ Terraform quality
fmt: ## Format all Terraform
	$(TF) fmt -recursive terraform

fmt-check: ## terraform fmt -check (fails on unformatted code)
	$(TF) fmt -check -recursive -diff terraform

tf-validate: ## terraform validate (root stack + bootstrap), no credentials needed
	@for dir in terraform terraform/bootstrap; do \
	  echo ">> validate $$dir"; \
	  TF_DATA_DIR="$(ROOT)/.local/tfdata-validate-$$(basename $$dir)" $(TF) -chdir=$$dir init -backend=false -input=false -no-color >/dev/null; \
	  TF_DATA_DIR="$(ROOT)/.local/tfdata-validate-$$(basename $$dir)" $(TF) -chdir=$$dir validate -no-color; \
	done

tf-test: ## terraform test: module security assertions with a mocked AWS provider (offline)
	TF_DATA_DIR="$(ROOT)/.local/tfdata-test" $(TF) -chdir=terraform init -backend=false -input=false -no-color >/dev/null
	TF_DATA_DIR="$(ROOT)/.local/tfdata-test" $(TF) -chdir=terraform test -no-color

tflint: ## tflint with the AWS ruleset
	cd terraform && TFLINT_PLUGIN_DIR="$(ROOT)/.tools/tflint-plugins" $(BIN)/tflint --init >/dev/null && \
	  TFLINT_PLUGIN_DIR="$(ROOT)/.tools/tflint-plugins" $(BIN)/tflint --recursive --format compact

##@ Tests
unit-test: reports ## Application unit tests
	$(PYTEST) -q tests/unit --junitxml=reports/junit-unit.xml

security-test: reports tf-test ## Security configuration tests (pytest static checks + terraform test)
	$(PYTEST) -q tests/security --junitxml=reports/junit-security.xml

test: unit-test security-test ## All offline tests

##@ Security scanning (reports in ./reports)
security-scan: ## All scanners: checkov, tfsec, trivy, tflint, gitleaks, semgrep, actionlint, image scan
	scripts/security-scan.sh all

iac-scan: ## checkov + tfsec + trivy config + tflint
	scripts/security-scan.sh iac

secret-scan: ## gitleaks (working tree and git history)
	scripts/security-scan.sh secrets

sast: ## semgrep
	scripts/security-scan.sh code

deps-scan: ## trivy dependency vulnerability scan
	scripts/security-scan.sh deps

image-scan: docker-build ## Build the image, then trivy vulnerability/secret/misconfig scan + SBOM
	IMAGE=$(IMAGE) scripts/security-scan.sh image

workflow-lint: ## actionlint on GitHub workflows
	scripts/security-scan.sh workflows

##@ Containers / local runtime
docker-build: ## Build the application image
	docker build -f docker/Dockerfile -t $(IMAGE) .

local-env: ## Generate .env with random local secrets (never overwrites)
	scripts/gen-local-env.sh

run-local: local-env ## Run app + PostgreSQL locally (https://127.0.0.1:8443)
	$(COMPOSE) up -d --build

stop-local: ## Stop the local app and delete its throw-away database
	$(COMPOSE) down -v

smoke: local-env ## Build + run locally, execute HTTPS smoke tests, tear down
	$(COMPOSE) up -d --build --wait
	scripts/smoke-test.sh || { $(COMPOSE) logs app | tail -n 50; $(COMPOSE) down -v; exit 1; }
	$(COMPOSE) down -v

local-stack: ## LOCAL MODE: deploy the full stack to a moto AWS emulator, run posture tests, destroy
	scripts/local-stack.sh all

##@ Pipelines
validate: fmt-check tf-validate tflint test security-scan ## fmt, validate, lint, unit + config tests, all scanners incl. secrets

all: validate local-stack smoke ## Complete pipeline: validate + local cloud deployment + container smoke test

##@ AWS (real account; requires credentials)
bootstrap: ## One-time: create the encrypted, versioned, locked state bucket
	TF_DATA_DIR="$(ROOT)/.local/tfdata-bootstrap" $(TF) -chdir=terraform/bootstrap init -input=false
	TF_DATA_DIR="$(ROOT)/.local/tfdata-bootstrap" $(TF) -chdir=terraform/bootstrap apply
	$(MAKE) backend-config ENV=$(ENV)

backend-config: ## Write terraform/environments/$(ENV)/backend.hcl from the bootstrap outputs
	@mkdir -p terraform/environments/$(ENV); umask 077; TF_DATA_DIR="$(ROOT)/.local/tfdata-bootstrap" $(TF) -chdir=terraform/bootstrap output -raw backend_config \
	  | sed 's#key          = "dev/terraform.tfstate"#key          = "$(ENV)/terraform.tfstate"#' > terraform/environments/$(ENV)/backend.hcl
	@echo "wrote terraform/environments/$(ENV)/backend.hcl"

destroy-bootstrap: ## DANGER: delete the state bucket and key (only after every ENV is destroyed; CONFIRM=destroy-state)
	CONFIRM=$(CONFIRM) scripts/destroy-bootstrap.sh

init: ## terraform init for ENV (default dev) against its S3 backend
	TF_DATA_DIR=$(ENV_DATA) $(TF) -chdir=terraform init -reconfigure -input=false -backend-config=environments/$(ENV)/backend.hcl

plan: ## terraform plan for ENV, saved to .local/$(ENV).tfplan
	TF_DATA_DIR=$(ENV_DATA) $(TF) -chdir=terraform plan -input=false -var-file=$(TFVARS) -out="$(ROOT)/.local/$(ENV).tfplan"

apply: ## Apply the saved plan for ENV
	TF_DATA_DIR=$(ENV_DATA) $(TF) -chdir=terraform apply -input=false "$(ROOT)/.local/$(ENV).tfplan"

destroy: ## Tear ENV down completely (requires CONFIRM=<env>)
	@[[ "$(CONFIRM)" == "$(ENV)" ]] || { echo "Refusing: run 'make destroy ENV=$(ENV) CONFIRM=$(ENV)'"; exit 1; }
	@echo ">> phase 1: lift deletion protection / retention guards"
	TF_DATA_DIR=$(ENV_DATA) $(TF) -chdir=terraform apply -input=false -auto-approve -var-file=$(TFVARS) $(TEARDOWN_VARS)
	@echo ">> phase 2: destroy"
	TF_DATA_DIR=$(ENV_DATA) $(TF) -chdir=terraform destroy -input=false -auto-approve -var-file=$(TFVARS) $(TEARDOWN_VARS)

cloud-test: ## Live posture tests + HTTPS checks against the deployed ENV
	scripts/cloud-test.sh $(ENV)

deploy-image: ## Build, scan, push and roll out the image to ENV (TAG=<tag>)
	scripts/deploy-image.sh sci-$(ENV) $(TAG)

rotate-token: ## Rotate the application API token in ENV
	scripts/rotate-app-token.sh sci-$(ENV)

##@ Maintenance
lock: ## Re-lock Python (hashes) and Terraform provider dependencies
	python3 -m venv .local/piptools && .local/piptools/bin/pip install -q pip-tools==7.6.1
	cd app && ../.local/piptools/bin/pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url -o requirements.txt requirements.in
	for dir in terraform terraform/bootstrap; do \
	  TF_DATA_DIR="$(ROOT)/.local/tfdata-validate-$$(basename $$dir)" $(TF) -chdir=$$dir providers lock \
	    -platform=linux_amd64 -platform=linux_arm64 -platform=darwin_amd64 -platform=darwin_arm64; \
	done

clean: ## Remove generated reports and local caches (keeps .tools)
	rm -rf reports .local .pytest_cache
	find . -name __pycache__ -type d -prune -not -path './.tools/*' -exec rm -rf {} +
