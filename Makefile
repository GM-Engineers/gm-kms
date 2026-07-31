# KMS Project Makefile
# Provides targets for security verification (DJCP Level 3 Phase B)

.PHONY: help sbom sbom-json sbom-xml build-reproducible verify-reproducible clean-sbom zap-baseline zap-api-scan zap-clean report-crypto report-compliance report-clean

CARGO = cargo
CYCLONEDX_FLAGS = --spec-version 1.5

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# ── SBOM Generation (VERIFY-061) ──────────────────────────────

sbom: sbom-json sbom-xml ## Generate SBOM in both JSON and XML formats

sbom-json: ## Generate CycloneDX SBOM in JSON format
	SOURCE_DATE_EPOCH=1 $(CARGO) cyclonedx \
		--format json \
		$(CYCLONEDX_FLAGS) \
		--override-filename kms-sbom.cdx
	@echo "SBOM generated: kms-sbom.cdx.json"

sbom-xml: ## Generate CycloneDX SBOM in XML format
	SOURCE_DATE_EPOCH=1 $(CARGO) cyclonedx \
		--format xml \
		$(CYCLONEDX_FLAGS) \
		--override-filename kms-sbom.cdx
	@echo "SBOM generated: kms-sbom.cdx.xml"

clean-sbom: ## Remove generated SBOM files
	rm -f kms-sbom.cdx.json kms-sbom.cdx.xml

# ── Build Reproducibility (VERIFY-062) ────────────────────────

# Set SOURCE_DATE_EPOCH for deterministic build timestamps.
# Uses --remap-path-prefix to strip build machine paths from debug info.
export SOURCE_DATE_EPOCH ?= 1
export RUSTFLAGS ?= --remap-path-prefix=$(shell pwd)=/build

build-reproducible: ## Build with reproducible settings
	$(CARGO) build --workspace --release --target-dir target/reproducible

verify-reproducible: build-reproducible ## Build twice and compare checksums
	$(CARGO) build --workspace --release --target-dir target/reproducible-2
	@echo "Comparing build artifacts..."
	@diff <(shasum -a 256 target/reproducible/release/kms) \
	      <(shasum -a 256 target/reproducible-2/release/kms) \
	      && echo "BUILD IS REPRODUCIBLE" \
	      || echo "WARNING: build differs - check SOURCE_DATE_EPOCH and RUSTFLAGS"
	@rm -rf target/reproducible target/reproducible-2

# ── Convenience ────────────────────────────────────────────────

check: ## Run full CI check (format, clippy, build, test)
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) build --workspace --release
	$(CARGO) test --workspace --release
	@echo "All checks passed"

# ── OWASP ZAP Security Scanning (VERIFY-135) ──────────────────

zap-baseline: ## Run OWASP ZAP baseline (passive) scan against KMS REST API
	@echo "Running ZAP baseline scan..."
	./tests/zap/run-zap-scan.sh baseline

zap-api-scan: ## Run OWASP ZAP active scan with OpenAPI import
	@echo "Running ZAP API scan (this may take 15-30 minutes)..."
	./tests/zap/run-zap-scan.sh api-scan

zap-clean: ## Remove ZAP scan reports
	rm -rf tests/zap/reports/*.html tests/zap/reports/*.json tests/zap/reports/*.md

# ── Compliance Reporting (VERIFY-121) ─────────────────────────

report-crypto: ## Generate crypto configuration report (JSON + HTML)
	$(CARGO) run -p kms-cli -- report crypto-config --output both

report-compliance: ## Generate DJCP Level 3 compliance self-assessment report (JSON + HTML)
	$(CARGO) run -p kms-cli -- report compliance --output both

report-clean: ## Remove generated report files
	rm -f crypto-config.json crypto-config.html compliance.json compliance.html
