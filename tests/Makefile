SHELL := /bin/bash
TESTS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PARALLEL_JOBS := $(shell echo $$(( $$(nproc) * 2 )) | awk '{ print ($$1 < 1) ? 1 : $$1 }')

.PHONY: test test-serial test-centos6 test-centos7 test-rocky8 test-rocky9 test-rocky10 \
        test-ubuntu2004 test-ubuntu2404 test-yara-x \
        test-modern test-legacy \
        test-modern-parallel test-legacy-parallel \
        test-all test-all-parallel help

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-26s %s\n", $$1, $$2}'

# Default: Debian 12, parallel within-OS
test: ## Run tests on Debian 12 (default, parallel)
	$(TESTS_DIR)/run-tests.sh --parallel

# Sequential: old behavior (single container, all files)
test-serial: ## Run tests on Debian 12 (sequential, single container)
	$(TESTS_DIR)/run-tests.sh --os debian12

# Individual OS targets (parallel within-OS)
test-centos6: ## Run tests on CentOS 6
	$(TESTS_DIR)/run-tests.sh --os centos6 --parallel

test-centos7: ## Run tests on CentOS 7
	$(TESTS_DIR)/run-tests.sh --os centos7 --parallel

test-rocky8: ## Run tests on Rocky Linux 8
	$(TESTS_DIR)/run-tests.sh --os rocky8 --parallel

test-rocky9: ## Run tests on Rocky Linux 9
	$(TESTS_DIR)/run-tests.sh --os rocky9 --parallel

test-rocky10: ## Run tests on Rocky Linux 10
	$(TESTS_DIR)/run-tests.sh --os rocky10 --parallel

test-ubuntu2004: ## Run tests on Ubuntu 20.04
	$(TESTS_DIR)/run-tests.sh --os ubuntu2004 --parallel

test-ubuntu2404: ## Run tests on Ubuntu 24.04
	$(TESTS_DIR)/run-tests.sh --os ubuntu2404 --parallel

test-yara-x: ## Run tests with YARA-X (yr) instead of classic yara
	$(TESTS_DIR)/run-tests.sh --os yara-x --parallel

# Modern OS targets (active support) — sequential across OS, parallel within each
test-modern: ## Run modern targets sequentially (debian12, rocky9, ubuntu2404)
	$(TESTS_DIR)/run-tests.sh --os debian12 --parallel
	$(TESTS_DIR)/run-tests.sh --os rocky9 --parallel
	$(TESTS_DIR)/run-tests.sh --os ubuntu2404 --parallel

# Legacy OS targets (EOL but still in production) — sequential across OS
test-legacy: ## Run legacy targets sequentially (centos6, centos7, rocky8, ubuntu2004)
	$(TESTS_DIR)/run-tests.sh --os centos6 --parallel
	$(TESTS_DIR)/run-tests.sh --os centos7 --parallel
	$(TESTS_DIR)/run-tests.sh --os rocky8 --parallel
	$(TESTS_DIR)/run-tests.sh --os ubuntu2004 --parallel

# Full matrix (all CI targets) — sequential across OS, parallel within each
test-all: ## Run all 9 targets sequentially
	$(TESTS_DIR)/run-tests.sh --os debian12 --parallel
	$(TESTS_DIR)/run-tests.sh --os centos6 --parallel
	$(TESTS_DIR)/run-tests.sh --os centos7 --parallel
	$(TESTS_DIR)/run-tests.sh --os rocky8 --parallel
	$(TESTS_DIR)/run-tests.sh --os rocky9 --parallel
	$(TESTS_DIR)/run-tests.sh --os rocky10 --parallel
	$(TESTS_DIR)/run-tests.sh --os ubuntu2004 --parallel
	$(TESTS_DIR)/run-tests.sh --os ubuntu2404 --parallel
	$(TESTS_DIR)/run-tests.sh --os yara-x --parallel

# Parallel targets — run multiple OS tests concurrently (2x available cores)
test-modern-parallel: ## Run modern targets in parallel
	printf '%s\n' debian12 rocky9 ubuntu2404 | \
		xargs -P $(PARALLEL_JOBS) -I{} $(TESTS_DIR)/run-tests.sh --os {} --parallel

test-legacy-parallel: ## Run legacy targets in parallel
	printf '%s\n' centos6 centos7 rocky8 ubuntu2004 | \
		xargs -P $(PARALLEL_JOBS) -I{} $(TESTS_DIR)/run-tests.sh --os {} --parallel

test-all-parallel: ## Run all 9 targets in parallel
	printf '%s\n' debian12 centos6 centos7 rocky8 rocky9 rocky10 ubuntu2004 ubuntu2404 yara-x | \
		xargs -P $(PARALLEL_JOBS) -I{} $(TESTS_DIR)/run-tests.sh --os {} --parallel
