.DEFAULT_GOAL := build

# Build configuration
##? PROFILE=debug|release: Select the build profile (default: debug).
PROFILE ?= debug
ifneq ($(PROFILE),debug)
ifneq ($(PROFILE),release)
$(error PROFILE must be debug or release)
endif
endif

##? CARGO_TARGET_DIR=path: Set the Cargo output directory (default: ./target).
CARGO_TARGET_DIR ?= $(CURDIR)/target
##? SMOKE_PROFILE=release|debug: Profile make smoke builds and tests (default: release; debug only for debugging).
SMOKE_PROFILE ?= release
ifneq ($(SMOKE_PROFILE),debug)
ifneq ($(SMOKE_PROFILE),release)
$(error SMOKE_PROFILE must be debug or release)
endif
endif
##? SMOKE_ARGS=...: Extra pytest arguments for make smoke.
SMOKE_ARGS ?=
##? SMOKE_WORKERS=N: Parallel smoke workers (default: 2; size for guest RAM, not CPU count).
SMOKE_WORKERS ?= 2
##? SMOKE_MARK=expression: Smoke marker selection (default: not slow; SMOKE_ARGS=-m overrides it).
SMOKE_MARK ?= not slow
##? PERF_COHORTS=a,b: Performance cohorts (empty selects all).
PERF_COHORTS ?=
##? PERF_SYSTEMS=silo,msb: Performance systems (default: silo).
PERF_SYSTEMS ?= silo
##? PERF_SAMPLES=N: Samples per performance cohort and mode (default: 3).
PERF_SAMPLES ?= 3
##? PERF_ARGS=...: Extra serial performance pytest arguments.
PERF_ARGS ?=
##? PERF_SHELL=command: Performance toolchain prefix (default: nix develop .#perf --command).
PERF_SHELL ?= nix develop .\#perf --command
##? CHANGESET_ARGS=...: Extra arguments for explicit OCI fixture/acquisition/qualification commands.
CHANGESET_ARGS ?=
##? BASELINE=path: Select the coverage regression baseline (default: target/coverage-baseline).
BASELINE ?= $(CARGO_TARGET_DIR)/coverage-baseline
override CARGO_TARGET_DIR := $(abspath $(CARGO_TARGET_DIR))
export CARGO_TARGET_DIR

# Kernel configuration
##? KERNEL_REFERENCE=reference: Select the kernel OCI reference.
KERNEL_REFERENCE ?= ghcr.io/vandycknick/silo/kernel:stable
##? KERNEL_PATH=path: Use a local architecture-matched kernel.
KERNEL_PATH ?=
##? KERNEL_OFFLINE=0|1: Disable network access during kernel resolution.
KERNEL_OFFLINE ?= 0

ifneq ($(KERNEL_OFFLINE),0)
ifneq ($(KERNEL_OFFLINE),1)
$(error KERNEL_OFFLINE must be 0 or 1)
endif
endif

# Local kernel builds (make kernel)
include $(CURDIR)/resources/kernels/sources.mk
##? TRACK=stable|longterm|longterm5: Select the kernel source track built by make kernel (default: stable).
TRACK ?= stable
ifeq ($(strip $(KERNEL_TRACK_$(TRACK)_VERSION)),)
$(error TRACK must name a track in resources/kernels/sources.mk, got '$(TRACK)')
endif
##? KERNEL_SHELL=command: Toolchain prefix for make kernel (default: nix develop .#kernel --command; empty uses the current environment).
KERNEL_SHELL ?= nix develop .\#kernel --command
LOCAL_KERNEL := $(CARGO_TARGET_DIR)/kernel-$(TRACK)

# Rosetta probe acquisition (Apple Silicon macOS builds)
##? RPROBE_REFERENCE=reference: Select the rprobe OCI reference.
RPROBE_REFERENCE ?= ghcr.io/vandycknick/silo/rprobe:stable
##? RPROBE_PATH=path: Use a locally built self-contained rprobe kernel.
RPROBE_PATH ?=
##? RPROBE_OFFLINE=0|1: Disable network access during probe resolution.
RPROBE_OFFLINE ?= 0

ifneq ($(RPROBE_OFFLINE),0)
ifneq ($(RPROBE_OFFLINE),1)
$(error RPROBE_OFFLINE must be 0 or 1)
endif
endif

# macOS packaging configuration
##? DMG=0|1: Also create a DMG when packaging (default: 0).
DMG ?= 0
##? BUILD_NUMBER=number: Override the macOS application build number.
BUILD_NUMBER ?=
##? DEVELOPER_ID_APPLICATION=identity: Sign with a Developer ID Application identity.
DEVELOPER_ID_APPLICATION ?=

ifneq ($(DMG),0)
ifneq ($(DMG),1)
$(error DMG must be 0 or 1)
endif
endif

# Installation configuration
##? APPDIR=path: Set the macOS application install directory.
APPDIR ?= /Applications
##? BINDIR=path: Set the CLI symlink install directory.
BINDIR ?= /usr/local/bin

# Derived commands and arguments
HOST_OS := $(shell uname -s)
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_OS)/$(HOST_ARCH),Linux/x86_64)
RUNTIME_TARGET := linux-amd64-gnu
else ifeq ($(HOST_OS)/$(HOST_ARCH),Linux/aarch64)
RUNTIME_TARGET := linux-arm64-gnu
else ifeq ($(HOST_OS)/$(HOST_ARCH),Darwin/arm64)
RUNTIME_TARGET := darwin-arm64
else
$(error unsupported host)
endif
XTASK := CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo run --locked -p xtask --
KERNEL_ARGS := --reference "$(KERNEL_REFERENCE)"
ifneq ($(strip $(KERNEL_PATH)),)
KERNEL_ARGS += --path "$(abspath $(KERNEL_PATH))"
endif
ifeq ($(KERNEL_OFFLINE),1)
KERNEL_ARGS += --offline
endif
RPROBE_ARGS := --rprobe-reference "$(RPROBE_REFERENCE)"
ifneq ($(strip $(RPROBE_PATH)),)
RPROBE_ARGS += --rprobe-path "$(abspath $(RPROBE_PATH))"
endif
ifeq ($(RPROBE_OFFLINE),1)
RPROBE_ARGS += --rprobe-offline
endif
RUNTIME_ARGS := $(KERNEL_ARGS) $(RPROBE_ARGS)
APP_ARGS := $(strip $(if $(strip $(BUILD_NUMBER)),--build-number "$(BUILD_NUMBER)") $(if $(strip $(DEVELOPER_ID_APPLICATION)),--developer-id-application "$(DEVELOPER_ID_APPLICATION)"))

##@ General
.PHONY: help
help: ## Show public targets and configurable options.
	@awk 'BEGIN { FS = ":.*## "; printf "Usage: make <target> [OPTION=value ...]\n" } \
		/^##\? / { line = substr($$0, 5); separator = index(line, ":"); option_count++; options[option_count] = substr(line, 1, separator - 1); option_help[option_count] = substr(line, separator + 2); next } \
		/^##@ / { printf "\n%s:\n", substr($$0, 5); next } \
		/^[A-Za-z0-9_.-]+:.*## / { printf "  %-20s %s\n", $$1, $$2 } \
		END { printf "\nOptions:\n"; for (i = 1; i <= option_count; i++) printf "  %-36s %s\n", options[i], option_help[i] }' $(MAKEFILE_LIST)

##@ Build
.PHONY: build stage
build: ## Build the complete adjacent runtime, CLI and daemon.
	$(XTASK) build --profile "$(PROFILE)" $(RUNTIME_ARGS)

stage: ## Build and assemble the portable runtime stage.
	$(XTASK) stage --profile "$(PROFILE)" $(RUNTIME_ARGS)

##@ Kernel
.PHONY: kernel
kernel: ## Build a workload kernel from resources/kernels (TRACK) to use as KERNEL_PATH.
ifneq ($(HOST_OS),Linux)
	@printf 'make kernel needs Linux on the target architecture; on macOS run it inside a Linux VM (see resources/kernels/README.md)\n' >&2; exit 1
endif
	@mkdir -p "$(dir $(LOCAL_KERNEL))"
	$(KERNEL_SHELL) $(MAKE) -C resources/kernels kernel-image TRACK="$(TRACK)" KERNEL_IMAGE_OUTPUT="$(LOCAL_KERNEL)"
	@printf '\nBuilt %s\nBake it into a Silo build with:\n  make build KERNEL_PATH=%s\n' "$(LOCAL_KERNEL)" "$(LOCAL_KERNEL)"

##@ Distribution
.PHONY: archive runtime-archive portable-archive app package install
archive: ## Build release runtime and product archives.
	$(XTASK) archive $(RUNTIME_ARGS)

runtime-archive: ## Archive an already-built PROFILE runtime stage with checksum, SBOM and provenance.
	$(XTASK) runtime-archive --profile "$(PROFILE)"

portable-archive: ## Archive an already-built release runtime and CLI.
	$(XTASK) portable-archive

app: ## Build and sign the macOS release application.
	$(XTASK) app $(APP_ARGS) $(RUNTIME_ARGS)

package: ## Build the macOS release package (use DMG=1 for a DMG).
	$(XTASK) package $(if $(filter 1,$(DMG)),--dmg) $(APP_ARGS) $(RUNTIME_ARGS)

install: ## Install the macOS release application and CLI symlink.
	$(XTASK) install --appdir "$(APPDIR)" --bindir "$(BINDIR)" $(APP_ARGS) $(RUNTIME_ARGS)

##@ Quality
.PHONY: fmt clippy test test-unit test-integration smoke version-check
fmt: ## Format workspace source code.
	$(XTASK) fmt

clippy: ## Lint all host-supported workspace components.
	$(XTASK) clippy

test: ## Run unit and integration tests for all host-supported workspace components.
	$(XTASK) test

test-unit: ## Run unit tests for all host-supported workspace components.
	$(XTASK) test-unit

test-integration: ## Run integration tests for all host-supported workspace components.
	$(XTASK) test-integration

.PHONY: coverage coverage-baseline coverage-diff
coverage: ## Collect Rust/Go coverage into target/coverage.
	$(XTASK) coverage

coverage-baseline: ## Snapshot coverage as the reduction baseline.
	rm -rf "$(BASELINE)" && cp -R "$(CARGO_TARGET_DIR)/coverage" "$(BASELINE)"

coverage-diff: ## Fail if coverage regressed versus BASELINE.
	$(XTASK) coverage-diff --baseline "$(BASELINE)" --current "$(CARGO_TARGET_DIR)/coverage"

.PHONY: smoke-kernel smoke-prereqs smoke-diagnostic
SMOKE_RUNTIME_SOURCE ?= $(CARGO_TARGET_DIR)/silo-runtime/$(RUNTIME_TARGET)/$(SMOKE_PROFILE)
# Smoke exercises this tree's kernel configuration, not the last published
# kernel, so it builds the repo kernel (a cache hit after the first build)
# unless KERNEL_PATH names one.
SMOKE_KERNEL := $(if $(strip $(KERNEL_PATH)),$(abspath $(KERNEL_PATH)),$(LOCAL_KERNEL))
smoke-kernel:
ifeq ($(strip $(KERNEL_PATH)),)
	$(MAKE) kernel
endif

# Every run stages and builds SMOKE_PROFILE first, so smoke and perf never
# test binaries older than the tree.
smoke-prereqs: smoke-kernel ## Stage SMOKE_PROFILE with the smoke kernel and build every helper used by smoke.
	$(MAKE) stage PROFILE="$(SMOKE_PROFILE)" KERNEL_PATH="$(SMOKE_KERNEL)"
	cargo build --locked $(if $(filter release,$(SMOKE_PROFILE)),--release) -p libvm --example storage_acceptance --example live_acceptance --example root_metrics --example overlay_candidate_lower --example erofs_qualification
	cargo build --locked $(if $(filter release,$(SMOKE_PROFILE)),--release) -p disk-image --example format_upper
	cargo build --locked $(if $(filter release,$(SMOKE_PROFILE)),--release) -p silo-vmm --example native-live-api --example guest-lifecycle-controller
	cd smoke && PROFILE="$(SMOKE_PROFILE)" SILO_SMOKE_BIN_DIR="$${SILO_SMOKE_BIN_DIR:-$(CARGO_TARGET_DIR)/$(SMOKE_PROFILE)}" uv run python -m silo_smoke.prereqs --runtime "$${SILO_SMOKE_RUNTIME_DIR:-$(CARGO_TARGET_DIR)/silo-runtime/$(RUNTIME_TARGET)/$(SMOKE_PROFILE)}" --local-kernel "$(SMOKE_KERNEL)" --marker "$(SMOKE_MARK)" -- $(SMOKE_ARGS)

smoke-diagnostic:
	$(XTASK) --target-dir "$(CARGO_TARGET_DIR)/smoke-diagnostic" stage --profile "$(SMOKE_PROFILE)" --vmm-features restore-irq-probe --path "$(SMOKE_RUNTIME_SOURCE)/assets/kernel-default"

smoke: smoke-prereqs ## Build and run real-VM smoke (needs KVM/HVF; not CI).
	cd smoke && { \
		export PROFILE="$(SMOKE_PROFILE)"; \
		export SILO_SMOKE_BIN_DIR="$${SILO_SMOKE_BIN_DIR:-$(CARGO_TARGET_DIR)/$(SMOKE_PROFILE)}"; \
		export SILO_SMOKE_RUNTIME_DIR="$${SILO_SMOKE_RUNTIME_DIR:-$(CARGO_TARGET_DIR)/silo-runtime/$(RUNTIME_TARGET)/$(SMOKE_PROFILE)}"; \
		status=0; \
		uv run pytest -m "$(SMOKE_MARK)" $(SMOKE_ARGS) -n $(SMOKE_WORKERS) --dist loadfile --smoke-lane parallel || { code=$$?; test $$code -eq 5 || status=$$code; }; \
		uv run pytest -m "$(SMOKE_MARK)" $(SMOKE_ARGS) -n 0 --smoke-lane serial || { code=$$?; test $$code -eq 5 || status=$$code; }; \
		exit $$status; \
	}

.PHONY: perf perf-run
perf: ## Enter the pinned perf shell, stage a fresh release build and benchmark serially.
	$(PERF_SHELL) $(MAKE) perf-run

# Performance is only ever measured on release binaries, whatever the caller asks for.
perf-run: override SMOKE_PROFILE := release
perf-run: smoke-prereqs
	cd perf && PROFILE=release \
		SILO_SMOKE_BIN_DIR="$${SILO_SMOKE_BIN_DIR:-$(CARGO_TARGET_DIR)/release}" \
		SILO_SMOKE_RUNTIME_DIR="$${SILO_SMOKE_RUNTIME_DIR:-$(CARGO_TARGET_DIR)/silo-runtime/$(RUNTIME_TARGET)/release}" \
		PERF_COHORTS="$(PERF_COHORTS)" PERF_SYSTEMS="$(PERF_SYSTEMS)" PERF_SAMPLES="$(PERF_SAMPLES)" \
		uv run pytest -s $(PERF_ARGS) -n 0

version-check: ## Verify product versions match the version authority.
	$(XTASK) version-check

.PHONY: changeset-fixtures changeset-extractor changeset-acquire changeset-socket changeset-metadata qualify-changesets
changeset-fixtures: ## Generate independent full-byte OCI changeset fixture goldens (offline Rust).
	$(XTASK) changeset-fixtures $(CHANGESET_ARGS)

changeset-extractor: ## Build the pinned test-only containerd v2.4.2 extractor (Go >=1.26.6).
	$(XTASK) changeset-extractor $(CHANGESET_ARGS)

changeset-acquire: ## Acquire one verified published corpus image (explicit --image NAME, network).
	$(XTASK) changeset-acquire $(CHANGESET_ARGS)

changeset-socket: ## Build pinned test-only star and generate/extract a real Unix socket specimen.
	$(XTASK) changeset-socket $(CHANGESET_ARGS)

changeset-metadata: ## Capture real GNU tar/libarchive/star xattr producer-original and extraction evidence.
	$(XTASK) changeset-metadata $(CHANGESET_ARGS)

qualify-changesets: ## Compare against real containerd extraction, retaining JSON and Markdown differences.
	$(XTASK) qualify-changesets $(CHANGESET_ARGS)

# Internal targets
.PHONY: cli silo-vmm netd agent portd init initramfs rprobe
cli silo-vmm netd agent portd init initramfs rprobe:
	$(XTASK) component $@ --profile "$(PROFILE)"
