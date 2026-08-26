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
##? EXAMPLE=name: Select the Go SDK example for `make go-sdk-example` (default: basic).
EXAMPLE ?= basic
override CARGO_TARGET_DIR := $(abspath $(CARGO_TARGET_DIR))
export CARGO_TARGET_DIR

# Kernel configuration
##? KERNEL_REFERENCE=reference: Select the kernel OCI reference.
KERNEL_REFERENCE ?= ghcr.io/vandycknick/silo/kernel:stable
##? KERNEL_PATH=path: Use a local architecture-matched kernel.
KERNEL_PATH ?=
##? KERNEL_OFFLINE=0|1: Disable network access during kernel resolution.
KERNEL_OFFLINE ?= 0
##? KERNEL_REFRESH=0|1: Refresh the cached kernel reference.
KERNEL_REFRESH ?= 0

ifneq ($(KERNEL_OFFLINE),0)
ifneq ($(KERNEL_OFFLINE),1)
$(error KERNEL_OFFLINE must be 0 or 1)
endif
endif
ifneq ($(KERNEL_REFRESH),0)
ifneq ($(KERNEL_REFRESH),1)
$(error KERNEL_REFRESH must be 0 or 1)
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
XTASK := CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo run --locked -p xtask --
KERNEL_ARGS := --reference "$(KERNEL_REFERENCE)"
ifneq ($(strip $(KERNEL_PATH)),)
KERNEL_ARGS += --path "$(abspath $(KERNEL_PATH))"
endif
ifeq ($(KERNEL_OFFLINE),1)
KERNEL_ARGS += --offline
endif
ifeq ($(KERNEL_REFRESH),1)
KERNEL_ARGS += --refresh
endif
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
.PHONY: build stage go-sdk-example
build: ## Build the complete adjacent runtime.
	$(XTASK) build --profile "$(PROFILE)" $(KERNEL_ARGS)

stage: ## Build and assemble the portable runtime stage.
	$(XTASK) stage --profile "$(PROFILE)" $(KERNEL_ARGS)

go-sdk-example: ## Build the runtime and Go bridge, then run EXAMPLE (default: basic).
	$(XTASK) go-sdk-example "$(EXAMPLE)" --profile "$(PROFILE)" $(KERNEL_ARGS)

##@ Distribution
.PHONY: archive app package assemble-go-sdk install
archive: ## Build release runtime and CLI archives.
	$(XTASK) archive $(KERNEL_ARGS)

app: ## Build and sign the macOS release application.
	$(XTASK) app $(APP_ARGS) $(KERNEL_ARGS)

package: ## Build the macOS release package (use DMG=1 for a DMG).
	$(XTASK) package $(if $(filter 1,$(DMG)),--dmg) $(APP_ARGS) $(KERNEL_ARGS)

assemble-go-sdk: ## Assemble Go SDK release source from all qualified target artifacts (release-only).
	$(XTASK) assemble-go-sdk

install: ## Install the macOS release application and CLI symlink.
	$(XTASK) install --appdir "$(APPDIR)" --bindir "$(BINDIR)" $(APP_ARGS) $(KERNEL_ARGS)

##@ Quality
.PHONY: fmt clippy test test-unit test-integration version-check
fmt: ## Format workspace source code.
	$(XTASK) fmt

clippy: ## Lint all host-supported workspace components.
	$(XTASK) clippy

test: ## Run unit and integration tests for all host-supported workspace components.
	$(XTASK) test

test-unit: ## Run unit tests for all host-supported workspace components.
	$(XTASK) test-unit

test-integration: ## Run Cargo integration tests for all host-supported workspace components.
	$(XTASK) test-integration

version-check: ## Verify product versions match the version authority.
	$(XTASK) version-check

# Internal targets
.PHONY: cli vmmon netd krun agent init initramfs go-ffi kernel
cli vmmon netd krun agent init initramfs go-ffi:
	$(XTASK) component $@ --profile "$(PROFILE)"

kernel:
	$(XTASK) kernel $(KERNEL_ARGS)
