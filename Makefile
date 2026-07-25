.DEFAULT_GOAL := all

# User options
PROFILE ?= debug
GUEST_TARGET ?=
TRACK ?= stable
KERNEL_REFERENCE ?= ghcr.io/vandycknick/silo/kernel:stable
RELEASE_BUILD_NUMBER ?= 1
MACOS_SIGNING_IDENTITY ?=
MACOS_NOTARY_KEYCHAIN_PROFILE ?=
MACOS_NOTARY_KEYCHAIN ?=
PUBLISHED_MACOS_DMG ?=
CARGO_TARGET_DIR ?= target
PREFIX ?= /usr/local

override CARGO_TARGET_DIR := $(abspath $(CARGO_TARGET_DIR))
export CARGO_TARGET_DIR

# Host and profile
HOST_OS := $(shell uname -s)
HOST_ARCH := $(shell uname -m)
HOST_PLATFORM := $(HOST_OS)-$(HOST_ARCH)

ifeq ($(HOST_PLATFORM),Darwin-arm64)
HOST_RELEASE_TARGET := darwin-arm64
WORKSPACE_EXCLUDES := --exclude agent --exclude init
else ifeq ($(HOST_PLATFORM),Linux-x86_64)
HOST_RELEASE_TARGET := linux-amd64-gnu
WORKSPACE_EXCLUDES := --exclude init --exclude vz
else ifeq ($(HOST_PLATFORM),Linux-aarch64)
HOST_RELEASE_TARGET := linux-arm64-gnu
WORKSPACE_EXCLUDES := --exclude init --exclude vz
else
HOST_RELEASE_TARGET :=
WORKSPACE_EXCLUDES := --exclude agent --exclude init --exclude vz
endif

ifneq ($(PROFILE),debug)
ifneq ($(PROFILE),release)
$(error PROFILE must be debug or release)
endif
endif

CARGO_PROFILE_FLAGS = $(if $(filter release,$(PROFILE)),--release)
GO_BUILD_FLAGS = $(if $(filter release,$(PROFILE)),-ldflags "-s -w")

# Derived development paths
PROFILE_DIR = $(CARGO_TARGET_DIR)/$(PROFILE)
GUEST_ASSETS_DIR := $(CARGO_TARGET_DIR)/resources/assets
DEV_ASSETS_DIR = $(PROFILE_DIR)/assets
KERNEL_CACHE_KEY := $(subst /,_,$(subst :,_,$(KERNEL_REFERENCE)))
DEV_KERNEL_DIR := $(CARGO_TARGET_DIR)/resources/kernels/$(HOST_RELEASE_TARGET)/$(KERNEL_CACHE_KEY)
DEFAULT_DEV_KERNEL := $(DEV_KERNEL_DIR)/kernel-default
DEV_KERNEL ?= $(DEFAULT_DEV_KERNEL)
ROOTFS_DIR := $(CARGO_TARGET_DIR)/resources/rootfs
INSTALL_BIN_DIR = $(DESTDIR)$(PREFIX)/bin
INSTALL_HELPER_DIR = $(DESTDIR)$(PREFIX)/libexec/silo
INSTALL_ASSET_DIR = $(DESTDIR)$(PREFIX)/lib/silo/assets

MACOS_PACKAGE_ARGS := --build-number "$(RELEASE_BUILD_NUMBER)"
ifneq ($(strip $(MACOS_SIGNING_IDENTITY)),)
MACOS_PACKAGE_ARGS += --signing-identity "$(MACOS_SIGNING_IDENTITY)"
endif
ifneq ($(strip $(MACOS_NOTARY_KEYCHAIN_PROFILE)),)
MACOS_PACKAGE_ARGS += --notary-keychain-profile "$(MACOS_NOTARY_KEYCHAIN_PROFILE)"
endif
ifneq ($(strip $(MACOS_NOTARY_KEYCHAIN)),)
MACOS_PACKAGE_ARGS += --notary-keychain "$(MACOS_NOTARY_KEYCHAIN)"
endif

.PHONY: all build cli install guest-assets test clippy verify kernel refresh-dev-kernel rootfs \
	release-stage package-archives package-macos package-homebrew-cask release help \
	vmmon netd krun development-assets check-supported-host

# Development
all: PROFILE = release
all: build ## Build a complete release runtime from source.

build: check-supported-host vmmon netd krun development-assets ## Build a complete development runtime.
	cargo build $(CARGO_PROFILE_FLAGS) -p cli

cli: ## Build only the Silo CLI and its Rust dependencies.
	cargo build $(CARGO_PROFILE_FLAGS) -p cli --bin silo

guest-assets: ## Build the guest agent, init, and initramfs.
	cargo run -p xtask -- guest-assets $(if $(strip $(GUEST_TARGET)),--target "$(GUEST_TARGET)") --assets-dir "$(GUEST_ASSETS_DIR)"

development-assets: guest-assets $(DEV_KERNEL)
	@mkdir -p "$(DEV_ASSETS_DIR)"
	cp "$(DEV_KERNEL)" "$(DEV_ASSETS_DIR)/kernel-default"
	cp "$(GUEST_ASSETS_DIR)/initramfs" "$(DEV_ASSETS_DIR)/initramfs"
	cp "$(GUEST_ASSETS_DIR)/agent" "$(DEV_ASSETS_DIR)/agent"
	chmod 0644 "$(DEV_ASSETS_DIR)/kernel-default" "$(DEV_ASSETS_DIR)/initramfs"
	chmod 0755 "$(DEV_ASSETS_DIR)/agent"

install: PROFILE = release
install: check-supported-host
	@case "$(PREFIX)" in /*) ;; *) echo "PREFIX must be absolute: $(PREFIX)" >&2; exit 1 ;; esac
	@if test -n "$(DESTDIR)"; then case "$(DESTDIR)" in /*) ;; *) echo "DESTDIR must be absolute: $(DESTDIR)" >&2; exit 1 ;; esac; fi
	@for path in "$(PROFILE_DIR)/silo" "$(PROFILE_DIR)/vmmon" "$(PROFILE_DIR)/netd" "$(PROFILE_DIR)/krun" "$(DEV_ASSETS_DIR)/agent"; do \
		test -x "$$path" || { echo "missing executable build artifact: $$path; run make first" >&2; exit 1; }; \
	done
	@for path in "$(DEV_ASSETS_DIR)/kernel-default" "$(DEV_ASSETS_DIR)/initramfs"; do \
		test -f "$$path" || { echo "missing build artifact: $$path; run make first" >&2; exit 1; }; \
	done
	install -d -m 0755 "$(INSTALL_BIN_DIR)" "$(INSTALL_HELPER_DIR)" "$(INSTALL_ASSET_DIR)"
	install -m 0755 "$(PROFILE_DIR)/silo" "$(INSTALL_BIN_DIR)/silo"
	install -m 0755 "$(PROFILE_DIR)/vmmon" "$(PROFILE_DIR)/netd" "$(PROFILE_DIR)/krun" "$(INSTALL_HELPER_DIR)"
	install -m 0755 "$(DEV_ASSETS_DIR)/agent" "$(INSTALL_ASSET_DIR)/agent"
	install -m 0644 "$(DEV_ASSETS_DIR)/kernel-default" "$(DEV_ASSETS_DIR)/initramfs" "$(INSTALL_ASSET_DIR)"

$(DEFAULT_DEV_KERNEL): | check-supported-host
	cargo run -p xtask -- resolve-kernel \
		--target "$(HOST_RELEASE_TARGET)" \
		--reference "$(KERNEL_REFERENCE)" \
		--output-dir "$(DEV_KERNEL_DIR)"

# Quality
test: ## Run the host-supported workspace test suite.
	cargo test --workspace --all-targets --all-features $(WORKSPACE_EXCLUDES)

clippy: ## Run the host-supported workspace lints.
	cargo clippy --workspace --all-targets --all-features $(WORKSPACE_EXCLUDES)

verify: ## Run formatting checks, xtask tests, and Clippy.
	cargo fmt --all --check
	cargo test -p xtask
	$(MAKE) clippy

# Kernel and root filesystem
kernel: ## Build the guest kernel from source.
	@$(MAKE) -C resources/kernels kernel TRACK="$(TRACK)"

refresh-dev-kernel: check-supported-host ## Refresh the cached OCI development kernel.
	$(RM) -r "$(DEV_KERNEL_DIR)"
	$(MAKE) "$(DEFAULT_DEV_KERNEL)"
	@mkdir -p "$(DEV_ASSETS_DIR)"
	cp "$(DEFAULT_DEV_KERNEL)" "$(DEV_ASSETS_DIR)/kernel-default"
	chmod 0644 "$(DEV_ASSETS_DIR)/kernel-default"

rootfs: ## Build the development root filesystem.
	@mkdir -p "$(ROOTFS_DIR)"
	@docker build -f resources/rootfs/Dockerfile -t rootfs .
	@docker run -it -v "$(ROOTFS_DIR):/resources" --privileged --cap-add=CAP_MKNOD rootfs

# Packaging and release
release-stage: check-supported-host ## Build and validate release staging.
	cargo run -p xtask -- release-stage \
		--target "$(HOST_RELEASE_TARGET)" \
		--kernel-reference "$(KERNEL_REFERENCE)"

package-archives: check-supported-host ## Package portable release archives.
	cargo run -p xtask -- package-archives --target "$(HOST_RELEASE_TARGET)"

package-macos: ## Package, sign, and optionally notarize the macOS distribution.
	cargo run -p xtask -- package-macos $(MACOS_PACKAGE_ARGS)

package-homebrew-cask: ## Generate the Homebrew Cask from a notarized release.
	@test -n "$(PUBLISHED_MACOS_DMG)" || { echo "PUBLISHED_MACOS_DMG is required" >&2; exit 1; }
	cargo run -p xtask -- package-homebrew-cask --published-macos-dmg "$(PUBLISHED_MACOS_DMG)"

release: verify ## Build all credential-free release artifacts.
	$(MAKE) release-stage
	$(MAKE) package-archives
ifeq ($(HOST_OS),Darwin)
	$(MAKE) package-macos
endif

# Internal component targets
vmmon:
	cargo build $(CARGO_PROFILE_FLAGS) -p vmmon
	cargo run -p xtask -- sign-vmmon "$(PROFILE_DIR)/vmmon"

netd:
	@mkdir -p "$(PROFILE_DIR)"
	cd net/netd && go build $(GO_BUILD_FLAGS) -o "$(PROFILE_DIR)/netd" ./cmd/netd

krun:
	cargo build $(CARGO_PROFILE_FLAGS) -p krun --features krun-bin --bin krun

check-supported-host:
	@test -n "$(HOST_RELEASE_TARGET)" || { \
		echo "unsupported host: $(HOST_OS) $(HOST_ARCH)" >&2; \
		exit 1; \
	}

help: ## Show available commands.
	@awk 'BEGIN { FS = ":.*## "; print "Usage: make <command> [VARIABLE=value]"; print ""; print "Commands:" } /^[a-zA-Z0-9_-]+:.*## / { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
