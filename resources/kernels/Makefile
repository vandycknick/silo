HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),x86_64)
override KERNEL_ARCH := x86_64
else ifneq ($(filter arm64 aarch64,$(HOST_ARCH)),)
override KERNEL_ARCH := arm64
endif

TRACK ?= stable
BUILD_REVISION ?= unknown
BUILD_CREATED ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

include $(CURDIR)/sources.mk

TRACK_VERSION := $(KERNEL_TRACK_$(TRACK)_VERSION)
TRACK_SHA256 := $(KERNEL_TRACK_$(TRACK)_SHA256)

ifeq ($(KERNEL_ARCH),arm64)
KERNEL_BUILD_TARGET := Image
else ifeq ($(KERNEL_ARCH),x86_64)
KERNEL_BUILD_TARGET := vmlinux
endif

RESOURCE_ROOT ?= $(abspath $(CURDIR)/..)
REPO_ROOT ?= $(abspath $(RESOURCE_ROOT)/..)
CACHE_ROOT ?= $(HOME)/.cache/silo/kernels
TARGET_ROOT ?= $(REPO_ROOT)/target
KERNEL_CHANNEL := v$(word 1,$(subst ., ,$(TRACK_VERSION))).x
KERNEL_SOURCE_URL := https://cdn.kernel.org/pub/linux/kernel/$(KERNEL_CHANNEL)/linux-$(TRACK_VERSION).tar.xz
KERNEL_SOURCE_DIR ?= $(CACHE_ROOT)/src/linux-$(TRACK_VERSION)
KERNEL_SOURCE_CHECKSUM := $(KERNEL_SOURCE_DIR).sha256
KERNEL_BUILD_DIR ?= $(CACHE_ROOT)/build/$(TRACK)-$(KERNEL_ARCH)-$(TRACK_VERSION)
KERNEL_TARBALL ?= $(CACHE_ROOT)/downloads/linux-$(TRACK_VERSION).tar.xz
KERNEL_OCI_LAYOUT ?= $(TARGET_ROOT)/kernels/$(TRACK)/$(KERNEL_ARCH)
KERNEL_OCI_REFERENCE ?= $(TRACK_VERSION)
COMMON_CONFIG ?= $(RESOURCE_ROOT)/kernels/configs/common.config
ARCH_CONFIG_FILE ?= $(RESOURCE_ROOT)/kernels/configs/$(KERNEL_ARCH).config
CONFIG_VALIDATOR ?= $(RESOURCE_ROOT)/kernels/scripts/validate-config.sh
OCI_PACKAGER ?= $(RESOURCE_ROOT)/kernels/scripts/package-oci.sh
OCI_VALIDATOR ?= $(RESOURCE_ROOT)/kernels/scripts/validate-oci.sh
COMPAT_CONFIG := $(wildcard $(RESOURCE_ROOT)/kernels/configs/compat/$(TRACK).config)
CONFIG_FRAGMENTS := $(COMMON_CONFIG) $(ARCH_CONFIG_FILE) $(COMPAT_CONFIG)
MINICONFIG := $(KERNEL_BUILD_DIR)/.miniconfig
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2)

.PHONY: kernel-config
kernel-config:
	@mkdir -p "$(dir $(KERNEL_TARBALL))" "$(dir $(KERNEL_SOURCE_DIR))" "$(KERNEL_BUILD_DIR)"
	@if [ -f "$(KERNEL_TARBALL)" ] && ! printf '%s  %s\n' "$(TRACK_SHA256)" "$(KERNEL_TARBALL)" | sha256sum --check --status; then \
		rm -f "$(KERNEL_TARBALL)"; \
	fi
	@if [ ! -f "$(KERNEL_TARBALL)" ]; then \
		curl -fL "$(KERNEL_SOURCE_URL)" -o "$(KERNEL_TARBALL).tmp" && \
		printf '%s  %s\n' "$(TRACK_SHA256)" "$(KERNEL_TARBALL).tmp" | sha256sum --check && \
		mv "$(KERNEL_TARBALL).tmp" "$(KERNEL_TARBALL)"; \
	fi
	@if [ ! -f "$(KERNEL_SOURCE_DIR)/Makefile" ] || [ "$$(cat "$(KERNEL_SOURCE_CHECKSUM)" 2>/dev/null)" != "$(TRACK_SHA256)" ]; then \
		rm -rf "$(KERNEL_SOURCE_DIR).tmp" && \
		mkdir -p "$(KERNEL_SOURCE_DIR).tmp" && \
		tar -xJf "$(KERNEL_TARBALL)" --strip-components=1 -C "$(KERNEL_SOURCE_DIR).tmp" && \
		rm -rf "$(KERNEL_SOURCE_DIR)" && \
		mv "$(KERNEL_SOURCE_DIR).tmp" "$(KERNEL_SOURCE_DIR)" && \
		printf '%s\n' "$(TRACK_SHA256)" > "$(KERNEL_SOURCE_CHECKSUM)"; \
	fi
	@KCONFIG_CONFIG="$(MINICONFIG)" "$(KERNEL_SOURCE_DIR)/scripts/kconfig/merge_config.sh" \
		-m -s $(CONFIG_FRAGMENTS)
	@KCONFIG_WARN_UNKNOWN_SYMBOLS=1 KCONFIG_WARN_CHANGED_INPUT=1 \
		$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		KCONFIG_ALLCONFIG="$(MINICONFIG)" alldefconfig
	@if ! "$(CONFIG_VALIDATOR)" "$(KERNEL_BUILD_DIR)/.config" $(CONFIG_FRAGMENTS); then \
		if [ "$(TRACK)" = stable ]; then exit 1; fi; \
		printf 'warning: %s/%s config differs from the stable miniconfig contract (best effort)\n' "$(TRACK)" "$(KERNEL_ARCH)" >&2; \
	fi

.PHONY: kernel
kernel: kernel-config
	@$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		-j"$(JOBS)" "$(KERNEL_BUILD_TARGET)"
	@KERNEL_BUILD_DIR="$(KERNEL_BUILD_DIR)" \
		KERNEL_ARCH="$(KERNEL_ARCH)" \
		KERNEL_OCI_LAYOUT="$(KERNEL_OCI_LAYOUT)" \
		KERNEL_OCI_REFERENCE="$(KERNEL_OCI_REFERENCE)" \
		KERNEL_TRACK="$(TRACK)" \
		KERNEL_VERSION="$(TRACK_VERSION)" \
		KERNEL_SOURCE_URL="$(KERNEL_SOURCE_URL)" \
		KERNEL_SOURCE_SHA256="$(TRACK_SHA256)" \
		BUILD_REVISION="$(BUILD_REVISION)" \
		BUILD_CREATED="$(BUILD_CREATED)" \
		"$(OCI_PACKAGER)"
	@"$(OCI_VALIDATOR)" "$(KERNEL_OCI_LAYOUT)" "$(KERNEL_OCI_REFERENCE)"
	@printf 'Created OCI kernel artifact %s:%s\n' "$(KERNEL_OCI_LAYOUT)" "$(KERNEL_OCI_REFERENCE)"

.PHONY: kernel-version
kernel-version:
	@printf '%s\n' "$(TRACK_VERSION)"

.PHONY: kernel-architecture
kernel-architecture:
	@printf '%s\n' "$(KERNEL_ARCH)"

.PHONY: publish
publish:
	@TRACK="$(TRACK)" "$(RESOURCE_ROOT)/kernels/scripts/publish-oci.sh"
