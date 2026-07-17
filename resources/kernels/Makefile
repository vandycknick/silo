TRACK ?=
ARCH ?= arm64
BUILD_REVISION ?= unknown

include $(CURDIR)/manifest.mk

TRACK_VERSION := $(KERNEL_TRACK_$(TRACK)_VERSION)
TRACK_SHA256 := $(KERNEL_TRACK_$(TRACK)_SHA256)
ARCH_CONFIG := $(KERNEL_ARCH_$(ARCH)_CONFIG)
KERNEL_BUILD_TARGET := $(KERNEL_ARCH_$(ARCH)_BUILD_TARGET)
KERNEL_IMAGE_PATH := $(KERNEL_ARCH_$(ARCH)_IMAGE_PATH)
KERNEL_IMAGE_NAME := $(notdir $(KERNEL_IMAGE_PATH))

RESOURCE_ROOT ?= $(abspath $(CURDIR)/..)
REPO_ROOT ?= $(abspath $(RESOURCE_ROOT)/..)
CACHE_ROOT ?= $(HOME)/.cache/silo/kernels
TARGET_ROOT ?= $(REPO_ROOT)/target
KERNEL_TARGET_ROOT := $(TARGET_ROOT)/kernels
KERNEL_CHANNEL := v$(word 1,$(subst ., ,$(TRACK_VERSION))).x
KERNEL_SOURCE_DIR ?= $(CACHE_ROOT)/src/linux-$(TRACK_VERSION)
KERNEL_SOURCE_CHECKSUM := $(KERNEL_SOURCE_DIR).sha256
KERNEL_BUILD_DIR ?= $(CACHE_ROOT)/build/$(TRACK)-$(ARCH)-$(TRACK_VERSION)
KERNEL_EXPORT_DIR ?= $(KERNEL_TARGET_ROOT)/$(TRACK)-$(ARCH)-$(TRACK_VERSION)
KERNEL_EXPORT_TMP := $(KERNEL_EXPORT_DIR).tmp
KERNEL_TARBALL ?= $(CACHE_ROOT)/downloads/linux-$(TRACK_VERSION).tar.xz
BASE_CONFIG ?= $(RESOURCE_ROOT)/kernels/configs/$(ARCH_CONFIG).config
OVERLAY_CONFIG ?= $(RESOURCE_ROOT)/kernels/configs/overlays/$(TRACK).config
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2)

.PHONY: kernel
kernel: guard-kernel
	@mkdir -p "$(dir $(KERNEL_TARBALL))" "$(dir $(KERNEL_SOURCE_DIR))" "$(KERNEL_BUILD_DIR)"
	@if [ -f "$(KERNEL_TARBALL)" ] && ! printf '%s  %s\n' "$(TRACK_SHA256)" "$(KERNEL_TARBALL)" | sha256sum --check --status; then \
		rm -f "$(KERNEL_TARBALL)"; \
	fi
	@if [ ! -f "$(KERNEL_TARBALL)" ]; then \
		curl -fL "https://cdn.kernel.org/pub/linux/kernel/$(KERNEL_CHANNEL)/linux-$(TRACK_VERSION).tar.xz" -o "$(KERNEL_TARBALL).tmp" && \
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
	@cp "$(BASE_CONFIG)" "$(KERNEL_BUILD_DIR)/.config"
	@cat "$(OVERLAY_CONFIG)" >> "$(KERNEL_BUILD_DIR)/.config"
	@$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" ARCH="$(ARCH)" CROSS_COMPILE="$(CROSS_COMPILE)" olddefconfig
	@$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" ARCH="$(ARCH)" CROSS_COMPILE="$(CROSS_COMPILE)" -j"$(JOBS)" "$(KERNEL_BUILD_TARGET)"
	@rm -rf "$(KERNEL_EXPORT_TMP)"
	@mkdir -p "$(KERNEL_EXPORT_TMP)"
	@cp "$(KERNEL_BUILD_DIR)/.config" "$(KERNEL_EXPORT_TMP)/.config"
	@cp "$(KERNEL_BUILD_DIR)/System.map" "$(KERNEL_EXPORT_TMP)/System.map"
	@cp "$(KERNEL_BUILD_DIR)/$(KERNEL_IMAGE_PATH)" "$(KERNEL_EXPORT_TMP)/$(KERNEL_IMAGE_NAME)"
	@xz -T0 -6 -c "$(KERNEL_BUILD_DIR)/vmlinux" > "$(KERNEL_EXPORT_TMP)/vmlinux.xz"
	@printf "track=%s\narch=%s\nversion=%s\nrevision=%s\nsource_sha256=%s\n" \
		"$(TRACK)" "$(ARCH)" "$(TRACK_VERSION)" "$(BUILD_REVISION)" "$(TRACK_SHA256)" \
		> "$(KERNEL_EXPORT_TMP)/build-info.txt"
	@cd "$(KERNEL_EXPORT_TMP)" && sha256sum \
		"$(KERNEL_IMAGE_NAME)" .config System.map vmlinux.xz build-info.txt > SHA256SUMS
	@rm -rf "$(KERNEL_EXPORT_DIR)"
	@mv "$(KERNEL_EXPORT_TMP)" "$(KERNEL_EXPORT_DIR)"
	@printf 'Exported kernel artifacts to %s\n' "$(KERNEL_EXPORT_DIR)"

.PHONY: kernel-version
kernel-version: guard-selection
	@printf '%s\n' "$(TRACK_VERSION)"

.PHONY: kernel-export-dir
kernel-export-dir: guard-selection
	@printf '%s\n' "$(KERNEL_EXPORT_DIR)"

.PHONY: guard-selection
guard-selection:
	@test -n "$(TRACK)" || (echo "TRACK is required" && exit 1)
	@test -n "$(ARCH)" || (echo "ARCH is required" && exit 1)
	@test -n "$(TRACK_VERSION)" || (echo "unknown kernel track: $(TRACK)" && exit 1)
	@test -n "$(ARCH_CONFIG)" || (echo "unknown kernel architecture: $(ARCH)" && exit 1)

.PHONY: guard-kernel
guard-kernel: guard-selection
	@command -v curl >/dev/null || (echo "missing required tool: curl" && exit 1)
	@command -v sha256sum >/dev/null || (echo "missing required tool: sha256sum" && exit 1)
	@command -v tar >/dev/null || (echo "missing required tool: tar" && exit 1)
	@command -v xz >/dev/null || (echo "missing required tool: xz" && exit 1)
	@if [ -n "$(CROSS_COMPILE)" ]; then \
		command -v "$(CROSS_COMPILE)gcc" >/dev/null || (echo "missing cross compiler: $(CROSS_COMPILE)gcc" && exit 1); \
	fi
	@test -f "$(BASE_CONFIG)" || (echo "missing base config $(BASE_CONFIG)" && exit 1)
	@test -f "$(OVERLAY_CONFIG)" || (echo "missing track overlay $(OVERLAY_CONFIG)" && exit 1)
