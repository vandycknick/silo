TRACK ?=
ARCH ?= arm64
KERNEL_VERSION := $(strip $(KERNEL_VERSION))

ifeq ($(KERNEL_VERSION),)
ifeq ($(TRACK),stable)
KERNEL_VERSION := 7.0.10
else ifeq ($(TRACK),longterm)
KERNEL_VERSION := 6.18.33
else ifeq ($(TRACK),longterm5)
KERNEL_VERSION := 5.15.208
endif
endif

RESOURCE_ROOT ?= $(abspath $(CURDIR)/..)
REPO_ROOT ?= $(abspath $(RESOURCE_ROOT)/..)
CACHE_ROOT ?= $(HOME)/.cache/bento/kernels
TARGET_ROOT ?= $(REPO_ROOT)/target
KERNEL_TARGET_ROOT := $(TARGET_ROOT)/kernels
KERNEL_CHANNEL := v$(shell printf '%s' "$(KERNEL_VERSION)" | cut -d '.' -f 1).x
KERNEL_SOURCE_DIR ?= $(CACHE_ROOT)/src/linux-$(KERNEL_VERSION)
KERNEL_BUILD_DIR ?= $(CACHE_ROOT)/build/$(TRACK)-$(ARCH)-$(KERNEL_VERSION)
KERNEL_OUT_DIR ?= $(CACHE_ROOT)/out/$(TRACK)-$(ARCH)-$(KERNEL_VERSION)
KERNEL_EXPORT_DIR ?= $(KERNEL_TARGET_ROOT)/$(TRACK)-$(ARCH)-$(KERNEL_VERSION)
KERNEL_TARBALL ?= $(CACHE_ROOT)/downloads/linux-$(KERNEL_VERSION).tar.xz
BASE_CONFIG ?= $(RESOURCE_ROOT)/kernels/configs/$(ARCH)-base.config
OVERLAY_CONFIG ?= $(RESOURCE_ROOT)/kernels/configs/overlays/$(TRACK).config
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2)


.PHONY: kernel
kernel: guard-kernel
	@mkdir -p "$(dir $(KERNEL_TARBALL))" "$(dir $(KERNEL_SOURCE_DIR))" "$(KERNEL_BUILD_DIR)" "$(KERNEL_OUT_DIR)" "$(KERNEL_EXPORT_DIR)"
	@if [ ! -f "$(KERNEL_SOURCE_DIR)/Makefile" ]; then \
		rm -rf "$(KERNEL_SOURCE_DIR).tmp"; \
		mkdir -p "$(KERNEL_SOURCE_DIR).tmp"; \
		if [ ! -f "$(KERNEL_TARBALL)" ]; then \
			curl -fL "https://cdn.kernel.org/pub/linux/kernel/$(KERNEL_CHANNEL)/linux-$(KERNEL_VERSION).tar.xz" -o "$(KERNEL_TARBALL)"; \
		fi; \
		tar -xJf "$(KERNEL_TARBALL)" --strip-components=1 -C "$(KERNEL_SOURCE_DIR).tmp"; \
		rm -rf "$(KERNEL_SOURCE_DIR)"; \
		mv "$(KERNEL_SOURCE_DIR).tmp" "$(KERNEL_SOURCE_DIR)"; \
	fi
	@cp "$(BASE_CONFIG)" "$(KERNEL_BUILD_DIR)/.config"
	@if [ -f "$(OVERLAY_CONFIG)" ]; then cat "$(OVERLAY_CONFIG)" >> "$(KERNEL_BUILD_DIR)/.config"; fi
	@$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" ARCH="$(ARCH)" olddefconfig
	@$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" ARCH="$(ARCH)" -j"$(JOBS)" Image
	@cp "$(KERNEL_BUILD_DIR)/.config" "$(KERNEL_OUT_DIR)/.config"
	@cp "$(KERNEL_BUILD_DIR)/System.map" "$(KERNEL_OUT_DIR)/System.map"
	@cp "$(KERNEL_BUILD_DIR)/arch/$(ARCH)/boot/Image" "$(KERNEL_OUT_DIR)/Image"
	@cp "$(KERNEL_OUT_DIR)/.config" "$(KERNEL_EXPORT_DIR)/.config"
	@cp "$(KERNEL_OUT_DIR)/System.map" "$(KERNEL_EXPORT_DIR)/System.map"
	@cp "$(KERNEL_OUT_DIR)/Image" "$(KERNEL_EXPORT_DIR)/Image"
	@printf "track=%s\narch=%s\nversion=%s\n" "$(TRACK)" "$(ARCH)" "$(KERNEL_VERSION)" > "$(KERNEL_EXPORT_DIR)/build-info.txt"

.PHONY: guard-kernel
guard-kernel:
	@test -n "$(TRACK)" || (echo "TRACK is required" && exit 1)
	@test -n "$(KERNEL_VERSION)" || (echo "KERNEL_VERSION is required" && exit 1)
	@test -n "$(ARCH)" || (echo "ARCH is required" && exit 1)
	@test -f "$(BASE_CONFIG)" || (echo "missing base config $(BASE_CONFIG)" && exit 1)
