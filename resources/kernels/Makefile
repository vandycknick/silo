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
OCI_IMAGE ?= ghcr.io/$(GITHUB_REPOSITORY_OWNER)/silo/kernel
ARM64_OCI_LAYOUT ?= $(TARGET_ROOT)/kernels/$(TRACK)/arm64
AMD64_OCI_LAYOUT ?= $(TARGET_ROOT)/kernels/$(TRACK)/x86_64
PUBLISH_REVISION ?= $(GITHUB_SHA)
PUBLISH_SOURCE ?= https://github.com/$(GITHUB_REPOSITORY)
PUBLISH_CREATED ?= $(shell git -C "$(REPO_ROOT)" show -s --format=%cI "$(PUBLISH_REVISION)" 2>/dev/null)
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
	@set -eu; \
		temp_dir=$$(mktemp -d); \
		trap 'rm -rf "$$temp_dir"' 0 HUP INT TERM; \
		revision_tag="$(TRACK_VERSION)-$(PUBLISH_REVISION)"; \
		arm64_tag="$$revision_tag-arm64"; \
		amd64_tag="$$revision_tag-amd64"; \
		oras cp --from-oci-layout "$(ARM64_OCI_LAYOUT):$(TRACK_VERSION)" "$(OCI_IMAGE):$$arm64_tag"; \
		oras cp --from-oci-layout "$(AMD64_OCI_LAYOUT):$(TRACK_VERSION)" "$(OCI_IMAGE):$$amd64_tag"; \
		oras manifest fetch --descriptor "$(OCI_IMAGE):$$arm64_tag" > "$$temp_dir/arm64-descriptor.json"; \
		oras manifest fetch --descriptor "$(OCI_IMAGE):$$amd64_tag" > "$$temp_dir/amd64-descriptor.json"; \
		jq -n \
			--slurpfile arm64 "$$temp_dir/arm64-descriptor.json" \
			--slurpfile amd64 "$$temp_dir/amd64-descriptor.json" \
			--arg created "$(PUBLISH_CREATED)" \
			--arg revision "$(PUBLISH_REVISION)" \
			--arg source "$(PUBLISH_SOURCE)" \
			--arg version "$(TRACK_VERSION)" \
			--arg track "$(TRACK)" \
			'{ \
				schemaVersion: 2, \
				mediaType: "application/vnd.oci.image.index.v1+json", \
				artifactType: "application/vnd.silo.kernel.v1", \
				manifests: [ \
					($$arm64[0] | {mediaType, digest, size, artifactType} + {platform: {os: "linux", architecture: "arm64"}}), \
					($$amd64[0] | {mediaType, digest, size, artifactType} + {platform: {os: "linux", architecture: "amd64"}}) \
				], \
				annotations: { \
					"org.opencontainers.image.created": $$created, \
					"org.opencontainers.image.description": "Silo Linux kernel", \
					"org.opencontainers.image.revision": $$revision, \
					"org.opencontainers.image.source": $$source, \
					"org.opencontainers.image.version": $$version, \
					"com.silo.kernel.track": $$track \
				} \
			}' > "$$temp_dir/kernel-index.json"; \
		oras manifest push "$(OCI_IMAGE):$$revision_tag,$(TRACK_VERSION),$(TRACK)" "$$temp_dir/kernel-index.json"; \
		oras manifest fetch "$(OCI_IMAGE):$$revision_tag" > "$$temp_dir/published-index.json"; \
		jq -e ' \
			.artifactType == "application/vnd.silo.kernel.v1" and \
			([.manifests[].platform | [.os, .architecture]] | sort) == \
				([ ["linux", "amd64"], ["linux", "arm64"] ] | sort) \
		' "$$temp_dir/published-index.json" >/dev/null; \
		for platform in linux/arm64 linux/amd64; do \
			oras manifest fetch --platform "$$platform" "$(OCI_IMAGE):$$revision_tag" | \
				jq -e '([.layers[] | select(.mediaType == "application/vnd.silo.kernel.image.v1")] | length) == 1' >/dev/null; \
			oras manifest fetch-config --platform "$$platform" "$(OCI_IMAGE):$$revision_tag" | \
				jq -e --arg platform "$$platform" '(.platform.os + "/" + .platform.architecture) == $$platform' >/dev/null; \
		done
