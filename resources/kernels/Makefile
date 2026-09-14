HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),x86_64)
override KERNEL_ARCH := x86_64
else ifneq ($(filter arm64 aarch64,$(HOST_ARCH)),)
override KERNEL_ARCH := arm64
endif

TRACK ?= stable
KERNEL_PROFILE ?= workload
BUILD_REVISION ?= unknown
BUILD_CREATED ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
SOURCE_DATE_EPOCH ?= 0
KBUILD_BUILD_TIMESTAMP ?= @$(SOURCE_DATE_EPOCH)
KBUILD_BUILD_VERSION ?= 1
KBUILD_BUILD_USER ?= silo
KBUILD_BUILD_HOST ?= silo
export SOURCE_DATE_EPOCH KBUILD_BUILD_TIMESTAMP KBUILD_BUILD_VERSION KBUILD_BUILD_USER KBUILD_BUILD_HOST

ifeq ($(filter $(KERNEL_PROFILE),workload rprobe),)
$(error unsupported KERNEL_PROFILE '$(KERNEL_PROFILE)'; expected workload or rprobe)
endif

ifeq ($(KERNEL_PROFILE),rprobe)
ifneq ($(KERNEL_ARCH),arm64)
$(error KERNEL_PROFILE=rprobe only supports native ARM64 Linux builders)
endif
endif

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
KERNEL_TARBALL ?= $(CACHE_ROOT)/downloads/linux-$(TRACK_VERSION).tar.xz
CONFIG_VALIDATOR ?= $(RESOURCE_ROOT)/kernels/scripts/validate-config.sh
OCI_PACKAGER ?= $(RESOURCE_ROOT)/kernels/scripts/package-oci.sh
OCI_VALIDATOR ?= $(RESOURCE_ROOT)/kernels/scripts/validate-oci.sh
SOURCE_DERIVER ?= $(RESOURCE_ROOT)/kernels/scripts/derive-source.sh
SOURCE_FETCHER ?= $(RESOURCE_ROOT)/kernels/scripts/fetch-source.sh
PRISTINE_PREPARER ?= $(RESOURCE_ROOT)/kernels/scripts/prepare-pristine.sh
WORKLOAD_EXPORTER ?= $(RESOURCE_ROOT)/kernels/scripts/export-workload-oci.sh
INPUT_KEYER ?= $(RESOURCE_ROOT)/kernels/scripts/kernel-input-key.sh
IDENTITY_TEST ?= $(RESOURCE_ROOT)/kernels/scripts/test-profile-isolation.sh
OCI_PROFILE_TEST ?= $(RESOURCE_ROOT)/kernels/scripts/test-oci-profiles.sh
SOURCE_DERIVATION_TEST ?= $(RESOURCE_ROOT)/kernels/scripts/test-source-derivation.sh
CACHE_OWNERSHIP_TEST ?= $(RESOURCE_ROOT)/kernels/scripts/test-cache-ownership.sh
WORKLOAD_CONFIG_FRAGMENTS := \
	$(RESOURCE_ROOT)/kernels/configs/common.config \
	$(RESOURCE_ROOT)/kernels/configs/$(KERNEL_ARCH).config \
	$(wildcard $(RESOURCE_ROOT)/kernels/configs/compat/$(TRACK).config)
RPROBE_CONFIG_FRAGMENTS := \
	$(RESOURCE_ROOT)/kernels/configs/rprobe.common.config \
	$(RESOURCE_ROOT)/kernels/configs/rprobe.arm64.config
WORKLOAD_PATCHES ?=
RPROBE_PATCHES ?=
CONFIG_FRAGMENTS := $($(shell printf '%s' "$(KERNEL_PROFILE)" | tr '[:lower:]' '[:upper:]')_CONFIG_FRAGMENTS)
PATCHES := $($(shell printf '%s' "$(KERNEL_PROFILE)" | tr '[:lower:]' '[:upper:]')_PATCHES)
SOURCE_KEY := sha256-$(TRACK_SHA256)
PATCH_KEY := $(shell "$(INPUT_KEYER)" patches $(PATCHES))
CONFIG_KEY := $(shell "$(INPUT_KEYER)" config $(CONFIG_FRAGMENTS))
ifeq ($(PATCH_KEY),)
$(error invalid patch inputs; paths containing whitespace are unsupported)
endif
ifeq ($(CONFIG_KEY),)
$(error invalid config inputs; paths containing whitespace are unsupported)
endif
sh_quote = '$(subst ','"'"',$(1))'
BUILD_INPUT_KEY := sha256-$(shell printf '%s\0' \
	$(call sh_quote,CC=$(CC)) $(call sh_quote,LD=$(LD)) $(call sh_quote,AR=$(AR)) \
	$(call sh_quote,NM=$(NM)) $(call sh_quote,STRIP=$(STRIP)) $(call sh_quote,OBJCOPY=$(OBJCOPY)) \
	$(call sh_quote,OBJDUMP=$(OBJDUMP)) $(call sh_quote,READELF=$(READELF)) $(call sh_quote,HOSTCC=$(HOSTCC)) \
	$(call sh_quote,HOSTCXX=$(HOSTCXX)) $(call sh_quote,PAHOLE=$(PAHOLE)) $(call sh_quote,RUSTC=$(RUSTC)) \
	$(call sh_quote,BINDGEN=$(BINDGEN)) $(call sh_quote,LLVM=$(LLVM)) $(call sh_quote,LLVM_IAS=$(LLVM_IAS)) \
	$(call sh_quote,CROSS_COMPILE=$(CROSS_COMPILE)) $(call sh_quote,KCFLAGS=$(KCFLAGS)) \
	$(call sh_quote,KCPPFLAGS=$(KCPPFLAGS)) $(call sh_quote,KAFLAGS=$(KAFLAGS)) \
	$(call sh_quote,KRUSTFLAGS=$(KRUSTFLAGS)) $(call sh_quote,LDFLAGS=$(LDFLAGS)) \
	$(call sh_quote,KBUILD_LDFLAGS=$(KBUILD_LDFLAGS)) $(call sh_quote,HOSTCFLAGS=$(HOSTCFLAGS)) \
	$(call sh_quote,HOSTCXXFLAGS=$(HOSTCXXFLAGS)) $(call sh_quote,HOSTLDFLAGS=$(HOSTLDFLAGS)) \
	$(call sh_quote,SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)) $(call sh_quote,KBUILD_BUILD_TIMESTAMP=$(KBUILD_BUILD_TIMESTAMP)) \
	$(call sh_quote,KBUILD_BUILD_VERSION=$(KBUILD_BUILD_VERSION)) $(call sh_quote,KBUILD_BUILD_USER=$(KBUILD_BUILD_USER)) \
	$(call sh_quote,KBUILD_BUILD_HOST=$(KBUILD_BUILD_HOST)) $(call sh_quote,LOCALVERSION=$(LOCALVERSION)) \
	| sha256sum | cut -d' ' -f1)
TOOLCHAIN_KEY := sha256-$(shell { $(CC) --version 2>&1; $(LD) --version 2>&1; $(MAKE) --version 2>&1; printf '%s\n' "$(BUILD_INPUT_KEY)"; } | sha256sum | cut -d' ' -f1)
TOOLCHAIN_COMPILER := $(shell $(CC) --version 2>&1 | sed -n '1p')
TOOLCHAIN_LINKER := $(shell $(LD) --version 2>&1 | sed -n '1p')
IDENTITY_DIGEST := $(shell printf '%s\n' "$(KERNEL_PROFILE)" "$(KERNEL_ARCH)" "$(TRACK)" "$(TRACK_VERSION)" "$(SOURCE_KEY)" "$(PATCH_KEY)" "$(CONFIG_KEY)" "$(TOOLCHAIN_KEY)" | sha256sum | cut -d' ' -f1)
KERNEL_IDENTITY := $(KERNEL_PROFILE)-$(KERNEL_ARCH)-sha256-$(IDENTITY_DIGEST)
PRISTINE_SOURCE_DIR ?= $(CACHE_ROOT)/pristine/$(SOURCE_KEY)/linux-$(TRACK_VERSION)
PRISTINE_SOURCE_CHECKSUM := $(PRISTINE_SOURCE_DIR)/.silo-kernel-pristine
KERNEL_SOURCE_DIR ?= $(CACHE_ROOT)/source/$(KERNEL_IDENTITY)/linux-$(TRACK_VERSION)
KERNEL_SOURCE_CHECKSUM := $(KERNEL_SOURCE_DIR)/.silo-kernel-source-identity
KERNEL_BUILD_DIR ?= $(CACHE_ROOT)/build/$(KERNEL_IDENTITY)
KERNEL_CANONICAL_OCI_LAYOUT ?= $(TARGET_ROOT)/kernels/.canonical/$(KERNEL_PROFILE)/$(TRACK)/$(KERNEL_ARCH)/$(KERNEL_IDENTITY)
KERNEL_CANONICAL_OCI_REFERENCE ?= $(KERNEL_PROFILE)-$(TRACK_VERSION)-sha256-$(IDENTITY_DIGEST)
ifeq ($(KERNEL_PROFILE),workload)
KERNEL_OCI_LAYOUT ?= $(TARGET_ROOT)/kernels/$(TRACK)/$(KERNEL_ARCH)
KERNEL_OCI_REFERENCE ?= $(TRACK_VERSION)
else
KERNEL_OCI_LAYOUT ?= $(KERNEL_CANONICAL_OCI_LAYOUT)
KERNEL_OCI_REFERENCE ?= $(KERNEL_CANONICAL_OCI_REFERENCE)
endif
MINICONFIG := $(KERNEL_BUILD_DIR)/.miniconfig
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2)

.PHONY: kernel-config
kernel-config:
	@mkdir -p "$(dir $(KERNEL_TARBALL))" "$(dir $(PRISTINE_SOURCE_DIR))" "$(dir $(KERNEL_SOURCE_DIR))" "$(KERNEL_BUILD_DIR)"
	@"$(SOURCE_FETCHER)" "$(KERNEL_SOURCE_URL)" "$(TRACK_SHA256)" "$(KERNEL_TARBALL)" "$(CACHE_ROOT)/downloads"
	@"$(PRISTINE_PREPARER)" "$(KERNEL_TARBALL)" "$(TRACK_SHA256)" "$(PRISTINE_SOURCE_DIR)" "$(CACHE_ROOT)/pristine"
	@if [ ! -f "$(KERNEL_SOURCE_DIR)/Makefile" ] || [ "$$(cat "$(KERNEL_SOURCE_CHECKSUM)" 2>/dev/null)" != "$(KERNEL_IDENTITY)" ]; then \
		"$(SOURCE_DERIVER)" "$(TRACK_SHA256)" "$(PRISTINE_SOURCE_DIR)" \
			"$(KERNEL_SOURCE_DIR)" "$(CACHE_ROOT)/source" "$(KERNEL_IDENTITY)" $(PATCHES); \
	fi
	@KCONFIG_CONFIG="$(MINICONFIG)" "$(KERNEL_SOURCE_DIR)/scripts/kconfig/merge_config.sh" \
		-m -s $(CONFIG_FRAGMENTS)
	@if [ "$(KERNEL_PROFILE)" = rprobe ]; then KCONFIG_WERROR=1; export KCONFIG_WERROR; fi; \
		KCONFIG_WARN_UNKNOWN_SYMBOLS=1 KCONFIG_WARN_CHANGED_INPUT=1 \
		$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		KCONFIG_ALLCONFIG="$(MINICONFIG)" alldefconfig
	@if ! "$(CONFIG_VALIDATOR)" "$(KERNEL_BUILD_DIR)/.config" $(CONFIG_FRAGMENTS); then \
		if [ "$(TRACK)" = stable ] || [ "$(KERNEL_PROFILE)" = rprobe ]; then exit 1; fi; \
		printf 'warning: %s/%s config differs from the stable miniconfig contract (best effort)\n' "$(TRACK)" "$(KERNEL_ARCH)" >&2; \
	fi

.PHONY: kernel
kernel: kernel-config
	@$(MAKE) -C "$(KERNEL_SOURCE_DIR)" O="$(KERNEL_BUILD_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		-j"$(JOBS)" "$(KERNEL_BUILD_TARGET)"
	@KERNEL_BUILD_DIR="$(KERNEL_BUILD_DIR)" \
		KERNEL_ARCH="$(KERNEL_ARCH)" \
		KERNEL_PROFILE="$(KERNEL_PROFILE)" \
		KERNEL_IDENTITY="$(KERNEL_IDENTITY)" \
		KERNEL_OCI_LAYOUT="$(KERNEL_CANONICAL_OCI_LAYOUT)" \
		KERNEL_OCI_REFERENCE="$(KERNEL_CANONICAL_OCI_REFERENCE)" \
		KERNEL_OCI_ROOT="$(TARGET_ROOT)/kernels/.canonical" \
		KERNEL_REPO_ROOT="$(REPO_ROOT)" \
		KERNEL_PRISTINE_ROOT="$(CACHE_ROOT)/pristine" \
		KERNEL_TRACK="$(TRACK)" \
		KERNEL_VERSION="$(TRACK_VERSION)" \
		KERNEL_SOURCE_URL="$(KERNEL_SOURCE_URL)" \
		KERNEL_SOURCE_SHA256="$(TRACK_SHA256)" \
		KERNEL_SOURCE_KEY="$(SOURCE_KEY)" \
		KERNEL_PATCH_KEY="$(PATCH_KEY)" \
		KERNEL_CONFIG_KEY="$(CONFIG_KEY)" \
		KERNEL_TOOLCHAIN_KEY="$(TOOLCHAIN_KEY)" \
		KERNEL_BUILD_INPUT_KEY="$(BUILD_INPUT_KEY)" \
		KERNEL_COMPILER="$(TOOLCHAIN_COMPILER)" \
		KERNEL_LINKER="$(TOOLCHAIN_LINKER)" \
		BUILD_REVISION="$(BUILD_REVISION)" \
		BUILD_CREATED="$(BUILD_CREATED)" \
		"$(OCI_PACKAGER)"
	@"$(OCI_VALIDATOR)" "$(KERNEL_CANONICAL_OCI_LAYOUT)" "$(KERNEL_CANONICAL_OCI_REFERENCE)" "$(KERNEL_PROFILE)"
	@if [ "$(KERNEL_PROFILE)" = workload ]; then \
		"$(WORKLOAD_EXPORTER)" "$(KERNEL_CANONICAL_OCI_LAYOUT)" "$(KERNEL_CANONICAL_OCI_REFERENCE)" \
			"$(KERNEL_OCI_LAYOUT)" "$(KERNEL_OCI_REFERENCE)" "$(TARGET_ROOT)/kernels" \
			"$(KERNEL_IDENTITY)" "$(OCI_VALIDATOR)"; \
	fi
	@printf 'Created OCI kernel artifact %s:%s\n' "$(KERNEL_OCI_LAYOUT)" "$(KERNEL_OCI_REFERENCE)"

.PHONY: kernel-version
kernel-version:
	@printf '%s\n' "$(TRACK_VERSION)"

.PHONY: kernel-architecture
kernel-architecture:
	@printf '%s\n' "$(KERNEL_ARCH)"

.PHONY: kernel-identities
kernel-identities:
	@printf 'profile=%s\narchitecture=%s\nfragments=%s\nsource=%s\npatches=%s\nconfig=%s\nbuild_inputs=%s\ntoolchain=%s\ncompiler=%s\nlinker=%s\nidentity=%s\nsource_dir=%s\nbuild_dir=%s\ncanonical_output=%s\ncanonical_reference=%s\noutput=%s\nreference=%s\n' \
		"$(KERNEL_PROFILE)" "$(KERNEL_ARCH)" "$(CONFIG_FRAGMENTS)" "$(SOURCE_KEY)" "$(PATCH_KEY)" "$(CONFIG_KEY)" "$(BUILD_INPUT_KEY)" "$(TOOLCHAIN_KEY)" "$(TOOLCHAIN_COMPILER)" "$(TOOLCHAIN_LINKER)" \
		"$(KERNEL_IDENTITY)" "$(KERNEL_SOURCE_DIR)" "$(KERNEL_BUILD_DIR)" "$(KERNEL_CANONICAL_OCI_LAYOUT)" "$(KERNEL_CANONICAL_OCI_REFERENCE)" "$(KERNEL_OCI_LAYOUT)" "$(KERNEL_OCI_REFERENCE)"

.PHONY: test-kernel-resources
test-kernel-resources:
	@"$(IDENTITY_TEST)" "$(CURDIR)"
	@"$(SOURCE_DERIVATION_TEST)" "$(CURDIR)"
	@"$(CACHE_OWNERSHIP_TEST)" "$(CURDIR)"
	@"$(OCI_PROFILE_TEST)" "$(CURDIR)"

.PHONY: publish
publish:
	@if [ "$(KERNEL_PROFILE)" != workload ]; then \
		printf 'KERNEL_PROFILE=%s is local-only and cannot be published\n' "$(KERNEL_PROFILE)" >&2; \
		exit 1; \
	fi
	@TRACK="$(TRACK)" KERNEL_PROFILE="$(KERNEL_PROFILE)" "$(RESOURCE_ROOT)/kernels/scripts/publish-oci.sh"
