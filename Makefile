.DEFAULT_GOAL := build

PROFILE ?= debug
ifeq ($(filter $(PROFILE),debug release),)
$(error PROFILE must be debug or release)
endif

CARGO_TARGET_DIR ?= $(CURDIR)/target
override CARGO_TARGET_DIR := $(abspath $(CARGO_TARGET_DIR))
export CARGO_TARGET_DIR

KERNEL_REFERENCE ?= ghcr.io/vandycknick/silo/kernel:stable
KERNEL_PATH ?=
KERNEL_OFFLINE ?= 0
KERNEL_REFRESH ?= 0
ifneq ($(filter $(KERNEL_OFFLINE),0 1),$(KERNEL_OFFLINE))
$(error KERNEL_OFFLINE must be 0 or 1)
endif
ifneq ($(filter $(KERNEL_REFRESH),0 1),$(KERNEL_REFRESH))
$(error KERNEL_REFRESH must be 0 or 1)
endif

XTASK = CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo run --locked -p xtask --
KERNEL_ARGS = --reference "$(KERNEL_REFERENCE)"
ifneq ($(strip $(KERNEL_PATH)),)
KERNEL_ARGS += --path "$(abspath $(KERNEL_PATH))"
endif
ifeq ($(KERNEL_OFFLINE),1)
KERNEL_ARGS += --offline
endif
ifeq ($(KERNEL_REFRESH),1)
KERNEL_ARGS += --refresh
endif

.PHONY: build stage verify-runtime archive verify-archive app package install release-linux cli vmmon netd krun agent init initramfs kernel fmt clippy test version-check

build:
	$(XTASK) build --profile "$(PROFILE)" $(KERNEL_ARGS)

stage:
	$(XTASK) stage --profile "$(PROFILE)" $(KERNEL_ARGS)

verify-runtime:
	$(XTASK) verify-runtime --profile "$(PROFILE)"

archive:
	$(XTASK) archive $(KERNEL_ARGS)

verify-archive:
	$(XTASK) verify-archive

BUILD_NUMBER ?=
DEVELOPER_ID_APPLICATION ?=
APP_ARGS = $(if $(strip $(BUILD_NUMBER)),--build-number "$(BUILD_NUMBER)") $(if $(strip $(DEVELOPER_ID_APPLICATION)),--developer-id-application "$(DEVELOPER_ID_APPLICATION)")

app:
	$(XTASK) app $(APP_ARGS) $(KERNEL_ARGS)

package:
	$(XTASK) package $(APP_ARGS) $(KERNEL_ARGS)

APPDIR ?= /Applications
BINDIR ?= /usr/local/bin
install:
	$(XTASK) install --appdir "$(APPDIR)" --bindir "$(BINDIR)" $(APP_ARGS) $(KERNEL_ARGS)

RELEASE_UNAME := $(shell uname -m)
ifeq ($(RELEASE_UNAME),x86_64)
RELEASE_ARCH ?= amd64
else ifeq ($(RELEASE_UNAME),aarch64)
RELEASE_ARCH ?= arm64
else
RELEASE_ARCH ?= $(RELEASE_UNAME)
endif
ifeq ($(filter $(RELEASE_ARCH),amd64 arm64),)
$(error RELEASE_ARCH must resolve to amd64 or arm64)
endif

release-linux:
	TARGETARCH="$(RELEASE_ARCH)" docker buildx bake --load -f release/docker-bake.hcl silo-release

cli vmmon netd krun agent init initramfs:
	$(XTASK) component $@ --profile "$(PROFILE)"

kernel:
	$(XTASK) kernel $(KERNEL_ARGS)

fmt:
	$(XTASK) fmt

clippy:
	$(XTASK) clippy

test:
	$(XTASK) test

version-check:
	$(XTASK) version-check
