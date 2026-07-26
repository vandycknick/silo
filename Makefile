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
ifneq ($(filter $(KERNEL_OFFLINE),0 1),$(KERNEL_OFFLINE))
$(error KERNEL_OFFLINE must be 0 or 1)
endif

XTASK = CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo run --locked -p xtask --
KERNEL_ARGS = --reference "$(KERNEL_REFERENCE)"
ifneq ($(strip $(KERNEL_PATH)),)
KERNEL_ARGS += --path "$(abspath $(KERNEL_PATH))"
endif
ifeq ($(KERNEL_OFFLINE),1)
KERNEL_ARGS += --offline
endif

.PHONY: build stage cli vmmon netd krun agent init initramfs kernel fmt clippy test version-check

build:
	$(XTASK) build --profile "$(PROFILE)" $(KERNEL_ARGS)

stage:
	$(XTASK) stage --profile "$(PROFILE)" $(KERNEL_ARGS)

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
