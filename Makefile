.DEFAULT_GOAL := build

PROFILE ?= debug
ifeq ($(filter $(PROFILE),debug release),)
$(error PROFILE must be debug or release)
endif

TRACK ?= stable
CARGO_TARGET_DIR ?= $(CURDIR)/target
override CARGO_TARGET_DIR := $(abspath $(CARGO_TARGET_DIR))
export CARGO_TARGET_DIR

XTASK = CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo run --locked -p xtask --

.PHONY: build cli vmmon netd krun agent init initramfs kernel fmt clippy test version-check

build:
	$(XTASK) build --profile "$(PROFILE)"

cli vmmon netd krun agent init initramfs:
	$(XTASK) component $@ --profile "$(PROFILE)"

kernel:
	$(XTASK) kernel --track "$(TRACK)"

fmt:
	$(XTASK) fmt

clippy:
	$(XTASK) clippy

test:
	$(XTASK) test

version-check:
	$(XTASK) version-check
