ARCH ?= amd64
IMAGE ?= ghcr.io/vandycknick/silo/system:dev
SOURCE_REVISION ?= $(shell git rev-parse HEAD)
BUILD_NETWORK ?= default

ifeq ($(ARCH),amd64)
RUST_TARGET := x86_64-unknown-linux-musl
DOCKER_PLATFORM := linux/amd64
else ifeq ($(ARCH),arm64)
RUST_TARGET := aarch64-unknown-linux-musl
DOCKER_PLATFORM := linux/arm64/v8
else
$(error ARCH must be amd64 or arm64)
endif

ROOT := ../../..
CARGO_TARGET_DIR := $(abspath $(ROOT)/target)
PORTD := $(ROOT)/target/$(RUST_TARGET)/release/silo-portd
HOST_ARCH := $(shell uname -m)

.PHONY: portd build archive rootfs verify clean
portd:
	@test "$(ARCH):$(HOST_ARCH)" = "amd64:x86_64" -o "$(ARCH):$(HOST_ARCH)" = "arm64:aarch64" || \
		{ printf 'ARCH=%s requires a native matching build host (found %s)\n' "$(ARCH)" "$(HOST_ARCH)" >&2; exit 1; }
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo zigbuild --locked \
		--manifest-path $(ROOT)/Cargo.toml -p silo-portd --target $(RUST_TARGET) --release
	mkdir -p .dist
	cp $(PORTD) .dist/silo-portd
	@file .dist/silo-portd | grep -q 'statically linked\|static-pie linked'
	@if test "$(ARCH)" = amd64; then file .dist/silo-portd | grep -q 'x86-64'; \
	else file .dist/silo-portd | grep -q 'ARM aarch64'; fi

build: portd
	docker buildx build --platform $(DOCKER_PLATFORM) --load \
		--network $(BUILD_NETWORK) \
		--build-arg SOURCE_REVISION=$(SOURCE_REVISION) \
		--tag $(IMAGE) -f Containerfile .

archive: portd
	mkdir -p .dist
	docker buildx build --platform $(DOCKER_PLATFORM) \
		--network $(BUILD_NETWORK) \
		--build-arg SOURCE_REVISION=$(SOURCE_REVISION) \
		--tag $(IMAGE) --output type=docker,dest=.dist/system-image.tar \
		--metadata-file .dist/build-metadata.json -f Containerfile .

rootfs: portd
	mkdir -p .dist
	docker buildx build --platform $(DOCKER_PLATFORM) \
		--network $(BUILD_NETWORK) \
		--build-arg SOURCE_REVISION=$(SOURCE_REVISION) \
		--output type=tar,dest=.dist/rootfs.tar -f Containerfile .

verify:
	sh ./verify.sh

clean:
	rm -rf .dist
