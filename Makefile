GUEST_TARGET := aarch64-unknown-linux-musl
GUEST_BIN := $(CURDIR)/target/$(GUEST_TARGET)/release/bento-agent
GUEST_INIT_BIN := $(CURDIR)/target/$(GUEST_TARGET)/release/init
INITRAMFS_OUT := $(CURDIR)/target/resources/initramfs
BENTO_CONFIG := $(HOME)/.config/bento/config.yaml
ARCH ?= arm64
PROFILE ?= debug
RUST_HOST_TRIPLE := $(shell rustc -vV | awk '/host:/ { print $$2 }')
HOST_OS := $(shell uname -s)
KRUN_DEPS_DIR ?= $(CURDIR)/target/libs/krun/$(RUST_HOST_TRIPLE)
export KRUN_DEPS_DIR

ifeq ($(HOST_OS),Darwin)
HOST_WORKSPACE_EXCLUDES := --exclude bento-agent --exclude bento-init
HOST_BUILD_COMPONENTS := vmmon netd
else ifeq ($(HOST_OS),Linux)
HOST_WORKSPACE_EXCLUDES := --exclude bento-init --exclude bento-vz
HOST_BUILD_COMPONENTS := vmmon netd krun
else
HOST_WORKSPACE_EXCLUDES := --exclude bento-agent --exclude bento-init --exclude bento-vz
HOST_BUILD_COMPONENTS := vmmon netd
endif

ifeq ($(PROFILE),release)
CARGO_PROFILE_FLAGS := --release
TARGET_PROFILE_DIR := release
else ifeq ($(PROFILE),debug)
CARGO_PROFILE_FLAGS :=
TARGET_PROFILE_DIR := debug
else
$(error PROFILE must be debug or release)
endif

VMMON_BIN := target/$(TARGET_PROFILE_DIR)/vmmon
NETD_BIN := target/$(TARGET_PROFILE_DIR)/netd

ifeq ($(PROFILE),release)
GO_BUILD_FLAGS := -ldflags "-s -w"
else
GO_BUILD_FLAGS :=
endif

.PHONY: build-guest-agent
build-guest-agent:
	cargo zigbuild -p bento-agent --target $(GUEST_TARGET) --release
	mkdir -p "$(HOME)/.config/bento"
	printf "guest:\n  binary: \"%s\"\n" "$(GUEST_BIN)" > "$(BENTO_CONFIG)"
	@echo "Updated $(BENTO_CONFIG) -> $(GUEST_BIN)"

.PHONY: build-guest-init
build-guest-init:
	RUSTFLAGS="-C panic=abort" cargo zigbuild -p bento-init --target $(GUEST_TARGET) --release

.PHONY: build
build: $(HOST_BUILD_COMPONENTS)
	cargo build $(CARGO_PROFILE_FLAGS) -p bentoctl

.PHONY: clippy
clippy:
	cargo clippy --workspace --all-targets --all-features $(HOST_WORKSPACE_EXCLUDES)

.PHONY: test
test:
	cargo test --workspace --all-targets --all-features $(HOST_WORKSPACE_EXCLUDES)

.PHONY: build-libkrun
build-libkrun:
	scripts/build-libkrun-deps

.PHONY: vmmon
vmmon:
	cargo build $(CARGO_PROFILE_FLAGS) -p bento-vmmon
	runtime/bento-vmmon/scripts/sign-vmmon "$(VMMON_BIN)"

.PHONY: krun
krun:
	cargo build $(CARGO_PROFILE_FLAGS) -p bento-krun --features krun-bin --bin krun

.PHONY: netd
netd:
	@mkdir -p "target/$(TARGET_PROFILE_DIR)"
	cd net/bento-netd && go build $(GO_BUILD_FLAGS) -o "$(CURDIR)/$(NETD_BIN)" ./cmd/bento-netd

.PHONY: kernel
kernel:
	@test -n "$(TRACK)" || (echo "TRACK is required, use TRACK=stable|longterm|longterm5" && exit 1)
	@$(MAKE) -C resources/kernels kernel TRACK=$(TRACK) ARCH=$(ARCH)

.PHONY: initramfs
initramfs: build-guest-init
	@mkdir -p ./target/resources
	@if [ -d "$(INITRAMFS_OUT)" ]; then rm -rf "$(INITRAMFS_OUT)"; fi
	cargo run -p bento-initramfs -- --init "$(GUEST_INIT_BIN)" --out "$(INITRAMFS_OUT)"

.PHONY: rootfs
rootfs:
	@mkdir -p ./target/resources/rootfs
	@docker build -f resources/rootfs/Dockerfile -t rootfs .
	@docker run -it -v $(shell pwd)/target/resources/rootfs:/resources --privileged --cap-add=CAP_MKNOD rootfs
