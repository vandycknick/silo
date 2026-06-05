.PHONY: build
build:
	docker buildx build \
		--platform linux/arm64/v8 \
		--load -f Containerfile \
		--output type=tar,dest=./.dist/rootfs.tar .

.PHONY: pack-btrfs
pack-btrfs:
	docker run -v $(PWD)/.dist:/assets \
		ghcr.io/vandycknick/image-builder:latest --format=raw --type=btrfs --size=3G /assets/rootfs.tar /assets/rootfs.img
