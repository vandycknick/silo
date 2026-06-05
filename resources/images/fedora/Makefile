.PHONY: build
build:
	docker buildx build \
		--platform linux/arm64/v8 \
		--load -f Containerfile \
		--output type=tar,dest=./.dist/rootfs.tar .

.PHONY: pack-ext4
pack-ext4:
	docker run -v $(PWD)/.dist:/assets \
		ghcr.io/vandycknick/image-builder:latest --format=raw --type=ext4 --size=3G /assets/rootfs.tar /assets/rootfs.img
