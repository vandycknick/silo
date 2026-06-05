.PHONY: build
build:
	docker buildx build \
		--platform linux/arm64/v8 \
		--load -f Containerfile \
		--output type=tar,dest=./.dist/rootfs.tar .
