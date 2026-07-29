# Linux Release Environment

`toolchains.toml` is the release-toolchain authority. The Ubuntu 24.04 OCI
index digest selects native amd64 and arm64 images with glibc 2.39. The
container verifies every downloaded bootstrap/archive checksum and its installed
tool versions before it can be used.

Build a native release environment with Docker Buildx:

```text
TARGETARCH=amd64 docker buildx bake --load -f release/docker-bake.hcl silo-release
TARGETARCH=arm64 docker buildx bake --load -f release/docker-bake.hcl silo-release
```

On Linux, `make PROFILE=release`, `make stage PROFILE=release`,
`make verify-runtime PROFILE=release`, `make archive`, and
`make verify-archive` invoke the matching native container automatically. They
fail rather than falling back to an ambient/Nix toolchain. The image entrypoint
remains `make` for CI builders that need to run it directly.
