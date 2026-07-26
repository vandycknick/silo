# Linux Release Environment

`toolchains.toml` is the release-toolchain lock record. The Ubuntu 24.04 OCI
index digest selects native amd64 and arm64 images with glibc 2.39. The container
installs only the recorded Rust, Go, Zig, and cargo-zigbuild versions.

Build a native release environment with Docker Buildx:

```text
docker buildx bake -f release/docker-bake.hcl --set silo-release.platforms=linux/amd64 silo-release
docker buildx bake -f release/docker-bake.hcl --set silo-release.platforms=linux/arm64 silo-release
```

The image entrypoint is `make`; mount a checkout at `/workspace` when running it
to execute `PROFILE=release`, `stage`, and `verify-runtime` on a native builder.
