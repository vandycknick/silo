# Resources

This directory holds guest OS build inputs and related assets.

- `resources/kernels/` contains kernel configs, track metadata, and kernel build orchestration
- `guest/bento-init/` builds the minimal initramfs `/init` payload
- `common/bento-initramfs/` packages `/init` into the shared gzip-compressed newc initramfs archive
- `resources/rootfs/` contains full root filesystem build inputs

Most generated outputs are written to `target/resources/`, while VM-built kernel artifacts are exported to `target/kernels/`.
