#!/usr/bin/env bash
set -euo pipefail

ROOTFS="ArchLinuxARM-aarch64-latest.tar.gz"
BASE_URL="http://os.archlinuxarm.org/os"
KEY="68B3537F39A313B3E574D06777193F152BDBE6A6"

curl -fL -o "$ROOTFS" "$BASE_URL/$ROOTFS"
curl -fL -o "$ROOTFS.sig" "$BASE_URL/$ROOTFS.sig"

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT

gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "$KEY"
gpg --verify "$ROOTFS.sig" "$ROOTFS"
