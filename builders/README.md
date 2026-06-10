- [ArchBoot](https://archboot.com/#releases)

# What to run

Create an image-backed VM with `bentoctl create <ref> <name>` using a Linux image that already
provides the kernel, initramfs, and writable root disk, then run the following commands inside the
guest.

```sh
./target/release/bentoctl create <image-ref> archboot \
    --cpus 2 \
    --memory 2gb
```

# Inside the VM run the following commands:

```sh
rm -f /var/lib/pacman/sync/*.db
pacman -Syy

mkfs.btrfs -f /dev/vda
mount /dev/vda /mnt

btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@home
umount /mnt

mount -o subvol=@ /dev/vda /mnt
mkdir /mnt/home
mount -o subvol=@home /dev/vda /mnt/home

pacman -Syy arch-install-scripts
pacstrap /mnt base systemd btrfs-progs ca-certificates ca-certificates-utils openssl openssh sudo socat vim

genfstab -U /mnt >> /mnt/etc/fstab
```

Chroot inside Linux VM.

```sh
arch-chroot /mnt

systemctl enable systemd-networkd.service
systemctl enable systemd-resolved.service
systemctl enable systemd-timesyncd.service
systemctl enable sshd.service

sudo rm -f /etc/resolv.conf
sudo ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

passwd -d root

echo archlinux > /etc/hostname

truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

exit
```

Cleanup

```sh
umount -R /mnt
```

Register the resulting root disk

```sh
mkdir -p ~/.local/share/bento/images/sha256-abc123
cp ~/.local/share/bento/instances/<archboot-id>/rootfs.img ~/.local/share/bento/images/sha256-abc123/rootfs.img

cat > ~/.local/share/bento/images/registry.json <<'JSON'
{
  "version": 1,
  "images": {
    "ghcr.io/vandycknick/archlinux:latest": "sha256-abc123/rootfs.img"
  }
}
JSON
```

# DNS management on Linux distros

## TL;DR for this image

This image uses `systemd-networkd` + `systemd-resolved`. The recommended setup is:

```sh
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

That makes apps that read `/etc/resolv.conf` talk to the local `systemd-resolved` stub (`127.0.0.53`), while `systemd-resolved` manages upstream DNS from DHCP/static config.

## How common Linux distros handle DNS

- **Arch Linux**
    - Common modern setup is `systemd-resolved` in stub mode.
    - `/etc/resolv.conf` should be a symlink to `/run/systemd/resolve/stub-resolv.conf`.
    - If `/etc/resolv.conf` is a regular file, `resolvectl status` shows `resolv.conf mode: foreign`, and name resolution can break for tools that read `resolv.conf` directly.

- **Fedora**
    - `systemd-resolved` is enabled by default in modern releases.
    - `/etc/resolv.conf` is typically managed as a stub symlink.
    - DNS routing (including split DNS with VPNs) is handled by `systemd-resolved`.

- **Ubuntu**
    - Also uses `systemd-resolved` by default in modern releases.
    - Common/default behavior is `/etc/resolv.conf` pointing at a `systemd-resolved`-managed resolver file.
    - Stub-resolver pattern is the standard path for compatibility with apps that parse `resolv.conf`.

- **Debian**
    - More mixed depending on install profile and admin choice.
    - Can run classic static `/etc/resolv.conf`, `resolvconf`, or `systemd-resolved`.
    - If `systemd-resolved` is used, symlinked resolver files are the expected pattern.

## Practical note for image builds

In some install/chroot flows, `/etc/resolv.conf` can be bind-mounted from the host, so creating the symlink from inside chroot may fail. If that happens, create the symlink from outside chroot against the target root (for example `/mnt/etc/resolv.conf`).
