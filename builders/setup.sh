#!/usr/bin/env bash
set -eou pipefail

echo "Syncing pacman database."
rm -f /var/lib/pacman/sync/*.db
pacman -Syy
# pacman -Syy arch-install-scripts

if ! findmnt -rn -S /dev/vda > /dev/null; then
    echo "/dev/vda not mounted — formatting and mounting"

    mkfs.btrfs -f /dev/vda
    mount /dev/vda /mnt

    btrfs subvolume create /mnt/@
    btrfs subvolume create /mnt/@home
    umount /mnt

    mount -o subvol=@ /dev/vda /mnt
    mkdir /mnt/home
    mount -o subvol=@home /dev/vda /mnt/home
else
    echo "/dev/vda already mounted"
fi

pacstrap /mnt base systemd btrfs-progs ca-certificates ca-certificates-utils openssl openssh sudo socat vim

genfstab -U /mnt >> /mnt/etc/fstab

echo
echo "Starting arch-chroot"
arch-chroot /mnt /bin/bash <<'CHROOT'
set -euo pipefail

systemctl enable systemd-networkd.service
systemctl enable systemd-resolved.service
systemctl enable systemd-timesyncd.service
systemctl enable sshd.service

ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true

passwd -d root

echo archlinux > /etc/hostname

truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

exit
CHROOT

umount -R /mnt
