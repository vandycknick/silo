use bento_ext4::Formatter;
use bento_ext4::constants::{file_mode, make_mode};
use std::io::Cursor;
use std::path::Path;
use std::process::Command;

fn workspace_tempdir() -> tempfile::TempDir {
    let target_tmp = std::env::current_dir()
        .unwrap()
        .join("target/bento-ext4-tests");
    std::fs::create_dir_all(&target_tmp).unwrap();
    tempfile::Builder::new()
        .prefix("e2fsprogs-")
        .tempdir_in(target_tmp)
        .unwrap()
}

fn create_test_image(dir: &Path) {
    let image = dir.join("rootfs.img");

    let mut formatter = Formatter::new(&image, 4096, 512 * 1024 * 1024).unwrap();
    formatter
        .create(
            "/etc",
            make_mode(file_mode::S_IFDIR, 0o755),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    let content = vec![0x5Au8; 2 * 1024 * 1024];
    let mut reader = Cursor::new(content);
    formatter
        .create(
            "/etc/big-file",
            make_mode(file_mode::S_IFREG, 0o644),
            None,
            None,
            Some(&mut reader),
            None,
            None,
            None,
        )
        .unwrap();
    formatter.close().unwrap();
}

#[test]
#[ignore = "requires Docker and network access for Fedora e2fsprogs"]
fn e2fsprogs_validates_and_resizes_generated_image() {
    let dir = workspace_tempdir();
    create_test_image(dir.path());

    let mount = format!("{}:/work", dir.path().display());
    let script = r#"
set -eu
dnf -y install e2fsprogs >/dev/null
features=$(tune2fs -l /work/rootfs.img | awk -F: '/Filesystem features/ { print $2 }')
case "$features" in
  *resize_inode*) ;;
  *) echo "missing resize_inode in: $features" >&2; exit 1 ;;
esac
case "$features" in
  *sparse_super2*) echo "unexpected sparse_super2 in: $features" >&2; exit 1 ;;
esac
case "$features" in
  *sparse_super*) ;;
  *) echo "missing sparse_super in: $features" >&2; exit 1 ;;
esac
e2fsck -fn /work/rootfs.img
truncate -s 1G /work/rootfs.img
e2fsck -f -y /work/rootfs.img >/dev/null
resize2fs /work/rootfs.img >/tmp/resize2fs.log
e2fsck -fn /work/rootfs.img
"#;

    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            "fedora:45",
            "sh",
            "-lc",
            script,
        ])
        .status()
        .expect("failed to run Docker e2fsprogs validation");

    assert!(status.success(), "Docker e2fsprogs validation failed");
}

#[test]
#[ignore = "requires privileged Docker with loop-device mount support"]
fn privileged_docker_online_resize_generated_image() {
    let dir = workspace_tempdir();
    create_test_image(dir.path());

    let mount = format!("{}:/work", dir.path().display());
    let script = r#"
set -eu
dnf -y install e2fsprogs util-linux >/dev/null
test -f /work/rootfs.img
if ! losetup -f >/dev/null 2>&1; then
  echo "skipping online resize validation: no loop device available" >&2
  exit 0
fi
mkdir -p /mnt/root
if ! loop=$(losetup --find --show /work/rootfs.img); then
  echo "skipping online resize validation: cannot attach loop device" >&2
  exit 0
fi
cleanup() {
  set +e
  umount /mnt/root >/dev/null 2>&1
  losetup -d "$loop" >/dev/null 2>&1
}
trap cleanup EXIT
mount "$loop" /mnt/root
before=$(df -B1 --output=size /mnt/root | tail -n 1)
truncate -s 1G /work/rootfs.img
losetup -c "$loop"
resize2fs "$loop"
after=$(df -B1 --output=size /mnt/root | tail -n 1)
test "$after" -gt "$before"
umount /mnt/root
losetup -d "$loop"
trap - EXIT
e2fsck -fn /work/rootfs.img
"#;

    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--privileged",
            "-v",
            &mount,
            "fedora:45",
            "sh",
            "-lc",
            script,
        ])
        .status()
        .expect("failed to run privileged Docker online-resize validation");

    assert!(status.success(), "privileged Docker online resize failed");
}
