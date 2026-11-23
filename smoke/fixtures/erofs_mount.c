#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

static void require(int ok, const char *operation) {
    if (ok) return;
    printf("SILO_EROFS_FAIL operation=%s errno=%d (%s)\n", operation, errno, strerror(errno));
    fflush(stdout);
    for (;;) pause();
}
static struct stat metadata(const char *path) {
    struct stat result;
    require(lstat(path, &result) == 0, path);
    return result;
}
static void payload(const char *path) {
    int fd = open(path, O_RDONLY);
    require(fd >= 0, "open payload");
    unsigned char bytes[4114];
    ssize_t length = read(fd, bytes, sizeof(bytes));
    require(length == 4113, "payload exact length");
    for (int i = 0; i < 4113; ++i)
        require(bytes[i] == (i * 17 + 3) % 251, "payload byte");
    close(fd);
}
static void rich(void) {
    payload("/lower/payload");
    payload("/lower/hardlink");
    payload("/lower/raw-\xff");
    struct stat first = metadata("/lower/payload"), second = metadata("/lower/hardlink");
    require(first.st_ino == second.st_ino && first.st_nlink == 2, "hardlink identity");
    struct stat meta = metadata("/lower/metadata");
    require(meta.st_uid == UINT32_MAX - 1 && meta.st_gid == UINT32_MAX - 2, "wide ownership");
    require((meta.st_mode & 07777) == 0640, "ACL mode");
    require(meta.st_mtim.tv_sec == 4294967297LL && meta.st_mtim.tv_nsec == 123456789, "extended timestamp");
    unsigned char value[64];
    require(getxattr("/lower/metadata", "user.empty", value, sizeof(value)) == 0, "empty xattr");
    require(getxattr("/lower/metadata", "user.raw", value, sizeof(value)) == 3 && value[0] == 0 && value[1] == 255 && value[2] == 1, "raw xattr");
    const unsigned char cap[20] = {1,0,0,2,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    require(getxattr("/lower/metadata", "security.capability", value, sizeof(value)) == 20 && !memcmp(value, cap, 20), "security capability");
    const char label[] = "system_u:object_r:container_file_t:s0";
    require(getxattr("/lower/metadata", "security.selinux", value, sizeof(value)) == (ssize_t)sizeof(label) && !memcmp(value, label, sizeof(label)), "security label");
    const unsigned char acl[44] = {2,0,0,0,1,0,6,0,255,255,255,255,2,0,4,0,77,0,0,0,4,0,4,0,255,255,255,255,16,0,4,0,255,255,255,255,32,0,0,0,255,255,255,255};
    require(getxattr("/lower/metadata", "system.posix_acl_access", value, sizeof(value)) == 44 && !memcmp(value, acl, 44), "access ACL");
    require(getxattr("/lower/a", "system.posix_acl_default", value, sizeof(value)) == 44 && !memcmp(value, acl, 44), "default ACL");
    meta = metadata("/lower/char");
    require(S_ISCHR(meta.st_mode) && major(meta.st_rdev) == 1 && minor(meta.st_rdev) == 3, "character device");
    meta = metadata("/lower/block");
    require(S_ISBLK(meta.st_mode) && major(meta.st_rdev) == 7 && minor(meta.st_rdev) == 0, "block device");
    require(S_ISFIFO(metadata("/lower/fifo").st_mode), "FIFO");
    require(S_ISSOCK(metadata("/lower/socket").st_mode), "socket");
    int fd = open("/lower/sparse", O_RDONLY);
    require(fd >= 0, "open sparse");
    unsigned char sparse[12289];
    require(read(fd, sparse, sizeof(sparse)) == 12288, "sparse exact length");
    for (int i = 0; i < 12288; ++i)
        require(sparse[i] == (i < 16 ? 0x5a : i == 8193 ? 0x7f : 0), "sparse and NULL chunk bytes");
    close(fd);
    struct file_handle *handle = calloc(1, sizeof(*handle) + 128);
    require(handle != NULL, "allocate export handle");
    handle->handle_bytes = 128;
    int mount_id;
    require(name_to_handle_at(AT_FDCWD, "/lower/payload", handle, &mount_id, 0) == 0, "encode export handle");
    int mountfd = open("/lower", O_RDONLY | O_DIRECTORY);
    require(mountfd >= 0, "open export mount descriptor");
    printf("EROFS_EXPORT_HANDLE mount_fd=%d type=%d bytes=%u\n", mountfd, handle->handle_type, handle->handle_bytes);
    fd = open_by_handle_at(mountfd, handle, O_RDONLY);
    require(fd >= 0, "decode export handle");
    require(read(fd, value, 1) == 1 && value[0] == 3, "export handle data");
    close(fd); close(mountfd); free(handle);
}
static void large(void) {
    int fd = open("/lower/large", O_RDONLY);
    require(fd >= 0, "open split large file");
    const uint64_t length = 2147491840ULL;
    require((uint64_t)metadata("/lower/large").st_size == length, "large file length");
    unsigned char buffer[65536];
    uint64_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        require(count > 0, "large file read");
        for (ssize_t i = 0; i < count; ++i) {
            uint64_t at = offset + (uint64_t)i;
            unsigned char expected = at < 5 ? "BEGIN"[at] : at >= length - 3 ? "END"[at - (length - 3)] : 0;
            require(buffer[i] == expected, "large split file byte");
        }
        offset += (uint64_t)count;
    }
    require(read(fd, buffer, 1) == 0, "large file EOF");
    close(fd);
}
static void indexed_overlay(void) {
    require(mount("/dev/vdb", "/upper", "ext4", 0, "") == 0, "mount upper");
    const char *options = "lowerdir=/lower,upperdir=/upper/upper,workdir=/upper/work,index=on,metacopy=off,redirect_dir=off";
    require(mount("overlay", "/merged", "overlay", 0, options) == 0, "mount indexed EROFS overlay");
    int fd = open("/merged/payload", O_WRONLY);
    unsigned char changed = 0xa5, observed;
    require(fd >= 0 && pwrite(fd, &changed, 1, 0) == 1 && fsync(fd) == 0, "indexed copy-up");
    close(fd);
    fd = open("/merged/hardlink", O_RDONLY);
    require(fd >= 0 && read(fd, &observed, 1) == 1 && observed == changed, "copy-up hardlink data");
    close(fd);
    require(metadata("/merged/payload").st_ino == metadata("/merged/hardlink").st_ino, "copy-up hardlink inode");
    require(umount("/merged") == 0 && umount("/upper") == 0, "clean overlay unmount");
    require(mount("/dev/vdb", "/upper", "ext4", 0, "") == 0, "remount upper");
    require(mount("overlay", "/merged", "overlay", 0, options) == 0, "remount indexed EROFS overlay");
    fd = open("/merged/hardlink", O_RDONLY);
    require(fd >= 0 && read(fd, &observed, 1) == 1 && observed == changed, "persistent indexed hardlink");
    close(fd);
    payload("/lower/payload");
    require(umount("/merged") == 0 && umount("/upper") == 0, "final clean unmount");
}
int main(void) {
    mkdir("/dev", 0755); mkdir("/proc", 0755); mkdir("/sys", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, "");
    int console = open("/dev/console", O_RDWR);
    if (console >= 0) { dup2(console, 1); dup2(console, 2); close(console); }
    setbuf(stdout, NULL);
    require(mount("proc", "/proc", "proc", 0, "") == 0, "mount proc");
    require(mount("sysfs", "/sys", "sysfs", 0, "") == 0, "mount sysfs");
    char command[4096] = {0};
    int fd = open("/proc/cmdline", O_RDONLY);
    require(fd >= 0 && read(fd, command, sizeof(command) - 1) > 0, "read kernel command line");
    close(fd);
    char serial[64] = {0};
    fd = open("/sys/block/vda/serial", O_RDONLY);
    require(fd >= 0 && read(fd, serial, sizeof(serial) - 1) > 0 && !strncmp(serial, "silo-root-lower", 15), "lower native block identity");
    close(fd);
    mkdir("/lower", 0755); mkdir("/upper", 0755); mkdir("/merged", 0755);
    require(mount("/dev/vda", "/lower", "erofs", MS_RDONLY, "") == 0, "mount EROFS over VMDK");
    struct statfs fs;
    require(statfs("/lower", &fs) == 0 && (unsigned long)fs.f_type == 0xe0f5e1e2UL, "EROFS filesystem magic");
    require(open("/lower/prohibited", O_CREAT | O_WRONLY, 0600) < 0 && errno == EROFS, "immutable lower");
    if (!strstr(command, "silo.erofs_fixture=empty")) {
        require(S_ISDIR(metadata("/lower/a/b").st_mode), "nested directory");
        require(metadata("/lower/a").st_nlink == 3, "directory link count");
        char target[64];
        require(readlink("/lower/link", target, sizeof(target)) == 10 && !memcmp(target, "a/../raw-\xff", 10), "raw symlink");
        require(metadata("/lower/empty").st_size == 0, "empty regular file");
    }
    if (strstr(command, "silo.erofs_fixture=rich") || strstr(command, "silo.erofs_fixture=many") || strstr(command, "silo.erofs_fixture=split")) {
        rich();
        if (strstr(command, "silo.erofs_fixture=split")) large();
        indexed_overlay();
    }
    require(umount("/lower") == 0, "unmount EROFS");
    puts("SILO_EROFS_PASS");
    for (;;) pause();
}
