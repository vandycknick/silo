#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static void require(int ok, const char *operation) {
    if (ok) return;
    printf("SILO_VMDK_MAPPING_FAIL operation=%s errno=%d\n", operation, errno);
    fflush(stdout);
    for (;;) pause();
}

int main(void) {
    mkdir("/dev", 0755); mkdir("/proc", 0755); mkdir("/sys", 0755);
    require(mount("devtmpfs", "/dev", "devtmpfs", 0, "") == 0, "mount devtmpfs");
    int console = open("/dev/console", O_RDWR);
    require(console >= 0, "open console");
    require(dup2(console, 1) >= 0 && dup2(console, 2) >= 0, "redirect console");
    close(console);
    setbuf(stdout, NULL);
    require(mount("proc", "/proc", "proc", 0, "") == 0, "mount proc");
    require(mount("sysfs", "/sys", "sysfs", 0, "") == 0, "mount sysfs");
    DIR *directory = opendir("/sys/block");
    require(directory != NULL, "open block devices");
    char device[512] = {0};
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char path[512];
        int length = snprintf(path, sizeof(path), "/sys/block/%s/serial", entry->d_name);
        require(length > 0 && (size_t)length < sizeof(path), "serial path bound");
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char serial[64] = {0};
        ssize_t count = read(fd, serial, sizeof(serial) - 1);
        close(fd);
        static const char expected[] = "silo-root-lower";
        if (count > 0 && serial[count - 1] == '\n') --count;
        if (count == (ssize_t)(sizeof(expected) - 1) && !memcmp(serial, expected, sizeof(expected) - 1)) {
            require(device[0] == 0, "unique lower serial");
            length = snprintf(device, sizeof(device), "/dev/%s", entry->d_name);
            require(length > 0 && (size_t)length < sizeof(device), "device path bound");
        }
    }
    require(closedir(directory) == 0 && device[0] != 0, "find lower serial");
    int lower = open(device, O_RDONLY);
    require(lower >= 0, "open mapping device");
    struct stat metadata;
    require(fstat(lower, &metadata) == 0 && S_ISBLK(metadata.st_mode), "actual block device");
    char command[4097] = {0};
    int fd = open("/proc/cmdline", O_RDONLY);
    require(fd >= 0, "open command line");
    ssize_t length = read(fd, command, sizeof(command) - 1);
    require(length > 0 && (size_t)length < sizeof(command) - 1, "command line bound");
    close(fd);
    char *positions = strstr(command, "silo.smoke_probes=");
    require(positions != NULL, "mapping positions");
    positions += strlen("silo.smoke_probes=");
    positions[strcspn(positions, " \n")] = 0;
    unsigned char bytes[65536];
    unsigned count = 0;
    char *state = NULL;
    for (char *position = strtok_r(positions, ",", &state); position != NULL; position = strtok_r(NULL, ",", &state)) {
        uint64_t offset;
        size_t size;
        char trailing;
        require(++count <= 64 && sscanf(position, "%" SCNu64 ":%zu%c", &offset, &size, &trailing) == 2, "mapping position syntax");
        require(size > 0 && size <= sizeof(bytes) && offset <= INT64_MAX - size, "mapping range bound");
        size_t done = 0;
        while (done < size) {
            ssize_t read_bytes = pread(lower, bytes + done, size - done, (off_t)(offset + done));
            if (read_bytes < 0 && errno == EINTR) continue;
            require(read_bytes > 0, "mapping read");
            done += (size_t)read_bytes;
        }
        char row[2 * sizeof(bytes) + 96];
        int prefix = snprintf(row, sizeof(row), "SILO_MAP_RESULT {\"offset\":%" PRIu64 ",\"hex\":\"", offset);
        require(prefix > 0 && (size_t)prefix + 2 * size + 4 <= sizeof(row), "mapping output bound");
        size_t used = (size_t)prefix;
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < size; ++i) {
            row[used++] = hex[bytes[i] >> 4];
            row[used++] = hex[bytes[i] & 15];
        }
        row[used++] = '"';
        row[used++] = '}';
        row[used++] = '\n';
        require(fwrite(row, 1, used, stdout) == used, "mapping output");
    }
    require(count > 0 && close(lower) == 0, "mapping complete");
    puts("SILO_VMDK_MAPPING_PASS");
    for (;;) pause();
}
