/* Smoke-only CPU and real virtio-block DMA dirty-page witness. The daemon
 * pins tmpfs-backed pages across exec commands and execution restores. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MEMORY "/dev/shm/incremental-memory"
#define DISK "/incremental-dma"
#define MIB (1024U * 1024U)
#define LENGTH (96U * MIB)

static int fail(const char *operation)
{
    fprintf(stderr, "incremental-memory: %s: %s\n", operation, strerror(errno));
    return 1;
}

static int transfer(int fd, unsigned char *buffer, size_t length, int writing)
{
    ssize_t done;
    do {
        done = writing ? pwrite(fd, buffer, length, 0) : pread(fd, buffer, length, 0);
    } while (done < 0 && errno == EINTR);
    if (done != (ssize_t)length) {
        if (done >= 0)
            errno = EIO;
        return fail(writing ? "pwrite" : "pread O_DIRECT");
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "start") && strcmp(argv[1], "read") &&
                     strcmp(argv[1], "first") && strcmp(argv[1], "second") &&
                     strcmp(argv[1], "zero") && strcmp(argv[1], "crossover"))) {
        fprintf(stderr, "usage: incremental-memory start|read|first|second|zero|crossover\n");
        return 2;
    }
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || LENGTH % (size_t)page) {
        errno = EINVAL;
        return fail("page size");
    }
    int starting = !strcmp(argv[1], "start");
    int fd = open(MEMORY, O_RDWR | O_CLOEXEC | (starting ? O_CREAT | O_EXCL : 0), 0600);
    if (fd < 0)
        return fail("open tmpfs witness");
    if (starting && ftruncate(fd, LENGTH))
        return fail("ftruncate");
    unsigned char *memory = mmap(NULL, LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (memory == MAP_FAILED)
        return fail("mmap");
    if (close(fd))
        return fail("close tmpfs");
    if (starting) {
        memset(memory, 0x51, LENGTH);
        struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_MEMLOCK, &limit) || mlock(memory, LENGTH))
            return fail("pin witness");
        /* Wait for the child to pin its own mapping before the command exits. */
        int ready[2];
        if (pipe(ready))
            return fail("pipe");
        pid_t child = fork();
        if (child < 0)
            return fail("fork witness holder");
        if (!child) {
            close(ready[0]);
            if (setsid() < 0 || mlock(memory, LENGTH))
                _exit(1);
            if (write(ready[1], "1", 1) != 1)
                _exit(1);
            close(ready[1]);
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            for (;;)
                pause();
        }
        close(ready[1]);
        char acknowledgement = 0;
        ssize_t received = read(ready[0], &acknowledgement, 1);
        close(ready[0]);
        if (received != 1 || acknowledgement != '1') {
            waitpid(child, NULL, 0);
            errno = EIO;
            return fail("pin holder acknowledgement");
        }
    } else if (!strcmp(argv[1], "first") || !strcmp(argv[1], "second")) {
        unsigned char value = !strcmp(argv[1], "first") ? 0x62 : 0x73;
        /* The CPU page is written through a volatile pointer. The DMA page is
         * changed only by an O_DIRECT block read, not a userspace memcpy. */
        volatile unsigned char *cpu = memory;
        for (long i = 0; i < page; ++i)
            cpu[i] = value;
        void *source = NULL;
        if (posix_memalign(&source, (size_t)page, (size_t)page)) {
            errno = ENOMEM;
            return fail("aligned DMA source");
        }
        memset(source, value + 1, (size_t)page);
        int disk = open(DISK, O_RDWR | O_CREAT | O_CLOEXEC | O_DIRECT, 0600);
        if (disk < 0)
            return fail("open direct disk");
        if (transfer(disk, source, (size_t)page, 1) || fsync(disk) ||
            transfer(disk, memory + 8U * MIB, (size_t)page, 0))
            return 1;
        free(source);
        if (close(disk))
            return fail("close DMA disk");
    } else if (!strcmp(argv[1], "zero")) {
        memset(memory + 16U * MIB, 0, (size_t)page);
    } else if (!strcmp(argv[1], "crossover")) {
        memset(memory, 0x84, LENGTH);
    }
    int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (pagemap < 0)
        return fail("open pagemap");
    printf("{\"pageSize\":%ld,\"pages\":[", page);
    const size_t offsets[] = {0, 8U * MIB, 16U * MIB, LENGTH - (size_t)page};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        unsigned char *address = memory + offsets[i];
        /* Each exec has fresh PTEs even though the holder pins the backing
         * pages. Fault this mapping in before observing its pagemap entry. */
        unsigned char value = *(volatile unsigned char *)address;
        uint64_t entry = 0;
        off_t offset = (off_t)((uintptr_t)address / (uintptr_t)page * 8U);
        if (pread(pagemap, &entry, sizeof(entry), offset) != sizeof(entry))
            return fail("read pagemap");
        uint64_t frame = entry & ((UINT64_C(1) << 55) - 1);
        if (!(entry & (UINT64_C(1) << 63)) || !frame) {
            errno = EACCES;
            return fail("present pinned guest PFN");
        }
        for (long j = 0; j < page; ++j) {
            if (address[j] != value) {
                errno = EIO;
                return fail("nonuniform witness page");
            }
        }
        printf("%s{\"guestPhysicalAddress\":%" PRIu64 ",\"value\":%u}",
               i ? "," : "", frame * (uint64_t)page, value);
    }
    puts("]}");
    if (close(pagemap) || munmap(memory, LENGTH))
        return fail("release command mapping");
    return 0;
}
