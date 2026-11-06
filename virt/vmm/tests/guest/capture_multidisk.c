/* Real capture-side witness: ordered direct writes on two mounted source
 * filesystems, dirty shared cache pages, and unsynchronized metadata churn.
 * Host readers inspect sealed bytes without mounting or replaying journals.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct disk_state {
    _Atomic uint64_t committed;
    _Atomic uint64_t pending;
    _Atomic uint64_t writing;
};
struct witness {
    uint64_t magic;
    struct disk_state disks[2];
};

static int fail(const char *operation)
{
    fprintf(stderr, "capture-multidisk: %s: %s\n", operation, strerror(errno));
    return 1;
}

static uint64_t physical(void *page, long page_size)
{
    int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    uint64_t entry = 0;
    off_t offset = (off_t)((uintptr_t)page / (uintptr_t)page_size * 8);
    ssize_t count = pread(fd, &entry, sizeof(entry), offset);
    int closed = close(fd);
    if (count != sizeof(entry) || closed != 0)
        return 0;
    uint64_t frame = entry & ((UINT64_C(1) << 55) - 1);
    if (!(entry & (UINT64_C(1) << 63)) || frame == 0) {
        errno = EACCES;
        return 0;
    }
    return frame * (uint64_t)page_size;
}

static int write_page(int fd, const void *bytes, size_t length)
{
    ssize_t count;
    do {
        count = pwrite(fd, bytes, length, 0);
    } while (count < 0 && errno == EINTR);
    if (count != (ssize_t)length) {
        if (count >= 0)
            errno = EIO;
        return fail("whole direct write");
    }
    return fdatasync(fd) == 0 ? 0 : fail("fdatasync numbered record");
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: capture-multidisk SOURCE_MOUNT_A SOURCE_MOUNT_B\n");
        return 2;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size != 4096) {
        errno = ENOTSUP;
        return fail("4096-byte witness pages required");
    }
    struct witness *state = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t *buffer = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED || buffer == MAP_FAILED)
        return fail("mmap witness");
    state->magic = UINT64_C(0x53494c4f4d554c31);
    for (int i = 0; i < 2; ++i) {
        atomic_init(&state->disks[i].committed, 0);
        atomic_init(&state->disks[i].pending, 0);
        atomic_init(&state->disks[i].writing, 0);
    }
    if (!atomic_is_lock_free(&state->disks[0].committed)) {
        errno = ENOTSUP;
        return fail("lock-free witness");
    }
    if (mlock(state, (size_t)page_size) != 0)
        return fail("mlock witness");
    int direct[2];
    _Atomic uint64_t *cache[2];
    uint64_t cache_address[2];
    for (int i = 0; i < 2; ++i) {
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/numbered", argv[i + 1]) >= (int)sizeof(path)) {
            errno = ENAMETOOLONG;
            return fail("numbered path");
        }
        direct[i] = open(path, O_RDWR | O_CREAT | O_EXCL | O_DIRECT | O_CLOEXEC, 0600);
        if (direct[i] < 0 || write_page(direct[i], buffer, (size_t)page_size) != 0)
            return fail("initialize numbered extent");
        if (snprintf(path, sizeof(path), "%s/cached", argv[i + 1]) >= (int)sizeof(path)) {
            errno = ENAMETOOLONG;
            return fail("cache path");
        }
        int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || write_page(fd, buffer, (size_t)page_size) != 0)
            return fail("initialize cache extent");
        cache[i] = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (cache[i] == MAP_FAILED || close(fd) != 0)
            return fail("map cache");
        atomic_store(cache[i], 0);
        if (mlock(cache[i], (size_t)page_size) != 0)
            return fail("mlock cache");
        cache_address[i] = physical(cache[i], page_size);
        if (cache_address[i] == 0)
            return fail("cache physical address");
        /* Keep allocation stable across reservation and monitor admission while
         * continuing to dirty existing metadata during the measured workload. */
        for (unsigned slot = 0; slot < 16; ++slot) {
            if (snprintf(path, sizeof(path), "%s/churn-%u", argv[i + 1], slot) >= (int)sizeof(path)) {
                errno = ENAMETOOLONG;
                return fail("initial churn path");
            }
            fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd < 0 || write_page(fd, buffer, (size_t)page_size) != 0 || close(fd) != 0)
                return fail("initialize churn extent");
        }
    }
    /* Establish file extents only before the measured unsynced workload. */
    sync();
    uint64_t address = physical(state, page_size);
    if (address == 0)
        return fail("witness physical address");
    printf("{\"guestPhysicalAddress\":%" PRIu64 ",\"pageSize\":%ld,"
           "\"cacheGuestPhysicalAddresses\":[%" PRIu64 ",%" PRIu64 "],\"pid\":%ld}\n",
           address, page_size, cache_address[0], cache_address[1], (long)getpid());
    if (fflush(stdout) != 0)
        return fail("identity output");
    for (uint64_t next = 1; next != 0; ++next) {
        for (size_t word = 0; word < (size_t)page_size / sizeof(*buffer); ++word)
            buffer[word] = next;
        for (int i = 0; i < 2; ++i) {
            atomic_store(&state->disks[i].pending, next);
            atomic_store(&state->disks[i].writing, 1);
            if (write_page(direct[i], buffer, (size_t)page_size) != 0)
                return 1;
            atomic_store(&state->disks[i].committed, next);
            atomic_store(&state->disks[i].writing, 0);
            /* No msync/fsync for this shared page after initialization. */
            atomic_store(cache[i], next);
            char path[4096];
            if (snprintf(path, sizeof(path), "%s/churn-%u", argv[i + 1], (unsigned)(next % 16)) >= (int)sizeof(path)) {
                errno = ENAMETOOLONG;
                return fail("churn path");
            }
            int fd = open(path, O_WRONLY | O_CLOEXEC, 0600);
            if (fd < 0 || write(fd, &next, sizeof(next)) != sizeof(next) || close(fd) != 0)
                return fail("unsynced metadata churn");
        }
        printf("COMMITTED=%" PRIu64 "\n", next);
        if (fflush(stdout) != 0)
            return fail("progress output");
    }
    errno = EOVERFLOW;
    return fail("counter overflow");
}
