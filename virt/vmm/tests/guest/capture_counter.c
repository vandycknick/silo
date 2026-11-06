/* Smoke-only matched-cut witness. The host reads this pinned page at its
 * reported guest physical address, not by searching RAM for copied markers.
 * A frozen write may be pending: disk must contain committed or pending then;
 * outside that interval disk and committed must agree exactly.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

struct counter {
    uint64_t magic;
    _Atomic uint64_t committed;
    _Atomic uint64_t pending;
    _Atomic uint64_t writing;
};

static int fail(const char *operation)
{
    fprintf(stderr, "capture-counter: %s: %s\n", operation, strerror(errno));
    return 1;
}

static int write_counter(int fd, uint64_t value)
{
    unsigned char bytes[8];
    for (unsigned int i = 0; i < sizeof(bytes); ++i)
        bytes[i] = (unsigned char)(value >> (i * 8));
    size_t done = 0;
    while (done < sizeof(bytes)) {
        ssize_t n = pwrite(fd, bytes + done, sizeof(bytes) - done, (off_t)done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (n == 0)
                errno = EIO;
            return fail("pwrite");
        }
        done += (size_t)n;
    }
    if (fdatasync(fd) != 0)
        return fail("fdatasync");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: capture-counter NEW_COUNTER_FILE\n");
        return 2;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < (long)sizeof(struct counter)) {
        errno = EINVAL;
        return fail("page size");
    }
    struct counter *state = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED)
        return fail("mmap");
    state->magic = UINT64_C(0x53494c4f43555431);
    atomic_init(&state->committed, 0);
    atomic_init(&state->pending, 0);
    atomic_init(&state->writing, 0);
    if (!atomic_is_lock_free(&state->committed)) {
        errno = ENOTSUP;
        return fail("lock-free counter");
    }
    if (mlock(state, (size_t)page_size) != 0)
        return fail("mlock");
    int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (pagemap < 0)
        return fail("open pagemap");
    uint64_t entry = 0;
    off_t offset = (off_t)((uintptr_t)state / (uintptr_t)page_size * 8);
    if (pread(pagemap, &entry, sizeof(entry), offset) != sizeof(entry))
        return fail("read pagemap");
    if (close(pagemap) != 0)
        return fail("close pagemap");
    uint64_t frame = entry & ((UINT64_C(1) << 55) - 1);
    if (!(entry & (UINT64_C(1) << 63)) || frame == 0) {
        errno = EACCES;
        return fail("pagemap requires guest root PFN access");
    }
    int fd = open(argv[1], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return fail("create counter file");
    if (ftruncate(fd, (off_t)page_size) != 0 || write_counter(fd, 0) != 0)
        return fail("initialize counter file");
    /* Establish the inode and extent before the witness begins racing capture. */
    sync();
    printf("{\"guestPhysicalAddress\":%" PRIu64 ",\"pageSize\":%ld,\"pid\":%ld}\n",
           frame * (uint64_t)page_size, page_size, (long)getpid());
    fflush(stdout);
    for (uint64_t next = 1; next != 0; ++next) {
        atomic_store(&state->pending, next);
        atomic_store(&state->writing, 1);
        if (write_counter(fd, next) != 0)
            return 1;
        atomic_store(&state->committed, next);
        atomic_store(&state->writing, 0);
        printf("COMMITTED=%" PRIu64 "\n", next);
        fflush(stdout);
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};
        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR)
                return fail("nanosleep");
        }
    }
    errno = EOVERFLOW;
    return fail("counter overflow");
}
