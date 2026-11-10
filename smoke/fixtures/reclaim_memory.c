/* Real tmpfs and anonymous-memory workload for host reclaim smoke. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define GIB (UINT64_C(1024) * 1024 * 1024)
#define LENGTH (2 * GIB)
#define MEMORY "/dev/shm/reclaim/blob"

static int fail(const char *operation)
{
    fprintf(stderr, "reclaim-memory: %s: %s\n", operation, strerror(errno));
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "seed") && strcmp(argv[1], "rewrite") &&
                     strcmp(argv[1], "zero"))) {
        fprintf(stderr, "usage: reclaim-memory seed|rewrite|zero\n");
        return 2;
    }
    if (sizeof(size_t) < 8) {
        errno = ENOTSUP;
        return fail("64-bit guest required");
    }
    const int anonymous = !strcmp(argv[1], "zero");
    const int seed = !strcmp(argv[1], "seed");
    int fd = -1;
    if (!anonymous) {
        fd = open(MEMORY, O_RDWR | O_CLOEXEC | (seed ? O_CREAT | O_EXCL : 0), 0600);
        if (fd < 0)
            return fail("open tmpfs blob");
        if (seed && ftruncate(fd, (off_t)LENGTH)) {
            int result = fail("size tmpfs blob");
            close(fd);
            unlink(MEMORY);
            return result;
        }
        struct stat metadata;
        if (fstat(fd, &metadata) || metadata.st_size != (off_t)LENGTH) {
            errno = EINVAL;
            int result = fail("2 GiB tmpfs blob required");
            close(fd);
            return result;
        }
    }
    /* MAP_POPULATE on a writable private anonymous mapping allocates actual
     * guest pages. A read-only scan of an unpopulated mmap would merely test
     * Linux's shared zero page, not a fresh 2 GiB allocation. */
    unsigned char *memory = mmap(NULL, (size_t)LENGTH, PROT_READ | PROT_WRITE,
        anonymous ? MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE : MAP_SHARED, fd, 0);
    if (memory == MAP_FAILED) {
        int result = fail("map memory");
        if (fd >= 0)
            close(fd);
        return result;
    }
    if (fd >= 0 && close(fd)) {
        int result = fail("close tmpfs blob");
        munmap(memory, (size_t)LENGTH);
        return result;
    }
    int result = 0;
    if (anonymous) {
        const volatile unsigned char *bytes = memory;
        for (size_t offset = 0; offset < (size_t)LENGTH; ++offset) {
            if (bytes[offset] != 0) {
                fprintf(stderr, "reclaim-memory: nonzero fresh byte at %zu: %u\n",
                        offset, (unsigned int)bytes[offset]);
                result = 1;
                break;
            }
        }
        if (!result)
            printf("zero bytes=%" PRIu64 "\n", LENGTH);
    } else {
        /* Distinct, fixed nonzero bytes make resurrection and COW observable. */
        memset(memory, seed ? 0x5a : 0xa5, seed ? (size_t)LENGTH : (size_t)GIB);
    }
    if (munmap(memory, (size_t)LENGTH))
        return fail("unmap memory");
    return result;
}
