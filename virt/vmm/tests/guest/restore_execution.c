/* Smoke-only execution witness. A detached workload owns its descriptors, not
 * an exec session. Read commands use a guest-local Unix socket after activation.
 * Disk records are durable append-only slots; the independently pinned RAM page
 * distinguishes an in-flight write from its last committed predecessor.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SOCKET "/restore-execution.sock"
#define LOG "/restore-execution.records"
#define LIMIT UINT64_C(32768)
#define MAGIC UINT64_C(0x53494c4f52535431)

struct witness {
    _Atomic uint64_t magic, committed, pending, writing;
    _Atomic uint64_t timers, delivered, timer_pending, signal_pending;
    _Atomic uint64_t cpu_steps, lane0, lane1, parked, errors;
    _Atomic uint64_t register_steps, avx_enabled;
};
struct record {
    uint64_t sequence, timers, delivered, cpu_steps, lane0, lane1, monotonic_ns, pending;
};
_Static_assert(sizeof(struct record) == 64, "disk record format");

static int fail(const char *operation)
{
    fprintf(stderr, "restore-execution: %s: %s\n", operation, strerror(errno));
    return 1;
}

static int transfer(int fd, void *buffer, size_t length, int writing)
{
    unsigned char *bytes = buffer;
    while (length) {
        ssize_t n = writing ? write(fd, bytes, length) : read(fd, bytes, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (n == 0)
                errno = EIO;
            return fail("transfer");
        }
        bytes += n;
        length -= (size_t)n;
    }
    return 0;
}

static int pin_cpu(int cpu)
{
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    return sched_setaffinity(0, sizeof(affinity), &affinity) == 0 ? 0 : fail("CPU affinity");
}

/* The vector remains live across a real blocking syscall. Integer arithmetic
 * has an exact oracle, unlike a floating-point approximation tolerance.
 */
static void *cpu_work(void *argument)
{
    struct witness *state = argument;
    if (pin_cpu(1) != 0) {
        atomic_fetch_add(&state->errors, 1);
        return NULL;
    }
    typedef uint64_t vector __attribute__((vector_size(16)));
    vector lanes = {UINT64_C(7), UINT64_C(19)};
    const vector increment = {UINT64_C(3), UINT64_C(5)};
    for (uint64_t step = 1; ; ++step) {
        lanes += increment;
#if defined(__x86_64__)
        __asm__ volatile("" : "+x"(lanes));
#elif defined(__aarch64__)
        __asm__ volatile("" : "+w"(lanes));
#else
#error Unsupported restore execution witness architecture
#endif
        atomic_store(&state->parked, 1);
        struct timespec delay = {.tv_nsec = 5000000};
        while (nanosleep(&delay, &delay) != 0)
            if (errno != EINTR) {
                atomic_fetch_add(&state->errors, 1);
                return NULL;
            }
        atomic_store(&state->parked, 0);
        if (lanes[0] != 7 + 3 * step || lanes[1] != 19 + 5 * step) {
            atomic_fetch_add(&state->errors, 1);
            return NULL;
        }
        atomic_store(&state->lane0, lanes[0]);
        atomic_store(&state->lane1, lanes[1]);
        atomic_store(&state->cpu_steps, step);
    }
}

/* Phase 9's production Linux live-register sentinel protocol, now observed
 * through the persistent witness rather than a captured exec stdout stream.
 * No function call in the loop may spill or reseed these live values.
 */
static void *register_work(void *argument)
{
    struct witness *state = argument;
    if (pin_cpu(1) != 0) {
        atomic_fetch_add(&state->errors, 1);
        return NULL;
    }
#if defined(__x86_64__)
    uint32_t eax = 1, ebx, ecx = 0, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    const uint32_t required = (UINT32_C(1) << 26) | (UINT32_C(1) << 27) | (UINT32_C(1) << 28);
    int avx = 0;
    if ((ecx & required) == required) {
        __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
        avx = (((uint64_t)edx << 32 | eax) & 7) == 7;
    }
    atomic_store(&state->avx_enabled, (uint64_t)avx);
    uint64_t count = 0, fp;
    int failed = 0;
    __asm__ volatile(
        "movabs $0x13579bdf2468ace0, %%r12\n"
        "movabs $0xfedcba9876543210, %%r13\n"
        "pcmpeqd %%xmm15, %%xmm15\n"
        "test %[avx], %[avx]\n"
        "jz 3f\n"
        "vpcmpeqd %%ymm14, %%ymm14, %%ymm14\n"
        "3: fld1\n"
        "1:\n"
        "movabs $0x13579bdf2468ace0, %%rax\n"
        "cmp %%rax, %%r12\n"
        "jne 2f\n"
        "movabs $0xfedcba9876543210, %%rax\n"
        "cmp %%rax, %%r13\n"
        "jne 2f\n"
        "pmovmskb %%xmm15, %%eax\n"
        "cmp $65535, %%eax\n"
        "jne 2f\n"
        "fstl %[fp]\n"
        "movabs $0x3ff0000000000000, %%rax\n"
        "cmp %[fp], %%rax\n"
        "jne 2f\n"
        "test %[avx], %[avx]\n"
        "jz 4f\n"
        "vextractf128 $1, %%ymm14, %%xmm0\n"
        "pmovmskb %%xmm0, %%eax\n"
        "cmp $65535, %%eax\n"
        "jne 2f\n"
        "4: inc %[count]\n"
        "mov %[count], (%[progress])\n"
        "jmp 1b\n"
        "2: mov $1, %[failed]\n"
        "fstp %%st(0)\n"
        : [count] "+&r"(count), [failed] "+&r"(failed), [fp] "=m"(fp)
        : [progress] "r"(&state->register_steps), [avx] "r"(avx)
        : "rax", "r12", "r13", "xmm0", "xmm14", "xmm15", "cc", "memory");
    atomic_fetch_add(&state->errors, (uint64_t)failed);
    return NULL;
#else
#error The live-register restore witness requires the admitted KVM x86_64 lane
#endif
}

static int commit(int fd, struct witness *state)
{
    uint64_t sequence = atomic_load(&state->committed) + 1;
    if (sequence > LIMIT) {
        errno = EFBIG;
        return fail("bounded record log exhausted");
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return fail("clock_gettime");
    struct record value = {
        sequence, atomic_load(&state->timers), atomic_load(&state->delivered),
        atomic_load(&state->cpu_steps), atomic_load(&state->lane0), atomic_load(&state->lane1),
        (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
        atomic_load(&state->timer_pending) | (atomic_load(&state->signal_pending) << 1),
    };
    atomic_store(&state->pending, sequence);
    atomic_store(&state->writing, 1);
    ssize_t count;
    do {
        count = pwrite(fd, &value, sizeof(value), (off_t)((sequence - 1) * sizeof(value)));
    } while (count < 0 && errno == EINTR);
    if (count != (ssize_t)sizeof(value) || fdatasync(fd) != 0)
        return fail("durable record");
    atomic_store(&state->committed, sequence);
    atomic_store(&state->writing, 0);
    return 0;
}

static int respond(int client, int disk, struct witness *state, uint64_t address,
                   long page_size, uint64_t start)
{
    FILE *output = fdopen(client, "w");
    if (output == NULL) {
        close(client);
        return fail("fdopen");
    }
    uint64_t count = atomic_load(&state->committed);
    fprintf(output, "{\"guestPhysicalAddress\":%" PRIu64 ",\"pageSize\":%ld,\"pid\":%ld,"
            "\"committed\":%" PRIu64 ",\"timers\":%" PRIu64 ",\"delivered\":%" PRIu64 ","
            "\"timerPending\":%" PRIu64 ",\"signalPending\":%" PRIu64 ","
            "\"cpuSteps\":%" PRIu64 ",\"errors\":%" PRIu64 ","
            "\"registerSteps\":%" PRIu64 ",\"avxEnabled\":%" PRIu64 ",\"records\":[",
            address, page_size, (long)getpid(), count, atomic_load(&state->timers),
            atomic_load(&state->delivered), atomic_load(&state->timer_pending),
            atomic_load(&state->signal_pending), atomic_load(&state->cpu_steps),
            atomic_load(&state->errors), atomic_load(&state->register_steps),
            atomic_load(&state->avx_enabled));
    for (uint64_t index = start; index < count && index < start + 32; ++index) {
        struct record record;
        if (pread(disk, &record, sizeof(record), (off_t)(index * sizeof(record))) != (ssize_t)sizeof(record)) {
            fclose(output);
            return fail("read committed record");
        }
        fprintf(output, "%s[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]",
                index == start ? "" : ",", record.sequence, record.timers, record.delivered,
                record.cpu_steps, record.lane0, record.lane1, record.monotonic_ns, record.pending);
    }
    fprintf(output, "]}\n");
    return fclose(output) == 0 ? 0 : fail("close response");
}

static int serve(int ready)
{
    if (pin_cpu(0) != 0)
        return 1;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < (long)sizeof(struct witness))
        return fail("page size");
    struct witness *state = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED)
        return fail("mmap");
    atomic_init(&state->magic, MAGIC);
    atomic_init(&state->committed, 0);
    atomic_init(&state->pending, 0);
    atomic_init(&state->writing, 0);
    atomic_init(&state->timers, 0);
    atomic_init(&state->delivered, 0);
    atomic_init(&state->timer_pending, 0);
    atomic_init(&state->signal_pending, 0);
    atomic_init(&state->cpu_steps, 0);
    atomic_init(&state->lane0, 0);
    atomic_init(&state->lane1, 0);
    atomic_init(&state->parked, 0);
    atomic_init(&state->errors, 0);
    atomic_init(&state->register_steps, 0);
    atomic_init(&state->avx_enabled, 0);
    if (!atomic_is_lock_free(&state->committed) || mlock(state, (size_t)page_size) != 0)
        return fail("pin lock-free witness");
    int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    uint64_t entry = 0;
    off_t offset = (off_t)((uintptr_t)state / (uintptr_t)page_size * 8);
    if (pagemap < 0 || pread(pagemap, &entry, sizeof(entry), offset) != (ssize_t)sizeof(entry))
        return fail("read pagemap");
    close(pagemap);
    uint64_t frame = entry & ((UINT64_C(1) << 55) - 1);
    if (!(entry & (UINT64_C(1) << 63)) || frame == 0)
        return fail("guest root PFN access");
    uint64_t address = frame * (uint64_t)page_size;
    int disk = open(LOG, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (disk < 0 || ftruncate(disk, (off_t)(LIMIT * sizeof(struct record))) != 0)
        return fail("create bounded log");
    /* The independent host reader does not replay the ext4 journal. Materialize
     * every log block before the initial sync so later writes change data only,
     * rather than adding extent mappings visible only through the guest journal. */
    unsigned char zeroes[4096] = {0};
    for (off_t position = 0; position < (off_t)(LIMIT * sizeof(struct record));
         position += (off_t)sizeof(zeroes)) {
        ssize_t written;
        do {
            written = pwrite(disk, zeroes, sizeof(zeroes), position);
        } while (written < 0 && errno == EINTR);
        if (written != (ssize_t)sizeof(zeroes))
            return fail("materialize bounded log");
    }
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un endpoint = {.sun_family = AF_UNIX};
    memcpy(endpoint.sun_path, SOCKET, sizeof(SOCKET));
    if (listener < 0 || bind(listener, (struct sockaddr *)&endpoint, sizeof(endpoint)) != 0 ||
        listen(listener, 4) != 0)
        return fail("Unix listener");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    int error = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (error != 0) {
        errno = error;
        return fail("block pending signal");
    }
    int signals = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    int pending_timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    struct itimerspec cadence = {.it_interval = {.tv_nsec = 50000000},
                                .it_value = {.tv_nsec = 50000000}};
    if (signals < 0 || timer < 0 || pending_timer < 0 || timerfd_settime(timer, 0, &cadence, NULL) != 0)
        return fail("timer setup");
    pthread_t worker;
    error = pthread_create(&worker, NULL, cpu_work, state);
    if (error != 0) {
        errno = error;
        return fail("CPU worker");
    }
    pthread_t registers;
    error = pthread_create(&registers, NULL, register_work, state);
    if (error != 0) {
        errno = error;
        return fail("live-register worker");
    }
    if (commit(disk, state) != 0)
        return 1;
    sync();
    unsigned char started = 1;
    if (transfer(ready, &started, sizeof(started), 1) != 0)
        return 1;
    close(ready);
    struct pollfd descriptors[] = {{listener, POLLIN, 0}, {timer, POLLIN, 0}};
    for (;;) {
        if (poll(descriptors, 2, -1) < 0) {
            if (errno == EINTR)
                continue;
            return fail("poll");
        }
        if (descriptors[1].revents & POLLIN) {
            uint64_t expirations;
            if (transfer(timer, &expirations, sizeof(expirations), 0) != 0)
                return 1;
            atomic_fetch_add(&state->timers, expirations);
            if (commit(disk, state) != 0)
                return 1;
        }
        if (!(descriptors[0].revents & POLLIN))
            continue;
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0)
            return fail("accept");
        char request[64] = {0};
        size_t length = 0;
        while (length + 1 < sizeof(request)) {
            struct pollfd readable = {client, POLLIN, 0};
            if (poll(&readable, 1, 1000) != 1 ||
                transfer(client, &request[length], 1, 0) != 0) {
                close(client);
                return fail("bounded control request");
            }
            if (request[length++] == '\n')
                break;
        }
        uint64_t start = 0;
        char operation[16] = {0};
        if (length == 0 || request[length - 1] != '\n' ||
            sscanf(request, "%15s %" SCNu64, operation, &start) != 2 || start > LIMIT) {
            close(client);
            return fail("malformed control command");
        }
        if (strcmp(operation, "arm") == 0) {
            if (atomic_load(&state->timer_pending) || atomic_load(&state->signal_pending)) {
                close(client);
                errno = EALREADY;
                return fail("already armed");
            }
            struct itimerspec once = {.it_value = {.tv_nsec = 1}};
            if (timerfd_settime(pending_timer, 0, &once, NULL) != 0 || kill(getpid(), SIGUSR1) != 0)
                return fail("arm pending events");
            struct pollfd armed = {pending_timer, POLLIN, 0};
            if (poll(&armed, 1, 1000) != 1)
                return fail("pending timer did not become readable");
            atomic_store(&state->timer_pending, 1);
            atomic_store(&state->signal_pending, 1);
        } else if (strcmp(operation, "deliver") == 0) {
            uint64_t expiration;
            struct signalfd_siginfo signal;
            if (atomic_load(&state->timer_pending) != 1 || atomic_load(&state->signal_pending) != 1 ||
                read(pending_timer, &expiration, sizeof(expiration)) != (ssize_t)sizeof(expiration) || expiration != 1 ||
                read(signals, &signal, sizeof(signal)) != (ssize_t)sizeof(signal) || signal.ssi_signo != SIGUSR1) {
                close(client);
                return fail("restore lost pending event");
            }
            errno = 0;
            if (read(pending_timer, &expiration, sizeof(expiration)) != -1 || errno != EAGAIN)
                return fail("duplicate timer delivery");
            errno = 0;
            if (read(signals, &signal, sizeof(signal)) != -1 || errno != EAGAIN)
                return fail("duplicate signal delivery");
            atomic_store(&state->timer_pending, 0);
            atomic_store(&state->signal_pending, 0);
            atomic_fetch_add(&state->delivered, 1);
        } else if (strcmp(operation, "read") != 0) {
            close(client);
            errno = EINVAL;
            return fail("unknown command");
        }
        if (respond(client, disk, state, address, page_size, start) != 0)
            return 1;
    }
}

static int start(void)
{
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) != 0)
        return fail("startup pipe");
    pid_t child = fork();
    if (child < 0)
        return fail("fork");
    if (child == 0) {
        close(ready[0]);
        if (setsid() < 0)
            _exit(fail("setsid"));
        pid_t daemon = fork();
        if (daemon < 0)
            _exit(fail("daemon fork"));
        if (daemon > 0)
            _exit(0);
        int null = open("/dev/null", O_RDWR);
        int errors = open("/restore-execution.error", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (null < 0 || errors < 0 || dup2(null, STDIN_FILENO) < 0 ||
            dup2(null, STDOUT_FILENO) < 0 || dup2(errors, STDERR_FILENO) < 0)
            _exit(1);
        close(null);
        close(errors);
        _exit(serve(ready[1]));
    }
    close(ready[1]);
    unsigned char started = 0;
    int result = transfer(ready[0], &started, sizeof(started), 0);
    close(ready[0]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return fail("reap startup process");
    return result == 0 && started == 1 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "start") == 0)
        return start();
    if ((argc != 2 && argc != 3) ||
        (strcmp(argv[1], "read") != 0 && strcmp(argv[1], "arm") != 0 && strcmp(argv[1], "deliver") != 0)) {
        fprintf(stderr, "usage: restore-execution start|read|arm|deliver [FIRST_RECORD_INDEX]\n");
        return 2;
    }
    char *end = NULL;
    errno = 0;
    uint64_t first = argc == 3 ? strtoull(argv[2], &end, 10) : 0;
    if (errno || (argc == 3 && (*end || end == argv[2] || argv[2][0] == '-')) || first > LIMIT)
        return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un endpoint = {.sun_family = AF_UNIX};
    memcpy(endpoint.sun_path, SOCKET, sizeof(SOCKET));
    if (fd < 0 || connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint)) != 0)
        return fail("connect witness");
    char request[64];
    int length = snprintf(request, sizeof(request), "%s %" PRIu64 "\n", argv[1], first);
    if (length < 0 || (size_t)length >= sizeof(request) || transfer(fd, request, (size_t)length, 1) != 0)
        return 1;
    char buffer[4096];
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return fail("response");
        }
        if (transfer(STDOUT_FILENO, buffer, (size_t)count, 1) != 0)
            return 1;
    }
    return close(fd) == 0 ? 0 : fail("close client");
}
