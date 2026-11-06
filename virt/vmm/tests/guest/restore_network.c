/* Smoke-only activation network witness for restored children.
 *
 *   restore-network start DIR HOST_IP TCP_PORT UDP_PORT LISTEN_PORT
 *   restore-network status DIR
 *   restore-network stream DIR
 *
 * `start` detaches one persistent workload (never an exec session) that:
 *   - holds an established TCP stream to HOST_IP:TCP_PORT with 1s kernel
 *     keepalives, so the restored kernel itself retries traffic while frozen;
 *   - sends one unconnected UDP datagram every 20ms to HOST_IP:UDP_PORT whose
 *     payload carries a sequence number and a fresh getrandom UUIDv4;
 *   - serves a TCP listener on LISTEN_PORT for machine-scoped forwards.
 * Progress is durably rewritten to DIR/progress, independent of any session,
 * so a fenced or failed child can be judged from its stopped disk.
 * `stream` is a captured exec session: it writes numbered lines to stdout and
 * durably records its own sequence and the first write error.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RECORD_BYTES 512
#define SYNC_EVERY 10

struct progress {
    int fd;
    pid_t pid;
    uint64_t udp_seq;
    uint64_t udp_errors;
    uint64_t accepted;
    int tcp_established;
    int tcp_errno;
    char uuid[37];
};

static int fail(const char *operation)
{
    fprintf(stderr, "restore-network: %s: %s\n", operation, strerror(errno));
    return 1;
}

static int path_in(char *output, size_t size, const char *directory, const char *name)
{
    int length = snprintf(output, size, "%s/%s", directory, name);
    if (length < 0 || (size_t)length >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int write_all_at(int fd, const char *data, size_t size, off_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t n = pwrite(fd, data + done, size - done, offset + (off_t)done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (n == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/* One fixed-size JSON line rewritten in place: readers never see a torn tail
 * beyond the record and never need a parser for partial appends. */
static int record(int fd, const char *json, int durable)
{
    char line[RECORD_BYTES];
    size_t length = strlen(json);
    if (length + 1 > sizeof(line)) {
        errno = EOVERFLOW;
        return -1;
    }
    memset(line, ' ', sizeof(line));
    memcpy(line, json, length);
    line[sizeof(line) - 1] = '\n';
    if (write_all_at(fd, line, sizeof(line), 0) != 0)
        return -1;
    return durable ? fdatasync(fd) : 0;
}

static int save(struct progress *state, int durable)
{
    char json[RECORD_BYTES];
    int length = snprintf(json, sizeof(json),
                          "{\"pid\":%ld,\"udpSeq\":%" PRIu64 ",\"udpErrors\":%" PRIu64
                          ",\"uuid\":\"%s\",\"accepted\":%" PRIu64
                          ",\"tcpEstablished\":%s,\"tcpErrno\":%d}",
                          (long)state->pid, state->udp_seq, state->udp_errors, state->uuid,
                          state->accepted, state->tcp_established ? "true" : "false",
                          state->tcp_errno);
    if (length < 0 || (size_t)length >= sizeof(json)) {
        errno = EOVERFLOW;
        return -1;
    }
    return record(state->fd, json, durable);
}

static int fresh_uuid(char output[37])
{
    unsigned char bytes[16];
    size_t done = 0;
    while (done < sizeof(bytes)) {
        ssize_t n = getrandom(bytes + done, sizeof(bytes) - done, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    bytes[6] = (unsigned char)((bytes[6] & 0x0f) | 0x40);
    bytes[8] = (unsigned char)((bytes[8] & 0x3f) | 0x80);
    snprintf(output, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return 0;
}

static int parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0 || value > 65535) {
        errno = EINVAL;
        return -1;
    }
    *port = (uint16_t)value;
    return 0;
}

static int tcp_stream(struct in_addr host, uint16_t port, pid_t pid)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1, idle = 1, interval = 1, count = 127;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) != 0
        || setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) != 0
        || setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) != 0
        || setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = host};
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    char hello[64];
    int length = snprintf(hello, sizeof(hello), "SILO-RN-TCP pid=%ld\n", (long)pid);
    if (length < 0 || send(fd, hello, (size_t)length, MSG_NOSIGNAL) != length) {
        close(fd);
        return -1;
    }
    return fd;
}

static int listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port),
                                  .sin_addr = {.s_addr = htonl(INADDR_ANY)}};
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0
        || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int serve(struct progress *state, int fd)
{
    for (;;) {
        int connection = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        if (connection < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            return -1;
        }
        state->accepted++;
        char reply[160];
        int length = snprintf(reply, sizeof(reply),
                              "SILO-RN-SVC pid=%ld seq=%" PRIu64 " accepted=%" PRIu64 "\n",
                              (long)state->pid, state->udp_seq, state->accepted);
        if (length > 0)
            (void)send(connection, reply, (size_t)length, MSG_NOSIGNAL);
        close(connection);
        if (save(state, 1) != 0)
            return -1;
    }
}

static int workload(const char *directory, struct in_addr host, uint16_t tcp_port,
                    uint16_t udp_port, uint16_t listen_port)
{
    char path[4096];
    if (path_in(path, sizeof(path), directory, "progress") != 0)
        return fail("progress path");
    struct progress state = {.pid = getpid()};
    state.fd = open(path, O_RDWR | O_CLOEXEC);
    if (state.fd < 0)
        return fail("open materialized progress");
    strcpy(state.uuid, "none");
    int service = listener(listen_port);
    if (service < 0)
        return fail("listen");
    int stream = tcp_stream(host, tcp_port, state.pid);
    if (stream < 0)
        return fail("tcp stream");
    state.tcp_established = 1;
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (udp < 0)
        return fail("udp socket");
    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    struct itimerspec period = {.it_interval = {.tv_nsec = 20000000}, .it_value = {.tv_nsec = 20000000}};
    if (timer < 0 || timerfd_settime(timer, 0, &period, NULL) != 0)
        return fail("timerfd");
    if (save(&state, 1) != 0)
        return fail("initial progress");
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(udp_port), .sin_addr = host};
    for (;;) {
        struct pollfd fds[3] = {{.fd = timer, .events = POLLIN}, {.fd = service, .events = POLLIN},
                                {.fd = stream, .events = POLLIN}};
        int ready = poll(fds, stream >= 0 ? 3 : 2, -1);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return fail("poll");
        }
        if (fds[0].revents & POLLIN) {
            uint64_t expirations = 0;
            if (read(timer, &expirations, sizeof(expirations)) != sizeof(expirations))
                return fail("timer read");
            state.udp_seq++;
            if (fresh_uuid(state.uuid) != 0)
                return fail("getrandom");
            char payload[128];
            int length = snprintf(payload, sizeof(payload), "SILO-RN-UDP pid=%ld seq=%" PRIu64 " uuid=%s\n",
                                  (long)state.pid, state.udp_seq, state.uuid);
            if (length < 0)
                return fail("payload");
            /* Unconnected on purpose: each datagram selects its source from
             * the current interface address, as an ordinary sender would. */
            if (sendto(udp, payload, (size_t)length, 0, (struct sockaddr *)&target, sizeof(target)) != length)
                state.udp_errors++;
            if (save(&state, state.udp_seq % SYNC_EVERY == 0) != 0)
                return fail("progress");
        }
        if ((fds[1].revents & POLLIN) && serve(&state, service) != 0)
            return fail("serve");
        if (stream >= 0 && (fds[2].revents & (POLLIN | POLLERR | POLLHUP))) {
            char buffer[256];
            ssize_t n = recv(stream, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (n <= 0 && !(n < 0 && (errno == EAGAIN || errno == EINTR))) {
                int error = 0;
                socklen_t size = sizeof(error);
                if (getsockopt(stream, SOL_SOCKET, SO_ERROR, &error, &size) != 0)
                    error = errno;
                state.tcp_errno = n == 0 ? 0 : (error != 0 ? error : errno);
                state.tcp_established = 0;
                close(stream);
                stream = -1;
                if (save(&state, 1) != 0)
                    return fail("progress");
            }
        }
    }
}

static int start(int argc, char **argv)
{
    if (argc != 7) {
        errno = EINVAL;
        return fail("usage: start DIR HOST_IP TCP_PORT UDP_PORT LISTEN_PORT");
    }
    struct in_addr host;
    uint16_t tcp_port, udp_port, listen_port;
    if (inet_pton(AF_INET, argv[3], &host) != 1) {
        errno = EINVAL;
        return fail("host address");
    }
    if (parse_port(argv[4], &tcp_port) != 0 || parse_port(argv[5], &udp_port) != 0
        || parse_port(argv[6], &listen_port) != 0)
        return fail("port");
    if (mkdir(argv[2], 0700) != 0 && errno != EEXIST)
        return fail("state directory");
    char errors[4096], progress[4096];
    if (path_in(errors, sizeof(errors), argv[2], "workload.err") != 0
        || path_in(progress, sizeof(progress), argv[2], "progress") != 0)
        return fail("state path");
    pid_t child = fork();
    if (child < 0)
        return fail("fork");
    if (child == 0) {
        if (setsid() < 0)
            _exit(fail("setsid"));
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        int stderr_file = open(errors, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (null < 0 || stderr_file < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(null, STDOUT_FILENO) < 0
            || dup2(stderr_file, STDERR_FILENO) < 0)
            _exit(fail("detach stdio"));
        char path[4096];
        if (path_in(path, sizeof(path), argv[2], "pid") != 0)
            _exit(fail("pid path"));
        int pidfile = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        char text[32];
        int length = snprintf(text, sizeof(text), "%ld\n", (long)getpid());
        if (pidfile < 0 || length < 0 || write_all_at(pidfile, text, (size_t)length, 0) != 0
            || fsync(pidfile) != 0 || close(pidfile) != 0)
            _exit(fail("pid file"));
        _exit(workload(argv[2], host, tcp_port, udp_port, listen_port));
    }
    /* Ready means the first durable record exists: listener bound, TCP stream
     * established. An early workload exit reports its own stderr file. */
    for (int attempt = 0; attempt < 1000; ++attempt) {
        struct stat metadata;
        if (stat(progress, &metadata) == 0 && metadata.st_size == RECORD_BYTES) {
            printf("{\"pid\":%ld}\n", (long)child);
            return 0;
        }
        int code = 0;
        pid_t ended = waitpid(child, &code, WNOHANG);
        if (ended == child) {
            int stderr_file = open(errors, O_RDONLY | O_CLOEXEC);
            char message[1024];
            ssize_t n = stderr_file < 0 ? -1 : read(stderr_file, message, sizeof(message) - 1);
            if (n > 0) {
                message[n] = '\0';
                fprintf(stderr, "%s", message);
            }
            errno = ECHILD;
            return fail("workload setup exited");
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return fail("workload setup");
}

static int status(int argc, char **argv)
{
    if (argc != 3) {
        errno = EINVAL;
        return fail("usage: status DIR");
    }
    char path[4096], line[RECORD_BYTES + 1];
    if (path_in(path, sizeof(path), argv[2], "progress") != 0)
        return fail("progress path");
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return fail("open progress");
    ssize_t n = pread(fd, line, RECORD_BYTES, 0);
    if (n != RECORD_BYTES)
        return fail("read progress");
    line[RECORD_BYTES - 1] = '\0';
    char *end = strrchr(line, '}');
    if (end == NULL) {
        errno = EINVAL;
        return fail("progress record");
    }
    end[1] = '\0';
    printf("%s\n", line);
    return 0;
}

static int stream(int argc, char **argv)
{
    if (argc != 3) {
        errno = EINVAL;
        return fail("usage: stream DIR");
    }
    if (mkdir(argv[2], 0700) != 0 && errno != EEXIST)
        return fail("state directory");
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return fail("SIGPIPE");
    char path[4096];
    if (path_in(path, sizeof(path), argv[2], "stream") != 0)
        return fail("stream path");
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return fail("create stream record");
    char json[RECORD_BYTES];
    for (uint64_t seq = 1;; ++seq) {
        char line[96];
        int length = snprintf(line, sizeof(line), "SILO-RN-STREAM pid=%ld seq=%" PRIu64 "\n",
                              (long)getpid(), seq);
        ssize_t written = write(STDOUT_FILENO, line, (size_t)length);
        int error = written == length ? 0 : (written < 0 ? errno : EIO);
        int size = snprintf(json, sizeof(json), "{\"pid\":%ld,\"seq\":%" PRIu64 ",\"errno\":%d}",
                            (long)getpid(), error == 0 ? seq : seq - 1, error);
        if (size < 0 || record(fd, json, 1) != 0)
            return fail("stream record");
        if (error != 0)
            return 3;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 50000000};
        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR)
                return fail("nanosleep");
        }
    }
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "start") == 0)
        return start(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "status") == 0)
        return status(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "stream") == 0)
        return stream(argc, argv);
    fprintf(stderr, "usage: restore-network start|status|stream ...\n");
    return 2;
}
