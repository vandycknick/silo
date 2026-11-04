/* Smoke-only Linux probe. Compile with cc -static -O2 -Wall -Wextra -std=c11.
 * Observation and activation-hook modes never change network state. Setup is an
 * explicit source-fixture operation, not a hook or an activation repair path.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct netlink {
    int fd;
    uint32_t sequence;
};

struct request {
    struct nlmsghdr header;
    union {
        struct ifinfomsg link;
        struct ifaddrmsg address;
        struct rtmsg route;
        struct ndmsg neighbour;
    } body;
    unsigned char attributes[256];
};

struct saved_default {
    unsigned int index;
    int found;
    struct request route;
};

static int fail(const char *operation)
{
    fprintf(stderr, "guest-activation-network: %s: %s\n", operation, strerror(errno));
    return -1;
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void hex(FILE *output, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    fputc('"', output);
    for (size_t i = 0; i < length; ++i)
        fprintf(output, "%02x", bytes[i]);
    fputc('"', output);
}

static void json_string(FILE *output, const char *value, size_t length)
{
    fputc('"', output);
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c == '"' || c == '\\')
            fprintf(output, "\\%c", c);
        else if (c < 32 || c > 126)
            fprintf(output, "\\u%04x", c);
        else
            fputc(c, output);
    }
    fputc('"', output);
}

static int file_hex(FILE *output, const char *path)
{
    unsigned char buffer[4096];
    size_t total = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return fail(path);
    fputc('"', output);
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            close(fd);
            return fail(path);
        }
        if (!count)
            break;
        total += (size_t)count;
        if (total > 65536) {
            close(fd);
            errno = EFBIG;
            return fail(path);
        }
        for (ssize_t i = 0; i < count; ++i)
            fprintf(output, "%02x", buffer[i]);
    }
    fputc('"', output);
    return close(fd) == 0 ? 0 : fail("close observed file");
}

static int netlink_open(struct netlink *netlink)
{
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    struct timeval timeout = {.tv_sec = 2};
    netlink->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    netlink->sequence = 0;
    if (netlink->fd < 0)
        return fail("open rtnetlink");
    if (bind(netlink->fd, (struct sockaddr *)&local, sizeof(local)) < 0 ||
        setsockopt(netlink->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int saved = errno;
        close(netlink->fd);
        errno = saved;
        return fail("bind/configure rtnetlink");
    }
    return 0;
}

static void request_init(struct netlink *netlink, struct request *request,
                         uint16_t type, uint16_t flags, size_t body_size)
{
    memset(request, 0, sizeof(*request));
    request->header.nlmsg_len = NLMSG_LENGTH(body_size);
    request->header.nlmsg_type = type;
    request->header.nlmsg_flags = NLM_F_REQUEST | flags;
    request->header.nlmsg_seq = ++netlink->sequence;
}

static int attribute(struct request *request, uint16_t type, const void *data, size_t length)
{
    size_t offset = NLMSG_ALIGN(request->header.nlmsg_len);
    size_t end = offset + RTA_SPACE(length);
    if (end > sizeof(*request)) {
        errno = E2BIG;
        return fail("netlink attribute size");
    }
    struct rtattr *attr = (struct rtattr *)((unsigned char *)request + offset);
    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(length);
    memcpy(RTA_DATA(attr), data, length);
    request->header.nlmsg_len = (uint32_t)end;
    return 0;
}

static int send_request(struct netlink *netlink, const struct request *request)
{
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t count;
    do {
        count = sendto(netlink->fd, request, request->header.nlmsg_len, 0,
                       (struct sockaddr *)&kernel, sizeof(kernel));
    } while (count < 0 && errno == EINTR);
    if (count != (ssize_t)request->header.nlmsg_len)
        return fail("send rtnetlink request");
    return 0;
}

static int receive(struct netlink *netlink, unsigned char *buffer, size_t capacity)
{
    struct sockaddr_nl peer = {0};
    struct iovec iov = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr message = {.msg_name = &peer, .msg_namelen = sizeof(peer),
                             .msg_iov = &iov, .msg_iovlen = 1};
    ssize_t count;
    do {
        count = recvmsg(netlink->fd, &message, 0);
    } while (count < 0 && errno == EINTR);
    if (count < 0)
        return fail("receive rtnetlink");
    if (!count || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || peer.nl_pid != 0) {
        errno = EPROTO;
        return fail("truncated/non-kernel rtnetlink response");
    }
    return (int)count;
}

static int netlink_error(const struct nlmsghdr *header)
{
    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
        errno = EPROTO;
        return fail("short rtnetlink error");
    }
    const struct nlmsgerr *error = NLMSG_DATA(header);
    if (error->error) {
        errno = -error->error;
        return fail("kernel rtnetlink error");
    }
    return 0;
}

static int ack(struct netlink *netlink, const struct request *request)
{
    unsigned char buffer[8192];
    if (send_request(netlink, request) < 0)
        return -1;
    uint64_t deadline = monotonic_ms() + 3000;
    while (monotonic_ms() < deadline) {
        int remaining = receive(netlink, buffer, sizeof(buffer));
        if (remaining < 0)
            return -1;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq == request->header.nlmsg_seq && header->nlmsg_type == NLMSG_ERROR)
                return netlink_error(header);
        }
        if (remaining) {
            errno = EPROTO;
            return fail("malformed rtnetlink acknowledgement");
        }
    }
    errno = ETIMEDOUT;
    return fail("rtnetlink acknowledgement deadline");
}

static void address_attribute(FILE *output, const char *name, int family,
                              const struct rtattr *attr)
{
    char text[INET6_ADDRSTRLEN];
    size_t size = family == AF_INET ? 4 : family == AF_INET6 ? 16 : 0;
    if (size && RTA_PAYLOAD(attr) == size && inet_ntop(family, RTA_DATA(attr), text, sizeof(text)))
        fprintf(output, ",\"%s\":\"%s\"", name, text);
}

static void integer_attribute(FILE *output, const char *name, const struct rtattr *attr)
{
    uint32_t value;
    if (RTA_PAYLOAD(attr) != sizeof(value))
        return;
    memcpy(&value, RTA_DATA(attr), sizeof(value));
    fprintf(output, ",\"%s\":%u", name, value);
}

static int record(FILE *output, const struct nlmsghdr *header, uint16_t expected)
{
    size_t size;
    int family;
    if (expected == RTM_NEWLINK) {
        size = sizeof(struct ifinfomsg);
        if (header->nlmsg_len < NLMSG_LENGTH(size))
            goto malformed;
        const struct ifinfomsg *link = NLMSG_DATA(header);
        family = link->ifi_family;
        fprintf(output, "{\"ifindex\":%d,\"flags\":%u,\"link_type\":%u",
                link->ifi_index, link->ifi_flags, link->ifi_type);
    } else if (expected == RTM_NEWADDR) {
        size = sizeof(struct ifaddrmsg);
        if (header->nlmsg_len < NLMSG_LENGTH(size))
            goto malformed;
        const struct ifaddrmsg *address = NLMSG_DATA(header);
        family = address->ifa_family;
        fprintf(output, "{\"ifindex\":%u,\"prefix_length\":%u,\"scope\":%u,\"flags\":%u",
                address->ifa_index, address->ifa_prefixlen, address->ifa_scope, address->ifa_flags);
    } else if (expected == RTM_NEWROUTE) {
        size = sizeof(struct rtmsg);
        if (header->nlmsg_len < NLMSG_LENGTH(size))
            goto malformed;
        const struct rtmsg *route = NLMSG_DATA(header);
        family = route->rtm_family;
        fprintf(output, "{\"dst_length\":%u,\"src_length\":%u,\"table\":%u,"
                "\"protocol\":%u,\"scope\":%u,\"route_type\":%u,\"flags\":%u",
                route->rtm_dst_len, route->rtm_src_len, route->rtm_table, route->rtm_protocol,
                route->rtm_scope, route->rtm_type, route->rtm_flags);
    } else {
        size = sizeof(struct ndmsg);
        if (header->nlmsg_len < NLMSG_LENGTH(size))
            goto malformed;
        const struct ndmsg *neighbour = NLMSG_DATA(header);
        family = neighbour->ndm_family;
        fprintf(output, "{\"ifindex\":%d,\"state\":%u,\"flags\":%u,\"neighbour_type\":%u",
                neighbour->ndm_ifindex, neighbour->ndm_state, neighbour->ndm_flags, neighbour->ndm_type);
    }
    fprintf(output, ",\"family\":%d,\"raw_hex\":", family);
    hex(output, header, header->nlmsg_len);
    int remaining = (int)header->nlmsg_len - (int)NLMSG_LENGTH(size);
    const struct rtattr *attr = (const struct rtattr *)((const unsigned char *)NLMSG_DATA(header) + NLMSG_ALIGN(size));
    for (; RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
        unsigned int type = attr->rta_type & NLA_TYPE_MASK;
        if (expected == RTM_NEWLINK) {
            if (type == IFLA_IFNAME) {
                fprintf(output, ",\"name\":");
                json_string(output, RTA_DATA(attr), strnlen(RTA_DATA(attr), RTA_PAYLOAD(attr)));
            } else if (type == IFLA_ADDRESS) {
                fprintf(output, ",\"mac_hex\":");
                hex(output, RTA_DATA(attr), RTA_PAYLOAD(attr));
            } else if (type == IFLA_MASTER)
                integer_attribute(output, "master", attr);
        } else if (expected == RTM_NEWADDR) {
            if (type == IFA_ADDRESS)
                address_attribute(output, "address", family, attr);
            else if (type == IFA_LOCAL)
                address_attribute(output, "local", family, attr);
            else if (type == IFA_FLAGS)
                integer_attribute(output, "extended_flags", attr);
        } else if (expected == RTM_NEWROUTE) {
            if (type == RTA_OIF)
                integer_attribute(output, "oif", attr);
            else if (type == RTA_IIF)
                integer_attribute(output, "iif", attr);
            else if (type == RTA_GATEWAY)
                address_attribute(output, "gateway", family, attr);
            else if (type == RTA_DST)
                address_attribute(output, "destination", family, attr);
            else if (type == RTA_PREFSRC)
                address_attribute(output, "preferred_source", family, attr);
        } else {
            if (type == NDA_DST)
                address_attribute(output, "destination", family, attr);
            else if (type == NDA_LLADDR) {
                fprintf(output, ",\"mac_hex\":");
                hex(output, RTA_DATA(attr), RTA_PAYLOAD(attr));
            }
        }
    }
    if (remaining)
        goto malformed;
    fputc('}', output);
    return 0;
malformed:
    errno = EPROTO;
    return fail("malformed rtnetlink record");
}

static int capture_default(struct saved_default *saved, const struct nlmsghdr *header)
{
    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) {
        errno = EPROTO;
        return fail("short default-route dump record");
    }
    const struct rtmsg *route = NLMSG_DATA(header);
    if (route->rtm_family != AF_INET || route->rtm_type != RTN_UNICAST ||
        route->rtm_protocol != RTPROT_STATIC || route->rtm_dst_len || route->rtm_src_len)
        return 0;
    uint32_t table = route->rtm_table, index = 0;
    int gateway_present = 0;
    int remaining = (int)header->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*route));
    const struct rtattr *attr = RTM_RTA(route);
    for (; RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
        unsigned int type = attr->rta_type & NLA_TYPE_MASK;
        if (type == RTA_OIF && RTA_PAYLOAD(attr) == sizeof(index))
            memcpy(&index, RTA_DATA(attr), sizeof(index));
        else if (type == RTA_TABLE && RTA_PAYLOAD(attr) == sizeof(table))
            memcpy(&table, RTA_DATA(attr), sizeof(table));
        else if (type == RTA_GATEWAY && RTA_PAYLOAD(attr) == sizeof(struct in_addr))
            gateway_present = 1;
    }
    if (remaining) {
        errno = EPROTO;
        return fail("malformed managed default-route attributes");
    }
    if (table != RT_TABLE_MAIN || index != saved->index || !gateway_present)
        return 0;
    if (saved->found || header->nlmsg_len > sizeof(saved->route)) {
        errno = saved->found ? EEXIST : E2BIG;
        return fail("ambiguous/oversized source managed default route");
    }
    memset(&saved->route, 0, sizeof(saved->route));
    memcpy(&saved->route, header, header->nlmsg_len);
    saved->found = 1;
    return 0;
}

static int dump(struct netlink *netlink, FILE *output, uint16_t type, int family, int proxy,
                struct saved_default *saved)
{
    struct request request;
    size_t body_size = type == RTM_GETLINK ? sizeof(struct ifinfomsg) :
                       type == RTM_GETADDR ? sizeof(struct ifaddrmsg) :
                       type == RTM_GETROUTE ? sizeof(struct rtmsg) : sizeof(struct ndmsg);
    request_init(netlink, &request, type, NLM_F_DUMP, body_size);
    /* The family byte is the first member of every rtnetlink body above. */
    request.body.link.ifi_family = (unsigned char)family;
    if (type == RTM_GETNEIGH)
        request.body.neighbour.ndm_flags = proxy ? NTF_PROXY : 0;
    if (send_request(netlink, &request) < 0)
        return -1;
    if (output)
        fputc('[', output);
    unsigned int records = 0;
    size_t bytes = 0;
    uint64_t deadline = monotonic_ms() + 3000;
    while (monotonic_ms() < deadline) {
        unsigned char buffer[65536];
        int remaining = receive(netlink, buffer, sizeof(buffer));
        if (remaining < 0)
            return -1;
        bytes += (size_t)remaining;
        if (bytes > 4 * 1024 * 1024) {
            errno = EFBIG;
            return fail("netlink dump bound");
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != request.header.nlmsg_seq)
                continue;
            if (header->nlmsg_flags & NLM_F_DUMP_INTR) {
                errno = EINTR;
                return fail("kernel interrupted netlink dump");
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                if (netlink_error(header) < 0)
                    return -1;
                continue;
            }
            if (header->nlmsg_type == NLMSG_DONE) {
                if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(int))) {
                    int status;
                    memcpy(&status, NLMSG_DATA(header), sizeof(status));
                    if (status) {
                        errno = status < 0 ? -status : status;
                        return fail("netlink dump terminal error");
                    }
                }
                if (output)
                    fputc(']', output);
                return 0;
            }
            if (header->nlmsg_type != type - 2) {
                errno = EPROTO;
                return fail("unexpected netlink dump record type");
            }
            if (++records > 4096) {
                errno = EFBIG;
                return fail("netlink record bound");
            }
            if (saved && capture_default(saved, header) < 0)
                return -1;
            if (output) {
                if (records > 1)
                    fputc(',', output);
                if (record(output, header, type - 2) < 0)
                    return -1;
            }
        }
        if (remaining) {
            errno = EPROTO;
            return fail("malformed netlink dump datagram");
        }
    }
    errno = ETIMEDOUT;
    return fail("netlink dump deadline");
}

static int observe(FILE *output, unsigned int index)
{
    char name[IF_NAMESIZE];
    if (!if_indextoname(index, name))
        return fail("resolve observed interface index");
    struct netlink netlink;
    if (netlink_open(&netlink) < 0)
        return -1;
    fprintf(output, "{\"schema\":1,\"ifindex\":%u,\"observed_monotonic_ms\":%llu,\"name\":",
            index, (unsigned long long)monotonic_ms());
    json_string(output, name, strlen(name));
    const struct { const char *name; uint16_t type; int family; int proxy; } dumps[] = {
        {"links", RTM_GETLINK, AF_UNSPEC, 0},
        {"addresses", RTM_GETADDR, AF_UNSPEC, 0},
        {"routes_ipv4", RTM_GETROUTE, AF_INET, 0},
        {"routes_ipv6", RTM_GETROUTE, AF_INET6, 0},
        {"neighbours", RTM_GETNEIGH, AF_UNSPEC, 0},
        {"proxy_neighbours", RTM_GETNEIGH, AF_UNSPEC, 1},
    };
    int result = 0;
    for (size_t i = 0; i < sizeof(dumps) / sizeof(dumps[0]); ++i) {
        fprintf(output, ",\"%s\":", dumps[i].name);
        if (dump(&netlink, output, dumps[i].type, dumps[i].family, dumps[i].proxy, NULL) < 0) {
            result = -1;
            break;
        }
    }
    close(netlink.fd);
    if (result < 0)
        return -1;
    fprintf(output, ",\"resolv_conf_hex\":");
    if (file_hex(output, "/etc/resolv.conf") < 0)
        return -1;
    fprintf(output, ",\"self_cgroup_hex\":");
    if (file_hex(output, "/proc/self/cgroup") < 0)
        return -1;
    fprintf(output, ",\"self_pid\":%ld}\n", (long)getpid());
    return ferror(output) ? fail("write network observation") : 0;
}

static int rename_link(struct netlink *netlink, unsigned int index, const char *name)
{
    if (!*name || strlen(name) >= IF_NAMESIZE || strchr(name, '/') || strchr(name, ':')) {
        errno = EINVAL;
        return fail("invalid fixture interface name");
    }
    /* NETDEV_DOWN removes the managed default. Preserve its actual kernel
     * message before changing the cold fixture, never synthesize a new route
     * from expected configuration or repair one inside activation.
     */
    struct saved_default saved = {.index = index};
    if (dump(netlink, NULL, RTM_GETROUTE, AF_INET, 0, &saved) < 0)
        return -1;
    if (!saved.found) {
        errno = ENOENT;
        return fail("source managed static default route missing before rename");
    }
    struct request request;
    request_init(netlink, &request, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
    request.body.link.ifi_index = (int)index;
    request.body.link.ifi_change = IFF_UP;
    if (ack(netlink, &request) < 0)
        return -1;
    request_init(netlink, &request, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
    request.body.link.ifi_index = (int)index;
    if (attribute(&request, IFLA_IFNAME, name, strlen(name) + 1) < 0 || ack(netlink, &request) < 0)
        return -1;
    request_init(netlink, &request, RTM_NEWLINK, NLM_F_ACK, sizeof(struct ifinfomsg));
    request.body.link.ifi_index = (int)index;
    request.body.link.ifi_change = IFF_UP;
    request.body.link.ifi_flags = IFF_UP;
    if (ack(netlink, &request) < 0)
        return -1;
    saved.route.header.nlmsg_type = RTM_NEWROUTE;
    saved.route.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    saved.route.header.nlmsg_seq = ++netlink->sequence;
    saved.route.header.nlmsg_pid = 0;
    return ack(netlink, &saved.route);
}

static int seed_neighbour(struct netlink *netlink, unsigned int index, const char *ip,
                           const unsigned char *mac, int proxy)
{
    struct in_addr address;
    if (inet_pton(AF_INET, ip, &address) != 1) {
        errno = EINVAL;
        return fail("invalid neighbour IPv4");
    }
    struct request request;
    request_init(netlink, &request, RTM_NEWNEIGH, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                 sizeof(struct ndmsg));
    request.body.neighbour.ndm_family = AF_INET;
    request.body.neighbour.ndm_ifindex = (int)index;
    request.body.neighbour.ndm_state = NUD_PERMANENT;
    request.body.neighbour.ndm_flags = proxy ? NTF_PROXY : 0;
    if (attribute(&request, NDA_DST, &address, sizeof(address)) < 0 ||
        (!proxy && attribute(&request, NDA_LLADDR, mac, 6) < 0))
        return -1;
    return ack(netlink, &request);
}

static int parse_mac(const char *text, unsigned char *mac)
{
    unsigned int values[6];
    int end = 0;
    if (strlen(text) != 17 || sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%n", &values[0], &values[1],
                                   &values[2], &values[3], &values[4], &values[5], &end) != 6 || end != 17) {
        errno = EINVAL;
        return fail("invalid seed MAC");
    }
    for (size_t i = 0; i < 6; ++i)
        mac[i] = (unsigned char)values[i];
    if (mac[0] & 1 || !memcmp(mac, "\0\0\0\0\0\0", 6)) {
        errno = EINVAL;
        return fail("seed MAC must be nonzero unicast");
    }
    return 0;
}

static uint16_t checksum(const unsigned char *data, size_t length)
{
    uint32_t sum = 0;
    while (length >= 2) {
        sum += (uint32_t)data[0] << 8 | data[1];
        data += 2;
        length -= 2;
    }
    if (length)
        sum += (uint32_t)data[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int gateway(const char *ip, const char *nonce)
{
    size_t length = strlen(nonce);
    struct sockaddr_in address = {.sin_family = AF_INET};
    if (!length || length > 64 || inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        errno = EINVAL;
        return fail("gateway requires IPv4 and 1..64 printable ASCII nonce bytes");
    }
    for (size_t i = 0; i < length; ++i) {
        if ((unsigned char)nonce[i] < 33 || (unsigned char)nonce[i] > 126) {
            errno = EINVAL;
            return fail("gateway nonce must be printable ASCII");
        }
    }
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    if (fd < 0)
        return fail("open gateway ICMP socket");
    int result = -1;
    struct sockaddr_in source = {0};
    socklen_t source_size = sizeof(source);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        getsockname(fd, (struct sockaddr *)&source, &source_size) < 0) {
        fail("connect kernel gateway route");
        goto done;
    }
    unsigned char request[72] = {8, 0, 0, 0, 0, 0, 0, 1};
    uint16_t identifier = (uint16_t)getpid();
    request[4] = (unsigned char)(identifier >> 8);
    request[5] = (unsigned char)identifier;
    memcpy(request + 8, nonce, length);
    uint16_t sum = checksum(request, length + 8);
    request[2] = (unsigned char)(sum >> 8);
    request[3] = (unsigned char)sum;
    ssize_t count = send(fd, request, length + 8, 0);
    if (count != (ssize_t)(length + 8)) {
        fail("send actual gateway nonce echo");
        goto done;
    }
    uint64_t deadline = monotonic_ms() + 3000;
    while (monotonic_ms() < deadline) {
        struct pollfd pollfd = {.fd = fd, .events = POLLIN};
        uint64_t now = monotonic_ms();
        if (now >= deadline)
            break;
        int remaining = (int)(deadline - now);
        int ready = poll(&pollfd, 1, remaining);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0) {
            fail("poll gateway reply");
            goto done;
        }
        if (!ready)
            break;
        unsigned char response[2048];
        count = recv(fd, response, sizeof(response), MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (count < 0) {
            fail("receive gateway reply");
            goto done;
        }
        if (count < 28 || response[0] >> 4 != 4)
            continue;
        size_t ihl = (response[0] & 15) * 4;
        size_t total = (size_t)response[2] << 8 | response[3];
        if (ihl < 20 || total > (size_t)count || total != ihl + length + 8 ||
            checksum(response, ihl) || response[9] != IPPROTO_ICMP ||
            ((response[6] & 0x3f) || response[7]) ||
            memcmp(response + 12, &address.sin_addr, 4) ||
            memcmp(response + 16, &source.sin_addr, 4))
            continue;
        const unsigned char *icmp = response + ihl;
        if (icmp[0] || icmp[1] || checksum(icmp, total - ihl) ||
            memcmp(icmp + 4, request + 4, length + 4))
            continue;
        char source_text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &source.sin_addr, source_text, sizeof(source_text))) {
            fail("format gateway source");
            goto done;
        }
        fprintf(stdout, "{\"schema\":1,\"protocol\":\"icmp\",\"gateway\":\"%s\","
                "\"source_ipv4\":\"%s\",\"identifier\":%u,\"sequence\":1,\"nonce\":",
                ip, source_text, identifier);
        json_string(stdout, nonce, length);
        fprintf(stdout, ",\"request_icmp_hex\":");
        hex(stdout, request, length + 8);
        fprintf(stdout, ",\"reply_ipv4_hex\":");
        hex(stdout, response, total);
        fprintf(stdout, ",\"observed_monotonic_ms\":%llu}\n", (unsigned long long)monotonic_ms());
        result = ferror(stdout) ? fail("write gateway evidence") : 0;
        goto done;
    }
    errno = ETIMEDOUT;
    fail("matching actual gateway nonce reply");
done:
    close(fd);
    return result;
}

static int increment_marker(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return fail("open hook marker");
    int result = -1;
    struct stat metadata;
    if (flock(fd, LOCK_EX) < 0 || fstat(fd, &metadata) < 0) {
        fail("lock/stat hook marker");
        goto done;
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_size > 20) {
        errno = EINVAL;
        fail("invalid hook marker file");
        goto done;
    }
    char buffer[32] = {0};
    ssize_t count;
    do {
        count = read(fd, buffer, sizeof(buffer) - 1);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        fail("read hook marker");
        goto done;
    }
    if (count != metadata.st_size) {
        errno = EIO;
        fail("short hook marker read");
        goto done;
    }
    unsigned long long value = 0;
    if (count) {
        for (ssize_t i = 0; i < count; ++i) {
            if ((buffer[i] < '0' || buffer[i] > '9') && !(i == count - 1 && buffer[i] == '\n')) {
                errno = EINVAL;
                fail("malformed hook marker");
                goto done;
            }
        }
        char *end;
        errno = 0;
        value = strtoull(buffer, &end, 10);
        if (errno || end == buffer || (*end && strcmp(end, "\n")) || value == ULLONG_MAX) {
            errno = EINVAL;
            fail("malformed/overflowed hook marker");
            goto done;
        }
    }
    int length = snprintf(buffer, sizeof(buffer), "%llu\n", value + 1);
    if (pwrite(fd, buffer, (size_t)length, 0) != length || ftruncate(fd, length) < 0 || fsync(fd) < 0) {
        fail("persist hook marker");
        goto done;
    }
    result = 0;
done:
    close(fd);
    return result;
}

static int observation_file(unsigned int index, const char *path)
{
    if (!path)
        return observe(stdout, index);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return fail("open network observation output");
    FILE *output = fdopen(fd, "w");
    if (!output) {
        close(fd);
        return fail("open observation stream");
    }
    int result = observe(output, index);
    if (fflush(output) != 0 || fsync(fd) != 0)
        result = fail("persist network observation");
    if (fclose(output) != 0)
        result = fail("close observation output");
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "gateway"))
        return gateway(argv[2], argv[3]) < 0 ? 1 : 0;
    if (argc < 3)
        goto usage;
    char *end;
    errno = 0;
    unsigned long parsed = strtoul(argv[2], &end, 10);
    if (errno || end == argv[2] || *end || !parsed || parsed > INT_MAX) {
        errno = EINVAL;
        fail("invalid interface index");
        return 1;
    }
    unsigned int index = (unsigned int)parsed;
    if (!strcmp(argv[1], "observe") && (argc == 3 || argc == 4))
        return observation_file(index, argc == 4 ? argv[3] : NULL) < 0 ? 1 : 0;
    if (!strcmp(argv[1], "hook") && argc == 5) {
        if (observation_file(index, argv[3]) < 0 || increment_marker(argv[4]) < 0)
            return 1;
        return 0;
    }
    if (!strcmp(argv[1], "setup") && argc == 7) {
        unsigned char mac[6];
        struct in_addr ordinary, proxy;
        if (parse_mac(argv[6], mac) < 0)
            return 1;
        if (inet_pton(AF_INET, argv[4], &ordinary) != 1 ||
            inet_pton(AF_INET, argv[5], &proxy) != 1 || ordinary.s_addr == proxy.s_addr) {
            errno = EINVAL;
            fail("seed neighbours require distinct IPv4 addresses");
            return 1;
        }
        struct netlink netlink;
        if (netlink_open(&netlink) < 0)
            return 1;
        int result = rename_link(&netlink, index, argv[3]);
        if (!result)
            result = seed_neighbour(&netlink, index, argv[4], mac, 0);
        if (!result)
            result = seed_neighbour(&netlink, index, argv[5], mac, 1);
        close(netlink.fd);
        if (result < 0)
            return 1;
        return observe(stdout, index) < 0 ? 1 : 0;
    }
usage:
    fprintf(stderr, "usage: guest-activation-network observe IFINDEX [OUTPUT]\n"
            "       guest-activation-network setup IFINDEX NEWNAME ORDINARY_IP PROXY_IP MAC\n"
            "       guest-activation-network hook IFINDEX OUTPUT MARKER\n"
            "       guest-activation-network gateway GATEWAY_IPV4 NONCE\n");
    return 2;
}
