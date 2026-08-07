/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef IP_RECVFRAGSIZE
#define IP_RECVFRAGSIZE 25
#endif
#ifndef IPV6_RECVFRAGSIZE
#define IPV6_RECVFRAGSIZE 77
#endif
#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 50
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 76
#endif

#define DNS_PACKET_UNICAST_SIZE_MAX 512U
#define DNS_PACKET_UNICAST_SIZE_LARGE_MAX 1232U
#define DNS_PACKET_SIZE_MAX 65535U
#define DNS_PACKET_INTERNET_SIZE_MAX 4096U
#define UDP4_PACKET_HEADER_SIZE 28U
#define UDP6_PACKET_HEADER_SIZE 48U

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t reload_requested = 0;

static void handle_signal(int signal_number) {
    if (signal_number == SIGHUP) {
        reload_requested = 1;
    } else {
        stop_requested = 1;
    }
}

int resolved_install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;

    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0) {
        return -errno;
    }
    return 0;
}

int resolved_take_reload(void) {
    const int value = reload_requested != 0;
    reload_requested = 0;
    return value;
}

int resolved_should_stop(void) {
    return stop_requested != 0;
}

int resolved_listen_fds(void) {
    const char *pid_text = getenv("LISTEN_PID");
    const char *fds_text = getenv("LISTEN_FDS");
    char *end = NULL;
    unsigned long pid_value;
    unsigned long fds_value;

    if (pid_text == NULL || fds_text == NULL) {
        return 0;
    }

    errno = 0;
    pid_value = strtoul(pid_text, &end, 10);
    if (errno != 0 || end == pid_text || *end != '\0' || pid_value != (unsigned long)getpid()) {
        return 0;
    }

    errno = 0;
    fds_value = strtoul(fds_text, &end, 10);
    if (errno != 0 || end == fds_text || *end != '\0' || fds_value > INT32_MAX) {
        return -EINVAL;
    }

    unsetenv("LISTEN_PID");
    unsetenv("LISTEN_FDS");
    unsetenv("LISTEN_FDNAMES");
    return (int)fds_value;
}

int resolved_notify(const char *state) {
    const char *socket_path = getenv("NOTIFY_SOCKET");
    struct sockaddr_un address;
    size_t path_length;
    socklen_t address_length;
    int fd;
    int result;

    if (state == NULL) {
        return -EINVAL;
    }
    if (socket_path == NULL || socket_path[0] == '\0') {
        return 0;
    }

    path_length = strlen(socket_path);
    if (path_length >= sizeof(address.sun_path)) {
        return -ENAMETOOLONG;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, path_length + 1U);
    if (address.sun_path[0] == '@') {
        address.sun_path[0] = '\0';
    }
    address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1U);

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -errno;
    }

    result = sendto(fd, state, strlen(state), MSG_NOSIGNAL,
                    (const struct sockaddr *)&address, address_length);
    if (result < 0) {
        result = -errno;
    } else {
        result = 1;
    }
    (void)close(fd);
    return result;
}

int resolved_peer_credentials(int fd, uint32_t *pid, uint32_t *uid, uint32_t *gid) {
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (pid == NULL || uid == NULL || gid == NULL) {
        return -EINVAL;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0) {
        return -errno;
    }
    if (length != sizeof(credentials)) {
        return -EIO;
    }

    *pid = (uint32_t)credentials.pid;
    *uid = (uint32_t)credentials.uid;
    *gid = (uint32_t)credentials.gid;
    return 0;
}

static int build_dns_sockaddr(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    struct sockaddr_storage *storage,
    socklen_t *length,
    int *family
) {
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;

    if (address == NULL || storage == NULL || length == NULL || family == NULL) {
        return -EINVAL;
    }

    memset(storage, 0, sizeof(*storage));
    ipv4 = (struct sockaddr_in *)storage;
    if (inet_pton(AF_INET, address, &ipv4->sin_addr) == 1) {
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        *length = sizeof(*ipv4);
        *family = AF_INET;
        return 0;
    }

    memset(storage, 0, sizeof(*storage));
    ipv6 = (struct sockaddr_in6 *)storage;
    if (inet_pton(AF_INET6, address, &ipv6->sin6_addr) == 1) {
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        ipv6->sin6_scope_id = scope_id != 0U
            ? scope_id
            : (ifindex > 0 ? (uint32_t)ifindex : 0U);
        *length = sizeof(*ipv6);
        *family = AF_INET6;
        return 0;
    }

    return -EINVAL;
}

static int sockaddr_is_loopback(const struct sockaddr_storage *storage, int family) {
    if (family == AF_INET) {
        const struct sockaddr_in *address = (const struct sockaddr_in *)storage;
        return (ntohl(address->sin_addr.s_addr) >> 24U) == 127U;
    }
    if (family == AF_INET6) {
        const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)storage;
        return IN6_IS_ADDR_LOOPBACK(&address->sin6_addr);
    }
    return 0;
}

static int sockaddr_is_local(const struct sockaddr_storage *storage, int family) {
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *entry;
    int found = 0;

    if (sockaddr_is_loopback(storage, family)) {
        return 1;
    }
    if (getifaddrs(&addresses) < 0) {
        return 0;
    }

    for (entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != family) {
            continue;
        }
        if (family == AF_INET) {
            const struct sockaddr_in *left = (const struct sockaddr_in *)storage;
            const struct sockaddr_in *right = (const struct sockaddr_in *)entry->ifa_addr;
            if (memcmp(&left->sin_addr, &right->sin_addr, sizeof(left->sin_addr)) == 0) {
                found = 1;
                break;
            }
        } else if (family == AF_INET6) {
            const struct sockaddr_in6 *left = (const struct sockaddr_in6 *)storage;
            const struct sockaddr_in6 *right = (const struct sockaddr_in6 *)entry->ifa_addr;
            if (memcmp(&left->sin6_addr, &right->sin6_addr, sizeof(left->sin6_addr)) == 0) {
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(addresses);
    return found;
}

static int set_unicast_if(int fd, int family, int ifindex) {
    const uint32_t ifindex_be = htonl((uint32_t)ifindex);
    int level;
    int option;

    if (ifindex <= 0) {
        return 0;
    }
    if (family == AF_INET) {
        level = IPPROTO_IP;
        option = IP_UNICAST_IF;
    } else if (family == AF_INET6) {
        level = IPPROTO_IPV6;
        option = IPV6_UNICAST_IF;
    } else {
        return -EAFNOSUPPORT;
    }

    if (setsockopt(fd, level, option, &ifindex_be, sizeof(ifindex_be)) < 0) {
        return -errno;
    }
    return 0;
}

static int bind_to_ifindex(int fd, int ifindex) {
#ifdef SO_BINDTOIFINDEX
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &ifindex, sizeof(ifindex)) < 0) {
        return -errno;
    }
    return 0;
#else
    char ifname[IF_NAMESIZE];

    if (ifindex <= 0) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NULL, 0) < 0) {
            return -errno;
        }
        return 0;
    }
    if (if_indextoname((unsigned int)ifindex, ifname) == NULL) {
        return -errno;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
        return -errno;
    }
    return 0;
#endif
}

static int prepare_link_connect(
    int fd,
    const struct sockaddr_storage *storage,
    int family,
    int ifindex,
    int *temporarily_bound
) {
    int result;

    *temporarily_bound = 0;
    if (ifindex <= 0 || sockaddr_is_local(storage, family)) {
        return 0;
    }

    result = set_unicast_if(fd, family, ifindex);
    if (result < 0) {
        return result;
    }
    result = bind_to_ifindex(fd, ifindex);
    if (result < 0) {
        return result;
    }
    *temporarily_bound = 1;
    return 0;
}

static int finish_link_connect(int fd, int temporarily_bound) {
    if (temporarily_bound == 0) {
        return 0;
    }
    return bind_to_ifindex(fd, 0);
}

int resolved_udp_connect(const char *address, uint16_t port, uint32_t scope_id, int ifindex) {
    struct sockaddr_storage storage;
    socklen_t length;
    int family;
    int fd;
    int result;
    int temporarily_bound;

    result = build_dns_sockaddr(address, port, scope_id, ifindex, &storage, &length, &family);
    if (result < 0) {
        return result;
    }

    fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -errno;
    }

    result = prepare_link_connect(fd, &storage, family, ifindex, &temporarily_bound);
    if (result < 0) {
        goto fail;
    }
    if (connect(fd, (const struct sockaddr *)&storage, length) < 0) {
        result = -errno;
        goto fail;
    }
    result = finish_link_connect(fd, temporarily_bound);
    if (result < 0) {
        goto fail;
    }
    return fd;

fail:
    (void)close(fd);
    return result;
}

int resolved_tcp_connect(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    uint32_t timeout_msec
) {
    struct sockaddr_storage storage;
    struct pollfd pollfd;
    socklen_t length;
    socklen_t error_length;
    int family;
    int fd;
    int flags;
    int result;
    int socket_error = 0;
    int temporarily_bound;
    const int one = 1;
    const int timeout = timeout_msec > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_msec;

    if (timeout_msec == 0U) {
        return -EINVAL;
    }
    result = build_dns_sockaddr(address, port, scope_id, ifindex, &storage, &length, &family);
    if (result < 0) {
        return result;
    }

    fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return -errno;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        result = -errno;
        goto fail;
    }

    result = prepare_link_connect(fd, &storage, family, ifindex, &temporarily_bound);
    if (result < 0) {
        goto fail;
    }
    if (connect(fd, (const struct sockaddr *)&storage, length) < 0 && errno != EINPROGRESS) {
        result = -errno;
        goto fail;
    }

    pollfd.fd = fd;
    pollfd.events = POLLOUT;
    pollfd.revents = 0;
    do {
        result = poll(&pollfd, 1, timeout);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        result = -errno;
        goto fail;
    }
    if (result == 0) {
        result = -ETIMEDOUT;
        goto fail;
    }

    error_length = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) < 0) {
        result = -errno;
        goto fail;
    }
    if (socket_error != 0) {
        result = -socket_error;
        goto fail;
    }

    result = finish_link_connect(fd, temporarily_bound);
    if (result < 0) {
        goto fail;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        result = -errno;
        goto fail;
    }
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        result = -errno;
        goto fail;
    }
    return fd;

fail:
    (void)close(fd);
    return result;
}

int resolved_udp_path_mtu(int fd, int ipv6) {
    int mtu = 0;
    socklen_t length = sizeof(mtu);
    const int level = ipv6 != 0 ? IPPROTO_IPV6 : IPPROTO_IP;
    const int option = ipv6 != 0 ? IPV6_MTU : IP_MTU;

    if (fd < 0) {
        return -EBADF;
    }
    if (getsockopt(fd, level, option, &mtu, &length) < 0) {
        return -errno;
    }
    if (length != sizeof(mtu) || mtu <= 0) {
        return -EIO;
    }
    return mtu;
}

int resolved_udp_enable_recvfragsize(int fd, int ipv6) {
    const int one = 1;
    const int level = ipv6 != 0 ? IPPROTO_IPV6 : IPPROTO_IP;
    const int option = ipv6 != 0 ? IPV6_RECVFRAGSIZE : IP_RECVFRAGSIZE;

    if (fd < 0) {
        return -EBADF;
    }
    if (setsockopt(fd, level, option, &one, sizeof(one)) < 0) {
        if (errno == ENOPROTOOPT || errno == EINVAL) {
            return 0;
        }
        return -errno;
    }
    return 1;
}

int64_t resolved_udp_recv(int fd, void *buffer, size_t capacity, uint32_t *fragment_size) {
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    ssize_t length;

    if (fd < 0 || buffer == NULL || fragment_size == NULL) {
        return -EINVAL;
    }

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    iov.iov_base = buffer;
    iov.iov_len = capacity;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    *fragment_size = 0;

    do {
        length = recvmsg(fd, &message, 0);
    } while (length < 0 && errno == EINTR);
    if (length < 0) {
        return -errno;
    }

    for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVFRAGSIZE) ||
            (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVFRAGSIZE)) {
            int value;
            if (cmsg->cmsg_len < CMSG_LEN(sizeof(value))) {
                return -EBADMSG;
            }
            memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
            if (value > 0) {
                *fragment_size = (uint32_t)value;
            }
        }
    }

    return (int64_t)length;
}

uint16_t resolved_dns_udp_payload_size(
    uint32_t path_mtu,
    int ipv6,
    int loopback,
    int fragmented,
    uint32_t received_udp_fragment_max
) {
    const uint32_t header_size = ipv6 != 0 ? UDP6_PACKET_HEADER_SIZE : UDP4_PACKET_HEADER_SIZE;
    uint32_t packet_size;

    if (loopback != 0) {
        packet_size = 65536U - header_size;
    } else {
        if (path_mtu == 0U) {
            packet_size = DNS_PACKET_UNICAST_SIZE_LARGE_MAX;
        } else if (path_mtu > header_size) {
            packet_size = path_mtu - header_size;
        } else {
            packet_size = 0U;
        }

        if (fragmented != 0 && received_udp_fragment_max > 0U &&
            received_udp_fragment_max < packet_size) {
            packet_size = received_udp_fragment_max;
        }
        if (packet_size > DNS_PACKET_INTERNET_SIZE_MAX) {
            packet_size = DNS_PACKET_INTERNET_SIZE_MAX;
        }
    }

    if (packet_size < DNS_PACKET_UNICAST_SIZE_MAX) {
        packet_size = DNS_PACKET_UNICAST_SIZE_MAX;
    }
    if (packet_size > DNS_PACKET_SIZE_MAX) {
        packet_size = DNS_PACKET_SIZE_MAX;
    }
    return (uint16_t)packet_size;
}
