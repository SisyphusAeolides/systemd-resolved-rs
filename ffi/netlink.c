/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(IF_NAMESIZE == RESOLVED_IFNAME_MAX, "interface name ABI size mismatch");

enum {
    RESOLVED_IF_OPER_UNKNOWN = 0,
    RESOLVED_IF_OPER_NOTPRESENT = 1,
    RESOLVED_IF_OPER_DOWN = 2,
    RESOLVED_IF_OPER_LOWERLAYERDOWN = 3,
    RESOLVED_IF_OPER_TESTING = 4,
    RESOLVED_IF_OPER_DORMANT = 5,
    RESOLVED_IF_OPER_UP = 6,
};

static int sysfs_path(char *buffer, size_t capacity, const char *ifname, const char *property) {
    int length;

    length = snprintf(buffer, capacity, "/sys/class/net/%s/%s", ifname, property);
    if (length < 0 || (size_t)length >= capacity) {
        return -ENAMETOOLONG;
    }
    return 0;
}

static uint32_t read_u32_property(const char *ifname, const char *property, int base) {
    char path[PATH_MAX];
    char text[64];
    char *end = NULL;
    unsigned long value;
    FILE *file;

    if (sysfs_path(path, sizeof(path), ifname, property) < 0) {
        return 0;
    }
    file = fopen(path, "re");
    if (file == NULL) {
        return 0;
    }
    if (fgets(text, sizeof(text), file) == NULL) {
        (void)fclose(file);
        return 0;
    }
    (void)fclose(file);

    errno = 0;
    value = strtoul(text, &end, base);
    if (errno != 0 || end == text || value > UINT32_MAX) {
        return 0;
    }
    return (uint32_t)value;
}

static uint8_t read_operstate(const char *ifname) {
    char path[PATH_MAX];
    char state[32];
    FILE *file;

    if (sysfs_path(path, sizeof(path), ifname, "operstate") < 0) {
        return RESOLVED_IF_OPER_UNKNOWN;
    }
    file = fopen(path, "re");
    if (file == NULL) {
        return RESOLVED_IF_OPER_UNKNOWN;
    }
    if (fgets(state, sizeof(state), file) == NULL) {
        (void)fclose(file);
        return RESOLVED_IF_OPER_UNKNOWN;
    }
    (void)fclose(file);

    if (strncmp(state, "notpresent", 10) == 0) return RESOLVED_IF_OPER_NOTPRESENT;
    if (strncmp(state, "down", 4) == 0) return RESOLVED_IF_OPER_DOWN;
    if (strncmp(state, "lowerlayerdown", 14) == 0) return RESOLVED_IF_OPER_LOWERLAYERDOWN;
    if (strncmp(state, "testing", 7) == 0) return RESOLVED_IF_OPER_TESTING;
    if (strncmp(state, "dormant", 7) == 0) return RESOLVED_IF_OPER_DORMANT;
    if (strncmp(state, "up", 2) == 0) return RESOLVED_IF_OPER_UP;
    return RESOLVED_IF_OPER_UNKNOWN;
}

static int find_snapshot(resolved_link_info *entries, size_t length, unsigned int ifindex) {
    size_t index;

    for (index = 0; index < length; index++) {
        if ((unsigned int)entries[index].ifindex == ifindex) {
            return (int)index;
        }
    }
    return -1;
}

static bool ipv4_is_link_local(const struct in_addr *address) {
    const uint32_t value = ntohl(address->s_addr);
    return (value & 0xffff0000U) == 0xa9fe0000U;
}

static bool ipv4_is_usable_global(const struct in_addr *address) {
    const uint32_t value = ntohl(address->s_addr);
    if (value == 0U || (value >> 24U) == 127U || (value & 0xf0000000U) == 0xe0000000U) {
        return false;
    }
    return !ipv4_is_link_local(address);
}

static void collect_addresses(resolved_link_info *entries, size_t length) {
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *entry;

    if (entries == NULL || length == 0 || getifaddrs(&addresses) < 0) {
        return;
    }

    for (entry = addresses; entry != NULL; entry = entry->ifa_next) {
        unsigned int ifindex;
        int index;

        if (entry->ifa_addr == NULL || entry->ifa_name == NULL) {
            continue;
        }
        ifindex = if_nametoindex(entry->ifa_name);
        if (ifindex == 0U) {
            continue;
        }
        index = find_snapshot(entries, length, ifindex);
        if (index < 0) {
            continue;
        }

        if (entry->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *address = (const struct sockaddr_in *)entry->ifa_addr;
            if (ipv4_is_link_local(&address->sin_addr)) {
                entries[index].has_ipv4_link_local = 1;
            } else if (ipv4_is_usable_global(&address->sin_addr)) {
                entries[index].has_ipv4_global = 1;
            }
        } else if (entry->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)entry->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr)) {
                entries[index].has_ipv6_link_local = 1;
            } else if (!IN6_IS_ADDR_UNSPECIFIED(&address->sin6_addr) &&
                       !IN6_IS_ADDR_LOOPBACK(&address->sin6_addr) &&
                       !IN6_IS_ADDR_MULTICAST(&address->sin6_addr)) {
                entries[index].has_ipv6_global = 1;
            }
        }
    }

    freeifaddrs(addresses);
}

int64_t resolved_link_snapshot(resolved_link_info *entries, size_t capacity) {
    struct if_nameindex *interfaces;
    struct if_nameindex *interface;
    size_t count = 0;
    size_t filled = 0;

    if (entries == NULL && capacity != 0) {
        return -EINVAL;
    }

    interfaces = if_nameindex();
    if (interfaces == NULL) {
        return -errno;
    }
    for (interface = interfaces; interface->if_index != 0U && interface->if_name != NULL; interface++) {
        count++;
    }
    if (entries == NULL || capacity == 0) {
        if_freenameindex(interfaces);
        return (int64_t)count;
    }

    memset(entries, 0, capacity * sizeof(*entries));
    for (interface = interfaces;
         interface->if_index != 0U && interface->if_name != NULL && filled < capacity;
         interface++, filled++) {
        resolved_link_info *snapshot = &entries[filled];

        snapshot->ifindex = (int32_t)interface->if_index;
        (void)snprintf(snapshot->ifname, sizeof(snapshot->ifname), "%s", interface->if_name);
        snapshot->flags = read_u32_property(interface->if_name, "flags", 0);
        snapshot->mtu = read_u32_property(interface->if_name, "mtu", 10);
        snapshot->operstate = read_operstate(interface->if_name);
    }

    if_freenameindex(interfaces);
    collect_addresses(entries, filled);
    return (int64_t)count;
}

int resolved_rtnl_open(void) {
    struct sockaddr_nl address;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }

    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_LINK |
                        RTMGRP_IPV4_IFADDR |
                        RTMGRP_IPV6_IFADDR |
                        RTMGRP_IPV4_ROUTE |
                        RTMGRP_IPV6_ROUTE;
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        const int error = errno;
        (void)close(fd);
        return -error;
    }
    return fd;
}

int resolved_rtnl_wait(int fd, uint32_t timeout_msec) {
    struct pollfd descriptor;
    char buffer[16384];
    int timeout;
    int result;
    bool changed = false;

    if (fd < 0) {
        return -EBADF;
    }
    timeout = timeout_msec > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_msec;
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;

    do {
        result = poll(&descriptor, 1, timeout);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        return -errno;
    }
    if (result == 0) {
        return 0;
    }
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        return -EIO;
    }

    for (;;) {
        ssize_t length = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (length > 0) {
            changed = true;
            continue;
        }
        if (length == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        return -errno;
    }
    return changed ? 1 : 0;
}
