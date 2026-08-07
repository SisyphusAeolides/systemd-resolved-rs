// SPDX-License-Identifier: LGPL-2.1-or-later
#include "mdns.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *message)
{
    fprintf(stderr, "test_mdns: %s\n", message);
    exit(EXIT_FAILURE);
}

int main(void)
{
    errno = 0;
    if (resolved_rs_mdns_interfaces(NULL, 1) != -1 || errno != EINVAL)
        fail("interface enumeration accepted a null output buffer");

    ssize_t count = resolved_rs_mdns_interfaces(NULL, 0);
    if (count < 0)
        fail("interface count query failed");

    size_t capacity = count > 0 ? (size_t)count : 1;
    struct resolved_rs_mdns_interface *interfaces =
        calloc(capacity, sizeof *interfaces);
    if (!interfaces)
        fail("interface allocation failed");

    ssize_t populated = resolved_rs_mdns_interfaces(interfaces, capacity);
    if (populated < 0)
        fail("interface enumeration failed");
    size_t available = (size_t)populated < capacity ? (size_t)populated : capacity;
    for (size_t i = 0; i < available; i++) {
        if (interfaces[i].ifindex == 0)
            fail("interface enumeration returned index zero");
        if (interfaces[i].family != AF_INET && interfaces[i].family != AF_INET6)
            fail("interface enumeration returned an unsupported family");
    }

    errno = 0;
    if (resolved_rs_mdns_open(AF_UNSPEC, 1, 5353) != -1 ||
        errno != EAFNOSUPPORT)
        fail("socket creation accepted an unsupported family");

    errno = 0;
    if (resolved_rs_mdns_open(AF_INET, 0, 5353) != -1 || errno != EINVAL)
        fail("socket creation accepted interface index zero");

    errno = 0;
    if (resolved_rs_mdns_open(AF_INET, 1, 0) != -1 || errno != EINVAL)
        fail("socket creation accepted port zero");

    unsigned char buffer[64];
    struct resolved_rs_mdns_meta metadata;
    errno = 0;
    if (resolved_rs_mdns_recv(-1, buffer, sizeof buffer, &metadata) != -1 ||
        errno != EINVAL)
        fail("receive accepted an invalid descriptor");

    if (available > 0) {
        int fd = resolved_rs_mdns_open(
            interfaces[0].family,
            interfaces[0].ifindex,
            (uint16_t)(20000u + interfaces[0].ifindex % 20000u));
        if (fd >= 0)
            close(fd);
        else if (errno != EADDRINUSE && errno != ENODEV && errno != ENETUNREACH &&
                 errno != EACCES && errno != EADDRNOTAVAIL)
            fail("socket creation failed with an unexpected error");
    }

    free(interfaces);
    return EXIT_SUCCESS;
}
