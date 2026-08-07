/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <errno.h>
#include <net/if.h>
#include <stdint.h>

int resolved_ifindex_from_name(const char *name) {
    unsigned int ifindex;

    if (name == NULL || name[0] == '\0') {
        return -EINVAL;
    }

    errno = 0;
    ifindex = if_nametoindex(name);
    if (ifindex == 0U) {
        return errno != 0 ? -errno : -ENODEV;
    }
    if (ifindex > (unsigned int)INT32_MAX) {
        return -EOVERFLOW;
    }
    return (int)ifindex;
}
