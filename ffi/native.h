/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef RESOLVED_NATIVE_H
#define RESOLVED_NATIVE_H

#include <stddef.h>
#include <stdint.h>

int resolved_notify(const char *state);
int resolved_listen_fds(void);
int resolved_install_signal_handlers(void);
int resolved_take_reload(void);
int resolved_should_stop(void);
int resolved_peer_credentials(int fd, uint32_t *pid, uint32_t *uid, uint32_t *gid);

int64_t resolved_route_score(
    const char *name,
    size_t name_len,
    const char *domain,
    size_t domain_len,
    int route_only,
    int default_route,
    int ifindex
);

#endif
