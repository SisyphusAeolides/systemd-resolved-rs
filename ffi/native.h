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

int resolved_udp_connect(const char *address, uint16_t port, uint32_t scope_id, int ifindex);
int resolved_tcp_connect(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    uint32_t timeout_msec
);
int resolved_udp_path_mtu(int fd, int ipv6);
int resolved_udp_enable_recvfragsize(int fd, int ipv6);
int64_t resolved_udp_recv(int fd, void *buffer, size_t capacity, uint32_t *fragment_size);
uint16_t resolved_dns_udp_payload_size(
    uint32_t path_mtu,
    int ipv6,
    int loopback,
    int fragmented,
    uint32_t received_udp_fragment_max
);

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
