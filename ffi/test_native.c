/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *name = "api.eu.example.com";
    const char *parent = "example.com";
    const char *child = "eu.example.com";
    const char *miss = "example.net";
    resolved_link_snapshot *links;
    int64_t link_count;
    int64_t filled;
    int64_t parent_score;
    int64_t child_score;
    int fd;
    int found_named_link = 0;
    size_t i;

    parent_score = resolved_route_score(name, strlen(name), parent, strlen(parent), 0, 1, 2);
    child_score = resolved_route_score(name, strlen(name), child, strlen(child), 1, 0, 3);
    assert(parent_score >= 0);
    assert(child_score > parent_score);
    assert(resolved_route_score(name, strlen(name), miss, strlen(miss), 0, 0, 0) == -1);
    assert(resolved_route_score("API.EXAMPLE.COM", strlen("API.EXAMPLE.COM"), parent,
                                strlen(parent), 0, 0, 0) >= 0);
    assert(resolved_route_score("notexample.com", strlen("notexample.com"), parent,
                                strlen(parent), 0, 0, 0) == -1);
    assert(resolved_route_score(name, strlen(name), "", 0, 0, 0, 0) == 0);
    assert(resolved_notify(NULL) < 0);

    assert(resolved_udp_connect(NULL, 53, 0, 0) < 0);
    assert(resolved_tcp_connect(NULL, 53, 0, 0, 100) < 0);
    fd = resolved_udp_connect("127.0.0.1", 53, 0, INT_MAX);
    assert(fd >= 0);
    assert(close(fd) == 0);
    assert(resolved_udp_connect("192.0.2.53", 53, 0, INT_MAX) < 0);

    assert(resolved_udp_path_mtu(-1, 0) < 0);
    assert(resolved_udp_enable_recvfragsize(-1, 0) < 0);
    assert(resolved_dns_udp_payload_size(1500, 0, 0, 0, 0) == 1472);
    assert(resolved_dns_udp_payload_size(1500, 1, 0, 0, 0) == 1452);
    assert(resolved_dns_udp_payload_size(9000, 0, 0, 0, 0) == 4096);
    assert(resolved_dns_udp_payload_size(1500, 0, 0, 1, 1172) == 1172);
    assert(resolved_dns_udp_payload_size(0, 0, 0, 0, 0) == 1232);
    assert(resolved_dns_udp_payload_size(20, 0, 0, 0, 0) == 512);
    assert(resolved_dns_udp_payload_size(40, 1, 0, 0, 0) == 512);
    assert(resolved_dns_udp_payload_size(0, 0, 1, 0, 0) == 65508);
    assert(resolved_dns_udp_payload_size(0, 1, 1, 0, 0) == 65488);

    assert(resolved_link_snapshot(NULL, 1) < 0);
    link_count = resolved_link_snapshot(NULL, 0);
    assert(link_count > 0);
    links = calloc((size_t)link_count, sizeof(*links));
    assert(links != NULL);
    filled = resolved_link_snapshot(links, (size_t)link_count);
    assert(filled >= link_count);
    for (i = 0; i < (size_t)link_count; i++) {
        assert(links[i].ifindex > 0);
        if (links[i].ifname[0] != '\0') {
            found_named_link = 1;
        }
    }
    assert(found_named_link != 0);
    free(links);

    fd = resolved_rtnl_open();
    assert(fd >= 0);
    assert(resolved_rtnl_wait(fd, 0) >= 0);
    assert(close(fd) == 0);
    return 0;
}
