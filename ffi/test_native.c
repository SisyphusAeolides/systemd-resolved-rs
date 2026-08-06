/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    const char *name = "api.eu.example.com";
    const char *parent = "example.com";
    const char *child = "eu.example.com";
    const char *miss = "example.net";
    int64_t parent_score;
    int64_t child_score;

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

    assert(resolved_udp_path_mtu(-1, 0) < 0);
    assert(resolved_udp_enable_recvfragsize(-1, 0) < 0);
    assert(resolved_dns_udp_payload_size(1500, 0, 0, 0, 0) == 1472);
    assert(resolved_dns_udp_payload_size(1500, 1, 0, 0, 0) == 1452);
    assert(resolved_dns_udp_payload_size(9000, 0, 0, 0, 0) == 4096);
    assert(resolved_dns_udp_payload_size(1500, 0, 0, 1, 1172) == 1172);
    assert(resolved_dns_udp_payload_size(0, 0, 0, 0, 0) == 1232);
    assert(resolved_dns_udp_payload_size(0, 0, 1, 0, 0) == 65508);
    assert(resolved_dns_udp_payload_size(0, 1, 1, 0, 0) == 65488);
    return 0;
}
