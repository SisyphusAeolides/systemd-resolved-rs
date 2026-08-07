/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    static const uint8_t sha256_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const uint8_t ed25519_public_key[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    };
    static const uint8_t ed25519_signature[64] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    };
    const char *name = "api.eu.example.com";
    const char *parent = "example.com";
    const char *child = "eu.example.com";
    const char *miss = "example.net";
    resolved_link_info *links;
    uint8_t digest[48];
    uint8_t invalid_signature[sizeof(ed25519_signature)];
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

    assert(resolved_ifindex_from_name(NULL) < 0);
    assert(resolved_ifindex_from_name("") < 0);
    assert(resolved_ifindex_from_name("lo") > 0);

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

    assert(resolved_dnssec_digest(2, "abc", 3, digest, sizeof(digest)) == 32);
    assert(memcmp(digest, sha256_abc, sizeof(sha256_abc)) == 0);
    assert(resolved_dnssec_digest(3, "abc", 3, digest, sizeof(digest)) < 0);
    assert(resolved_dnssec_digest(2, "abc", 3, digest, 1) < 0);

    assert(resolved_dnssec_verify(
        15,
        ed25519_public_key,
        sizeof(ed25519_public_key),
        (const uint8_t *)"",
        0,
        ed25519_signature,
        sizeof(ed25519_signature)
    ) == 1);
    memcpy(invalid_signature, ed25519_signature, sizeof(invalid_signature));
    invalid_signature[0] ^= 1U;
    assert(resolved_dnssec_verify(
        15,
        ed25519_public_key,
        sizeof(ed25519_public_key),
        (const uint8_t *)"",
        0,
        invalid_signature,
        sizeof(invalid_signature)
    ) == 0);
    assert(resolved_dnssec_verify(
        16,
        ed25519_public_key,
        sizeof(ed25519_public_key),
        (const uint8_t *)"",
        0,
        ed25519_signature,
        sizeof(ed25519_signature)
    ) < 0);

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

    fd = resolved_networkd_open();
    assert(fd >= 0);
    assert(resolved_networkd_wait(fd, 0) >= 0);
    assert(close(fd) == 0);
    return 0;
}
