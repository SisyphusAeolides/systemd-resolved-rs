/* ffi/llmnr_mcast.c — join/leave + ifindex-scoped send */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

int llmnr_join_v4(int fd, int ifindex) {
    struct ip_mreqn m = {0};
    m.imr_multiaddr.s_addr = htonl(0xE00000FC); /* 224.0.0.252 */
    m.imr_ifindex = ifindex;
    return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof m);
}

int llmnr_join_v6(int fd, int ifindex) {
    struct ipv6_mreq m = {0};
    /* ff02::1:3 */
    inet_pton(AF_INET6, "ff02::1:3", &m.ipv6mr_multiaddr);
    m.ipv6mr_interface = (unsigned)ifindex;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &m, sizeof m);
}

int llmnr_set_out_if_v4(int fd, int ifindex) {
    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                      &(struct ip_mreqn){ .imr_ifindex = ifindex },
                      sizeof(struct ip_mreqn));
}
