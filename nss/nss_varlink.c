/*
 * Minimal line protocol fallback if full varlink not ready:
 * Connect to UNIX socket and use DNS stub 127.0.0.53 instead —
 * most reliable landing path for NSS miss.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Query stub resolver with a tiny DNS A/AAAA question; fill dotted IPs. */
static int stub_query(const char *name, int want_aaaa,
                      char out[][64], int max, int *n_out)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = htonl(0x7f000035); /* 127.0.0.53 */

    uint8_t pkt[512];
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0x12; pkt[1] = 0x34; /* id */
    pkt[2] = 0x01; pkt[3] = 0x00; /* RD */
    pkt[4] = 0x00; pkt[5] = 0x01; /* qd=1 */
    size_t off = 12;
    /* encode name */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab == 0 || lab > 63 || off + 1 + lab >= sizeof pkt) {
            close(fd); return -1;
        }
        pkt[off++] = (uint8_t)lab;
        memcpy(pkt + off, p, lab);
        off += lab;
        if (!dot) break;
        p = dot + 1;
    }
    pkt[off++] = 0;
    uint16_t qt = want_aaaa ? 28 : 1;
    pkt[off++] = (uint8_t)(qt >> 8); pkt[off++] = (uint8_t)qt;
    pkt[off++] = 0; pkt[off++] = 1; /* IN */

    if (sendto(fd, pkt, off, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(fd); return -1;
    }
    uint8_t resp[2048];
    ssize_t rn = recv(fd, resp, sizeof resp, 0);
    close(fd);
    if (rn < 12) return -1;
    if ((resp[3] & 0x0f) != 0) return -1; /* rcode */
    uint16_t an = ((uint16_t)resp[6] << 8) | resp[7];
    /* skip question */
    size_t o = 12;
    while (o < (size_t)rn && resp[o] != 0) {
        if ((resp[o] & 0xC0) == 0xC0) { o += 2; goto qtype; }
        o += 1 + resp[o];
    }
    if (o >= (size_t)rn) return -1;
    o += 1 + 4; /* root + qtype qclass */
qtype: ;
    int n = 0;
    for (uint16_t i = 0; i < an && n < max && o + 10 <= (size_t)rn; i++) {
        if ((resp[o] & 0xC0) == 0xC0) o += 2;
        else {
            while (o < (size_t)rn && resp[o] != 0) {
                if ((resp[o] & 0xC0) == 0xC0) { o += 2; break; }
                o += 1 + resp[o];
            }
            if (o < (size_t)rn && resp[o] == 0) o++;
        }
        if (o + 10 > (size_t)rn) break;
        uint16_t typ = ((uint16_t)resp[o] << 8) | resp[o+1];
        uint16_t rdlen = ((uint16_t)resp[o+8] << 8) | resp[o+9];
        o += 10;
        if (o + rdlen > (size_t)rn) break;
        if (typ == 1 && rdlen == 4) {
            snprintf(out[n], 64, "%u.%u.%u.%u",
                     resp[o], resp[o+1], resp[o+2], resp[o+3]);
            n++;
        } else if (typ == 28 && rdlen == 16) {
            char buf[64];
            if (inet_ntop(AF_INET6, resp + o, buf, sizeof buf)) {
                snprintf(out[n], 64, "%s", buf);
                n++;
            }
        }
        o += rdlen;
    }
    *n_out = n;
    return n > 0 ? 0 : -1;
}

int sr_varlink_resolve_hostname(const char *name,
                                char out[][64], int max, int *n_out)
{
    if (!name || !out || !n_out || max <= 0) {
        errno = EINVAL;
        return -1;
    }
    *n_out = 0;
    char tmp[16][64];
    int n = 0, n6 = 0;
    if (stub_query(name, 0, tmp, 16, &n) == 0) {
        for (int i = 0; i < n && *n_out < max; i++) {
            snprintf(out[*n_out], 64, "%s", tmp[i]);
            (*n_out)++;
        }
    }
    if (stub_query(name, 1, tmp, 16, &n6) == 0) {
        for (int i = 0; i < n6 && *n_out < max; i++) {
            snprintf(out[*n_out], 64, "%s", tmp[i]);
            (*n_out)++;
        }
    }
    if (*n_out == 0) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}
