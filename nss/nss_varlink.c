#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int encode_qname(const char *name, uint8_t *out, size_t cap, size_t *olen)
{
    return sr_encode_name(name, out, cap, olen);
}

static int parse_addrs_from_response(const uint8_t *resp, size_t rn,
                                     char out[][64], int max, int *n_out)
{
    if (rn < 12)
        return -1;
    uint8_t rcode = resp[3] & 0x0f;
    if (rcode != 0)
        return -1;
    uint16_t an = ((uint16_t)resp[6] << 8) | resp[7];
    size_t o = 12;
    /* skip questions */
    uint16_t qd = ((uint16_t)resp[4] << 8) | resp[5];
    for (uint16_t qi = 0; qi < qd; qi++) {
        while (o < rn) {
            if (resp[o] == 0) {
                o++;
                break;
            }
            if ((resp[o] & 0xC0) == 0xC0) {
                o += 2;
                break;
            }
            o += 1u + resp[o];
        }
        o += 4;
        if (o > rn)
            return -1;
    }

    int n = *n_out;
    for (uint16_t ai = 0; ai < an && n < max; ai++) {
        if (o >= rn)
            break;
        if ((resp[o] & 0xC0) == 0xC0)
            o += 2;
        else {
            while (o < rn && resp[o] != 0) {
                if ((resp[o] & 0xC0) == 0xC0) {
                    o += 2;
                    goto after_name;
                }
                o += 1u + resp[o];
            }
            if (o < rn && resp[o] == 0)
                o++;
        }
    after_name:
        if (o + 10 > rn)
            break;
        uint16_t typ = ((uint16_t)resp[o] << 8) | resp[o + 1];
        uint16_t rdlen = ((uint16_t)resp[o + 8] << 8) | resp[o + 9];
        o += 10;
        if (o + rdlen > rn)
            break;
        if (typ == 1 && rdlen == 4) {
            snprintf(out[n], 64, "%u.%u.%u.%u", resp[o], resp[o + 1], resp[o + 2], resp[o + 3]);
            n++;
        } else if (typ == 28 && rdlen == 16) {
            char buf[INET6_ADDRSTRLEN];
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

static int stub_once(const char *name, int aaaa, char out[][64], int max, int *n_out)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = htonl(0x7f000035); /* 127.0.0.53 */

    uint8_t pkt[512];
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0xAB;
    pkt[1] = 0xCD;
    pkt[2] = 0x01; /* RD */
    pkt[5] = 1;    /* qdcount */
    size_t off = 12;
    uint8_t wire[256];
    size_t wlen = 0;
    if (encode_qname(name, wire, sizeof wire, &wlen) != 0) {
        close(fd);
        return -1;
    }
    if (off + wlen + 4 > sizeof pkt) {
        close(fd);
        return -1;
    }
    memcpy(pkt + off, wire, wlen);
    off += wlen;
    uint16_t qt = aaaa ? 28 : 1;
    pkt[off++] = (uint8_t)(qt >> 8);
    pkt[off++] = (uint8_t)qt;
    pkt[off++] = 0;
    pkt[off++] = 1;

    if (sendto(fd, pkt, off, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(fd);
        return -1;
    }

    uint8_t resp[4096];
    ssize_t rn = recv(fd, resp, sizeof resp, 0);
    close(fd);
    if (rn < 12)
        return -1;
    /* id check optional */
    return parse_addrs_from_response(resp, (size_t)rn, out, max, n_out);
}

int sr_stub_resolve_hostname(const char *name, char out[][64], int max, int *n_out)
{
    if (!name || !out || !n_out || max <= 0) {
        errno = EINVAL;
        return -1;
    }
    *n_out = 0;
    int n = 0;
    char tmp[32][64];
    int tn = 0;
    if (stub_once(name, 0, tmp, 32, &tn) == 0) {
        for (int i = 0; i < tn && n < max; i++) {
            snprintf(out[n], 64, "%s", tmp[i]);
            n++;
        }
    }
    tn = 0;
    if (stub_once(name, 1, tmp, 32, &tn) == 0) {
        for (int i = 0; i < tn && n < max; i++) {
            snprintf(out[n], 64, "%s", tmp[i]);
            n++;
        }
    }
    *n_out = n;
    if (n == 0) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

/* Back-compat name used by earlier glue */
int sr_varlink_resolve_hostname(const char *name, char out[][64], int max, int *n_out)
{
    return sr_stub_resolve_hostname(name, out, max, n_out);
}
