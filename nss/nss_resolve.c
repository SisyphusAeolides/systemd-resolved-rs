#define _GNU_SOURCE
#include <nss.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "nss_resolve_shm.h"

/* from nss_varlink.c */
int sr_varlink_resolve_hostname(const char *name, char out[][64], int max, int *n_out);

static int encode_wire(const char *name, uint8_t *out, size_t cap, size_t *olen)
{
    size_t off = 0;
    const char *p = name;
    if (!name || !*name) return -1;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab == 0 || lab > 63 || off + 1 + lab + 1 > cap) return -1;
        out[off++] = (uint8_t)lab;
        for (size_t i = 0; i < lab; i++) {
            unsigned char c = (unsigned char)p[i];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
            out[off++] = c;
        }
        if (!dot) break;
        p = dot + 1;
        if (!*p) break;
    }
    out[off++] = 0;
    *olen = off;
    return 0;
}

static enum nss_status fill_gaih(
    struct sr_shm_addr *addrs, size_t n, const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *h_errnop)
{
    /* Simplified: require buffer large enough; production mirrors glibc nss-resolve layout */
    size_t need = n * sizeof(struct gaih_addrtuple) + strlen(name) + 1 + 16;
    if (buflen < need) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    memset(buffer, 0, buflen);
    char *name_copy = buffer;
    memcpy(name_copy, name, strlen(name) + 1);
    struct gaih_addrtuple *tuples =
        (struct gaih_addrtuple *)(buffer + ((strlen(name) + 8) & ~7));
    for (size_t i = 0; i < n; i++) {
        tuples[i].next = (i + 1 < n) ? &tuples[i + 1] : NULL;
        tuples[i].name = name_copy;
        tuples[i].scopeid = addrs[i].scope_id;
        if (addrs[i].family == 4) {
            tuples[i].family = AF_INET;
            memcpy(tuples[i].addr, addrs[i].addr, 4);
        } else {
            tuples[i].family = AF_INET6;
            memcpy(tuples[i].addr, addrs[i].addr, 16);
        }
    }
    *pat = tuples;
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_resolve_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{
    if (!name || !pat || !buffer) {
        *errnop = EINVAL;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }

    uint8_t wire[256];
    size_t wlen = 0;
    if (encode_wire(name, wire, sizeof wire, &wlen) != 0) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    struct sr_shm_addr addrs[16];
    size_t n = 0;
    uint8_t rcode = 0;
    int secure = 0;

    /* merge A + AAAA from SHM */
    size_t na = 16;
    if (sr_shm_lookup(wire, wlen, 1, 1, &rcode, addrs, &na, &secure) == 0)
        n = na;
    size_t n6 = 16 - n;
    if (n6 > 0) {
        struct sr_shm_addr tmp[16];
        size_t tn = n6;
        if (sr_shm_lookup(wire, wlen, 28, 1, &rcode, tmp, &tn, &secure) == 0) {
            for (size_t i = 0; i < tn && n < 16; i++)
                addrs[n++] = tmp[i];
        }
    }

    if (n == 0) {
        char ips[16][64];
        int ni = 0;
        if (sr_varlink_resolve_hostname(name, ips, 16, &ni) != 0) {
            *errnop = ENOENT;
            *h_errnop = HOST_NOT_FOUND;
            return NSS_STATUS_NOTFOUND;
        }
        for (int i = 0; i < ni && n < 16; i++) {
            struct in_addr a4;
            struct in6_addr a6;
            if (inet_pton(AF_INET, ips[i], &a4) == 1) {
                addrs[n].family = 4;
                addrs[n].scope_id = 0;
                memset(addrs[n].addr, 0, 16);
                memcpy(addrs[n].addr, &a4, 4);
                n++;
            } else if (inet_pton(AF_INET6, ips[i], &a6) == 1) {
                addrs[n].family = 6;
                addrs[n].scope_id = 0;
                memcpy(addrs[n].addr, &a6, 16);
                n++;
            }
        }
    }

    if (n == 0) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    if (ttlp) *ttlp = 60;
    return fill_gaih(addrs, n, name, pat, buffer, buflen, errnop, h_errnop);
}

enum nss_status _nss_resolve_gethostbyname3_r(
    const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    (void)canonp;
    struct gaih_addrtuple *pat = NULL;
    enum nss_status st = _nss_resolve_gethostbyname4_r(
        name, &pat, buffer, buflen, errnop, h_errnop, ttlp);
    if (st != NSS_STATUS_SUCCESS)
        return st;
    /* Minimal hostent bridge — prefer getaddrinfo path via gaih */
    (void)af; (void)result;
    *errnop = EAFNOSUPPORT;
    *h_errnop = NO_DATA;
    return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
    const void *addr, socklen_t len, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    (void)addr; (void)len; (void)af; (void)result; (void)buffer; (void)buflen; (void)ttlp;
    *errnop = ENOENT;
    *h_errnop = HOST_NOT_FOUND;
    return NSS_STATUS_NOTFOUND;
}
