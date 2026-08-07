#define _GNU_SOURCE
#include <nss.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "nss_resolve_shm.h"

/* declared in nss_varlink.c */
int sr_varlink_resolve_hostname(const char *name, char out[][64], int max, int *n_out);

static enum nss_status status_from_errno(int err, int *errnop, int *h_errnop)
{
    *errnop = err;
    switch (err) {
    case ENOENT:
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    case ETIMEDOUT:
    case EAGAIN:
        *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
    case ERANGE:
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    default:
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
}

static int collect_addrs(const char *name, struct sr_shm_addr *addrs, size_t *n_io, int *secure)
{
    uint8_t wire[256];
    size_t wlen = 0;
    if (sr_encode_name(name, wire, sizeof wire, &wlen) != 0)
        return -1;

    size_t cap = *n_io;
    size_t n = 0;
    uint8_t rcode = 0;
    int sec = 0;

    size_t na = cap;
    if (sr_shm_lookup(wire, wlen, 1, 1, &rcode, addrs, &na, &sec) == 0 && rcode == 0)
        n = na;

    if (n < cap) {
        size_t n6 = cap - n;
        struct sr_shm_addr tmp[64];
        if (n6 > 64)
            n6 = 64;
        size_t tn = n6;
        if (sr_shm_lookup(wire, wlen, 28, 1, &rcode, tmp, &tn, &sec) == 0 && rcode == 0) {
            for (size_t i = 0; i < tn && n < cap; i++)
                addrs[n++] = tmp[i];
        }
    }

    if (n == 0) {
        char ips[32][64];
        int ni = 0;
        if (sr_varlink_resolve_hostname(name, ips, 32, &ni) != 0)
            return -1;
        for (int i = 0; i < ni && n < cap; i++) {
            struct in_addr a4;
            struct in6_addr a6;
            memset(&addrs[n], 0, sizeof addrs[n]);
            if (inet_pton(AF_INET, ips[i], &a4) == 1) {
                addrs[n].family = 4;
                memcpy(addrs[n].addr, &a4, 4);
                n++;
            } else if (inet_pton(AF_INET6, ips[i], &a6) == 1) {
                addrs[n].family = 6;
                memcpy(addrs[n].addr, &a6, 16);
                n++;
            }
        }
    }

    if (n == 0)
        return -1;
    *n_io = n;
    if (secure)
        *secure = sec;
    return 0;
}

/*
 * Pack gaih_addrtuple list into buffer.
 * Layout: name\0 padding tuples...
 */
static enum nss_status pack_gaih(
    const char *name,
    struct sr_shm_addr *addrs, size_t n,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *h_errnop)
{
    size_t namelen = strlen(name) + 1;
    size_t name_off = 0;
    size_t tuples_off = (namelen + 15) & ~((size_t)15);
    size_t need = tuples_off + n * sizeof(struct gaih_addrtuple);
    if (need > buflen)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, buflen);
    memcpy(buffer + name_off, name, namelen);
    struct gaih_addrtuple *t = (struct gaih_addrtuple *)(buffer + tuples_off);

    for (size_t i = 0; i < n; i++) {
        t[i].next = (i + 1 < n) ? &t[i + 1] : NULL;
        t[i].name = buffer + name_off;
        t[i].scopeid = addrs[i].scope_id;
        if (addrs[i].family == 4) {
            t[i].family = AF_INET;
            memcpy(t[i].addr, addrs[i].addr, 4);
        } else {
            t[i].family = AF_INET6;
            memcpy(t[i].addr, addrs[i].addr, 16);
        }
    }
    *pat = t;
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_resolve_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{
    if (!name || !*name || !pat || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop ? errnop : &(int){0},
                                 h_errnop ? h_errnop : &(int){0});

    struct sr_shm_addr addrs[64];
    size_t n = 64;
    int secure = 0;
    if (collect_addrs(name, addrs, &n, &secure) != 0)
        return status_from_errno(ENOENT, errnop, h_errnop);

    if (ttlp)
        *ttlp = 60;

    return pack_gaih(name, addrs, n, pat, buffer, buflen, errnop, h_errnop);
}

enum nss_status _nss_resolve_gethostbyname3_r(
    const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    struct gaih_addrtuple *pat = NULL;
    enum nss_status st =
        _nss_resolve_gethostbyname4_r(name, &pat, buffer, buflen, errnop, h_errnop, ttlp);
    if (st != NSS_STATUS_SUCCESS)
        return st;

    /* Build a classic hostent from first matching family */
    if (!result)
        return status_from_errno(EINVAL, errnop, h_errnop);

    /* Re-pack simply: many apps use getaddrinfo → gethostbyname4 */
    size_t namelen = strlen(name) + 1;
    if (buflen < namelen + sizeof(char *) * 4 + 16)
        return status_from_errno(ERANGE, errnop, h_errnop);

    /* We already used buffer for gaih; for hostent path request fresh via TRYAGAIN is harsh.
       Prefer documenting getaddrinfo. Provide best-effort: */
    memset(result, 0, sizeof *result);
    result->h_name = (char *)name;
    result->h_aliases = NULL;
    result->h_addrtype = (af == AF_INET6) ? AF_INET6 : AF_INET;
    result->h_length = (af == AF_INET6) ? 16 : 4;
    if (canonp)
        *canonp = (char *)name;

    /* Without separate buffer region, signal NOTFOUND for hostent API if family filter empty */
    int found = 0;
    for (struct gaih_addrtuple *p = pat; p; p = p->next) {
        if (af == AF_UNSPEC || p->family == af) {
            found = 1;
            break;
        }
    }
    if (!found)
        return status_from_errno(ENOENT, errnop, h_errnop);

    /* Insufficient to fully fill h_addr_list without clobbering — return SUCCESS with name only
       is wrong. Use UNAVAIL to force retry via other NSS modules for legacy API, or SUCCESS
       if af matches first. */
    (void)found;
    *errnop = EAFNOSUPPORT;
    *h_errnop = NO_DATA;
    return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_resolve_gethostbyname2_r(
    const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop)
{
    return _nss_resolve_gethostbyname3_r(name, af, result, buffer, buflen,
                                         errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_resolve_gethostbyname_r(
    const char *name,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop)
{
    return _nss_resolve_gethostbyname2_r(name, AF_INET, result, buffer, buflen, errnop, h_errnop);
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
    const void *addr, socklen_t len, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    (void)addr;
    (void)len;
    (void)af;
    (void)result;
    (void)buffer;
    (void)buflen;
    (void)ttlp;
    /* Reverse lookup: implement via stub PTR later */
    *errnop = ENOENT;
    *h_errnop = HOST_NOT_FOUND;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_resolve_gethostbyaddr_r(
    const void *addr, socklen_t len, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop)
{
    return _nss_resolve_gethostbyaddr2_r(addr, len, af, result, buffer, buflen,
                                         errnop, h_errnop, NULL);
}
