/*
 * nss/nss_resolve.c — NSS module talking to resolve1 / varlink
 * Install: /usr/lib/libnss_resolve.so.2
 * nsswitch.conf: hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
 *
 * Implements: gethostbyname*, getaddrinfo via _nss_resolve_gethostbyname4_r etc.
 * Must return AI_V4MAPPED/AI_ADDRCONFIG semantics close to glibc+nss-resolve.
 */

#include <nss.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Prefer varlink unix:/run/systemd/resolve/io.systemd.Resolve
 * Fallback: D-Bus org.freedesktop.resolve1.Manager.ResolveHostname
 */

/* nss/nss_resolve.c — fragment: gethostbyname4_r uses SHM first */
#include <nss.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "nss_resolve_shm.h"

/* owner_to_wire_lower() omitted — label encode qname */

enum nss_status _nss_resolve_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{
    uint8_t wire[256];
    size_t wlen = 0;
    /* TODO: encode name → wire lowercase absolute */
    if (sr_encode_name(name, wire, sizeof wire, &wlen) != 0) {
        *errnop = EINVAL; *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }

    struct sr_shm_addr addrs[16];
    size_t n = 16;
    uint8_t rcode = 0;
    int secure = 0;
    /* try AAAA + A */
    int hit = sr_shm_lookup(wire, wlen, 28, 1, &rcode, addrs, &n, &secure);
    if (hit != 0) {
        n = 16;
        hit = sr_shm_lookup(wire, wlen, 1, 1, &rcode, addrs, &n, &secure);
    }
    if (hit == 0 && n > 0 && rcode == 0) {
        /* pack gaih_addrtuple into buffer — see glibc nss-resolve for layout */
        /* On success return NSS_STATUS_SUCCESS */
        (void)pat; (void)buffer; (void)buflen; (void)ttlp;
        /* FALL THROUGH to full implementation in tree */
    }

    /* miss: varlink to daemon io.systemd.Resolve */
    (void)name;
    *errnop = EAGAIN;
    *h_errnop = TRY_AGAIN;
    return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_resolve_gethostbyname3_r(
    const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    (void)name; (void)af; (void)result; (void)buffer; (void)buflen;
    (void)ttlp; (void)canonp;
    *errnop = EAGAIN; *h_errnop = TRY_AGAIN;
    return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
    const void *addr, socklen_t len, int af,
    struct hostent *result, char *buffer, size_t buflen,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    /* ResolveAddress reverse path */
    (void)addr; (void)len; (void)af; (void)result; (void)buffer; (void)buflen; (void)ttlp;
    *errnop = EAGAIN; *h_errnop = TRY_AGAIN;
    return NSS_STATUS_UNAVAIL;
}
