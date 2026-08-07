#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nss_resolve_shm.h"

/* Declared in nss_varlink.c for compatibility with the original glue name. */
int sr_varlink_resolve_hostname(const char *name, char out[][64], int max, int *n_out);

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static int add_size(size_t left, size_t right, size_t *ret)
{
    if (left > SIZE_MAX - right) {
        errno = EOVERFLOW;
        return -1;
    }
    *ret = left + right;
    return 0;
}

static int multiply_size(size_t left, size_t right, size_t *ret)
{
    if (left != 0 && right > SIZE_MAX / left) {
        errno = EOVERFLOW;
        return -1;
    }
    *ret = left * right;
    return 0;
}

static enum nss_status status_from_errno(int error, int *errnop, int *h_errnop)
{
    if (error == 0)
        error = EIO;
    if (errnop)
        *errnop = error;

    switch (error) {
    case ENOENT:
        if (h_errnop)
            *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    case ENODATA:
        if (h_errnop)
            *h_errnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    case ETIMEDOUT:
    case EAGAIN:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTUNREACH:
        if (h_errnop)
            *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
    case ERANGE:
        if (h_errnop)
            *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    default:
        if (h_errnop)
            *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
}

static enum nss_status status_success(int *errnop, int *h_errnop)
{
    if (errnop)
        *errnop = 0;
    if (h_errnop)
        *h_errnop = NETDB_SUCCESS;
    h_errno = 0;
    return NSS_STATUS_SUCCESS;
}

static int collect_addrs(const char *name, struct sr_shm_addr *addrs, size_t *n_io, int *secure)
{
    uint8_t wire[256];
    size_t wire_length = 0;
    if (sr_encode_name(name, wire, sizeof wire, &wire_length) != 0) {
        errno = EINVAL;
        return -1;
    }

    size_t capacity = *n_io;
    size_t count = 0;
    uint8_t rcode = 0;
    int all_secure = 1;
    int cache_hit = 0;

    size_t ipv4_count = capacity;
    int ipv4_secure = 0;
    if (sr_shm_lookup(wire, wire_length, 1, 1, &rcode, addrs, &ipv4_count, &ipv4_secure) == 0 &&
        rcode == 0) {
        count = ipv4_count;
        all_secure = ipv4_secure;
        cache_hit = 1;
    }

    if (count < capacity) {
        struct sr_shm_addr ipv6[64];
        size_t ipv6_count = capacity - count;
        if (ipv6_count > ARRAY_SIZE(ipv6))
            ipv6_count = ARRAY_SIZE(ipv6);
        int ipv6_secure = 0;
        if (sr_shm_lookup(wire, wire_length, 28, 1, &rcode, ipv6, &ipv6_count, &ipv6_secure) == 0 &&
            rcode == 0) {
            for (size_t i = 0; i < ipv6_count && count < capacity; i++)
                addrs[count++] = ipv6[i];
            all_secure = cache_hit ? all_secure && ipv6_secure : ipv6_secure;
            cache_hit = 1;
        }
    }

    if (count == 0) {
        char addresses[32][64];
        int address_count = 0;
        if (sr_varlink_resolve_hostname(name, addresses, (int)ARRAY_SIZE(addresses),
                                        &address_count) != 0)
            return -1;

        for (int i = 0; i < address_count && count < capacity; i++) {
            struct in_addr ipv4;
            struct in6_addr ipv6;
            memset(&addrs[count], 0, sizeof addrs[count]);
            if (inet_pton(AF_INET, addresses[i], &ipv4) == 1) {
                addrs[count].family = 4;
                memcpy(addrs[count].addr, &ipv4, sizeof ipv4);
                count++;
            } else if (inet_pton(AF_INET6, addresses[i], &ipv6) == 1) {
                addrs[count].family = 6;
                memcpy(addrs[count].addr, &ipv6, sizeof ipv6);
                count++;
            }
        }
        all_secure = 0;
    }

    if (count == 0) {
        errno = ENODATA;
        return -1;
    }
    *n_io = count;
    if (secure)
        *secure = all_secure;
    return 0;
}

static enum nss_status pack_gaih(
    const char *name,
    const struct sr_shm_addr *addrs, size_t count,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    size_t valid_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (addrs[i].family == 4 || addrs[i].family == 6)
            valid_count++;
    }
    if (valid_count == 0)
        return status_from_errno(ENODATA, errnop, h_errnop);

    size_t name_length = strlen(name) + 1;
    size_t tuple_alignment = _Alignof(struct gaih_addrtuple);
    size_t tuple_stride = align_up(sizeof(struct gaih_addrtuple), tuple_alignment);
    size_t tuples_offset = align_up(name_length, tuple_alignment);
    size_t tuple_bytes = 0;
    size_t required = 0;
    if (multiply_size(valid_count, tuple_stride, &tuple_bytes) < 0 ||
        add_size(tuples_offset, tuple_bytes, &required) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    if (required > buffer_length)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, required);
    memcpy(buffer, name, name_length);

    struct gaih_addrtuple *first = NULL;
    struct gaih_addrtuple *previous = NULL;
    size_t offset = tuples_offset;
    for (size_t i = 0; i < count; i++) {
        if (addrs[i].family != 4 && addrs[i].family != 6)
            continue;
        struct gaih_addrtuple *tuple = (struct gaih_addrtuple *)(void *)(buffer + offset);
        tuple->name = buffer;
        tuple->family = addrs[i].family == 4 ? AF_INET : AF_INET6;
        tuple->scopeid = tuple->family == AF_INET6 ? addrs[i].scope_id : 0;
        memcpy(tuple->addr, addrs[i].addr, tuple->family == AF_INET ? 4u : 16u);
        if (!first)
            first = tuple;
        if (previous)
            previous->next = tuple;
        previous = tuple;
        offset += tuple_stride;
    }

    if (*pat)
        **pat = *first;
    else
        *pat = first;
    return status_success(errnop, h_errnop);
}

static enum nss_status pack_hostent(
    const char *name, int family,
    const struct sr_shm_addr *addrs, size_t count,
    struct hostent *result,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp, char **canonp)
{
    if (family == AF_UNSPEC)
        family = AF_INET;
    if (family != AF_INET && family != AF_INET6)
        return status_from_errno(EAFNOSUPPORT, errnop, h_errnop);

    size_t address_length = family == AF_INET ? 4u : 16u;
    size_t matching = 0;
    for (size_t i = 0; i < count; i++) {
        if ((family == AF_INET && addrs[i].family == 4) ||
            (family == AF_INET6 && addrs[i].family == 6))
            matching++;
    }
    if (matching == 0)
        return status_from_errno(ENODATA, errnop, h_errnop);

    size_t pointer_alignment = _Alignof(char *);
    size_t name_length = strlen(name) + 1;
    size_t aliases_offset = align_up(name_length, pointer_alignment);
    size_t addresses_offset = aliases_offset + sizeof(char *);
    size_t address_stride = align_up(address_length, pointer_alignment);
    size_t address_bytes = 0;
    size_t address_list_offset = 0;
    size_t pointer_bytes = 0;
    size_t required = 0;
    if (multiply_size(matching, address_stride, &address_bytes) < 0 ||
        add_size(addresses_offset, address_bytes, &address_list_offset) < 0 ||
        multiply_size(matching + 1u, sizeof(char *), &pointer_bytes) < 0 ||
        add_size(address_list_offset, pointer_bytes, &required) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    if (required > buffer_length)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, required);
    memcpy(buffer, name, name_length);
    char **aliases = (char **)(void *)(buffer + aliases_offset);
    aliases[0] = NULL;

    char *address_data = buffer + addresses_offset;
    char **address_list = (char **)(void *)(buffer + address_list_offset);
    size_t output = 0;
    for (size_t i = 0; i < count; i++) {
        if (!((family == AF_INET && addrs[i].family == 4) ||
              (family == AF_INET6 && addrs[i].family == 6)))
            continue;
        address_list[output] = address_data + output * address_stride;
        memcpy(address_list[output], addrs[i].addr, address_length);
        output++;
    }
    address_list[output] = NULL;

    result->h_name = buffer;
    result->h_aliases = aliases;
    result->h_addrtype = family;
    result->h_length = (int)address_length;
    result->h_addr_list = address_list;
    if (ttlp)
        *ttlp = 0;
    if (canonp)
        *canonp = result->h_name;
    return status_success(errnop, h_errnop);
}

enum nss_status _nss_resolve_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{
    if (!name || !*name || !pat || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop, h_errnop);

    struct sr_shm_addr addrs[64];
    size_t count = ARRAY_SIZE(addrs);
    int secure = 0;
    if (collect_addrs(name, addrs, &count, &secure) != 0)
        return status_from_errno(errno, errnop, h_errnop);
    (void)secure;

    if (ttlp)
        *ttlp = 0;
    return pack_gaih(name, addrs, count, pat, buffer, buffer_length, errnop, h_errnop);
}

enum nss_status _nss_resolve_gethostbyname3_r(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    if (!name || !*name || !result || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop, h_errnop);

    struct sr_shm_addr addrs[64];
    size_t count = ARRAY_SIZE(addrs);
    int secure = 0;
    if (collect_addrs(name, addrs, &count, &secure) != 0)
        return status_from_errno(errno, errnop, h_errnop);
    (void)secure;

    return pack_hostent(name, family, addrs, count, result, buffer, buffer_length,
                        errnop, h_errnop, ttlp, canonp);
}

enum nss_status _nss_resolve_gethostbyname2_r(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    return _nss_resolve_gethostbyname3_r(name, family, result, buffer, buffer_length,
                                         errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_resolve_gethostbyname_r(
    const char *name,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    return _nss_resolve_gethostbyname2_r(name, AF_INET, result, buffer, buffer_length,
                                         errnop, h_errnop);
}

static enum nss_status pack_reverse_hostent(
    const void *address, socklen_t address_length, int family,
    char names[][256], int name_count,
    struct hostent *result,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    if (name_count <= 0)
        return status_from_errno(ENODATA, errnop, h_errnop);

    size_t alias_offsets[31];
    size_t offset = 0;
    for (int i = 0; i < name_count; i++) {
        size_t length = strlen(names[i]) + 1;
        if (i > 0)
            alias_offsets[i - 1] = offset;
        if (add_size(offset, length, &offset) < 0)
            return status_from_errno(errno, errnop, h_errnop);
    }

    size_t pointer_alignment = _Alignof(char *);
    size_t aliases_offset = align_up(offset, pointer_alignment);
    size_t alias_pointer_bytes = 0;
    size_t address_offset = 0;
    size_t address_list_offset = 0;
    size_t required = 0;
    if (multiply_size((size_t)name_count, sizeof(char *), &alias_pointer_bytes) < 0 ||
        add_size(aliases_offset, alias_pointer_bytes, &address_offset) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    address_offset = align_up(address_offset, pointer_alignment);
    if (add_size(address_offset, address_length, &address_list_offset) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    address_list_offset = align_up(address_list_offset, pointer_alignment);
    if (add_size(address_list_offset, 2u * sizeof(char *), &required) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    if (required > buffer_length)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, required);
    offset = 0;
    for (int i = 0; i < name_count; i++) {
        size_t length = strlen(names[i]) + 1;
        memcpy(buffer + offset, names[i], length);
        offset += length;
    }

    char **aliases = (char **)(void *)(buffer + aliases_offset);
    for (int i = 1; i < name_count; i++)
        aliases[i - 1] = buffer + alias_offsets[i - 1];
    aliases[name_count - 1] = NULL;

    memcpy(buffer + address_offset, address, address_length);
    char **address_list = (char **)(void *)(buffer + address_list_offset);
    address_list[0] = buffer + address_offset;
    address_list[1] = NULL;

    result->h_name = buffer;
    result->h_aliases = aliases;
    result->h_addrtype = family;
    result->h_length = (int)address_length;
    result->h_addr_list = address_list;
    if (ttlp)
        *ttlp = 0;
    return status_success(errnop, h_errnop);
}

enum nss_status _nss_resolve_gethostbyaddr2_r(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    if (!address || !result || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop, h_errnop);
    if ((family == AF_INET && address_length != sizeof(struct in_addr)) ||
        (family == AF_INET6 && address_length != sizeof(struct in6_addr)))
        return status_from_errno(EINVAL, errnop, h_errnop);
    if (family != AF_INET && family != AF_INET6)
        return status_from_errno(EAFNOSUPPORT, errnop, h_errnop);

    char names[32][256];
    int name_count = 0;
    if (sr_stub_resolve_address(address, address_length, family,
                                names, (int)ARRAY_SIZE(names), &name_count) != 0)
        return status_from_errno(errno, errnop, h_errnop);

    return pack_reverse_hostent(address, address_length, family, names, name_count,
                                result, buffer, buffer_length, errnop, h_errnop, ttlp);
}

enum nss_status _nss_resolve_gethostbyaddr_r(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    return _nss_resolve_gethostbyaddr2_r(address, address_length, family,
                                         result, buffer, buffer_length,
                                         errnop, h_errnop, NULL);
}
