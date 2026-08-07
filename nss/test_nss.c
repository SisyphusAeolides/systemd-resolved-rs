#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern enum nss_status _nss_resolve_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp);

extern enum nss_status _nss_resolve_gethostbyname2_r(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop);

extern enum nss_status _nss_resolve_gethostbyaddr2_r(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp);

static void fail(const char *message)
{
    fprintf(stderr, "NSS test failed: %s\n", message);
    exit(EXIT_FAILURE);
}

static void require_status(enum nss_status actual, enum nss_status expected,
                           const char *operation, int error, int host_error)
{
    if (actual != expected) {
        fprintf(stderr,
                "NSS test failed: %s returned %d instead of %d (errno=%d h_errno=%d)\n",
                operation, actual, expected, error, host_error);
        exit(EXIT_FAILURE);
    }
}

static int hostent_has_address(const struct hostent *entry, const char *expected)
{
    uint8_t binary[sizeof(struct in6_addr)];
    if (inet_pton(entry->h_addrtype, expected, binary) != 1)
        fail("invalid expected address");
    for (char **address = entry->h_addr_list; address && *address; address++) {
        if (memcmp(*address, binary, (size_t)entry->h_length) == 0)
            return 1;
    }
    return 0;
}

static void test_gaih(void)
{
    char buffer[8192];
    struct gaih_addrtuple *tuples = NULL;
    int error = 0;
    int host_error = 0;
    int32_t ttl = -1;
    enum nss_status status = _nss_resolve_gethostbyname4_r(
        "example.test", &tuples, buffer, sizeof buffer, &error, &host_error, &ttl);
    require_status(status, NSS_STATUS_SUCCESS, "gethostbyname4", error, host_error);
    if (!tuples || ttl != 0 || error != 0 || host_error != NETDB_SUCCESS)
        fail("invalid gethostbyname4 metadata");

    int ipv4 = 0;
    int ipv6 = 0;
    unsigned count = 0;
    for (struct gaih_addrtuple *tuple = tuples; tuple; tuple = tuple->next) {
        if (!tuple->name || strcmp(tuple->name, "example.test") != 0)
            fail("invalid gaih canonical name");
        if (tuple->family == AF_INET) {
            struct in_addr expected;
            if (inet_pton(AF_INET, "192.0.2.123", &expected) != 1 ||
                memcmp(tuple->addr, &expected, sizeof expected) != 0)
                fail("invalid gaih IPv4 address");
            ipv4++;
        } else if (tuple->family == AF_INET6) {
            struct in6_addr expected;
            if (inet_pton(AF_INET6, "2001:db8::123", &expected) != 1 ||
                memcmp(tuple->addr, &expected, sizeof expected) != 0)
                fail("invalid gaih IPv6 address");
            ipv6++;
        } else {
            fail("invalid gaih address family");
        }
        if (++count > 8)
            fail("gaih tuple list contains a cycle");
    }
    if (ipv4 != 1 || ipv6 != 1)
        fail("gaih tuple list is incomplete");
}

static void test_hostent_family(int family, const char *expected)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "example.test", family, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_SUCCESS, "gethostbyname2", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "example.test") != 0 ||
        result.h_addrtype != family || !result.h_aliases || result.h_aliases[0] != NULL ||
        !result.h_addr_list || !result.h_addr_list[0] || result.h_addr_list[1] != NULL)
        fail("invalid hostent layout");
    if (!hostent_has_address(&result, expected))
        fail("hostent address is missing");
}

static void test_reverse(int family, const char *address)
{
    uint8_t binary[sizeof(struct in6_addr)];
    int length = family == AF_INET ? (int)sizeof(struct in_addr) : (int)sizeof(struct in6_addr);
    if (inet_pton(family, address, binary) != 1)
        fail("invalid reverse test address");

    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    int32_t ttl = -1;
    enum nss_status status = _nss_resolve_gethostbyaddr2_r(
        binary, (socklen_t)length, family, &result, buffer, sizeof buffer,
        &error, &host_error, &ttl);
    require_status(status, NSS_STATUS_SUCCESS, "gethostbyaddr2", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "example.test") != 0 ||
        result.h_addrtype != family || result.h_length != length || ttl != 0 ||
        !result.h_addr_list || !result.h_addr_list[0] || result.h_addr_list[1] != NULL ||
        memcmp(result.h_addr_list[0], binary, (size_t)length) != 0)
        fail("invalid reverse hostent");
}

static void test_small_buffer(void)
{
    char buffer[8];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "example.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_TRYAGAIN, "small-buffer lookup", error, host_error);
    if (error != ERANGE || host_error != NETDB_INTERNAL)
        fail("small-buffer lookup returned the wrong errors");
}

int main(void)
{
    test_gaih();
    test_hostent_family(AF_INET, "192.0.2.123");
    test_hostent_family(AF_INET6, "2001:db8::123");
    test_reverse(AF_INET, "192.0.2.123");
    test_reverse(AF_INET6, "2001:db8::123");
    test_small_buffer();
    puts("NSS forward, reverse, legacy hostent, and buffer tests passed");
    return EXIT_SUCCESS;
}
