#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define VARLINK_SOCKET_PATH "/run/systemd/resolve/io.systemd.Resolve"
#define VARLINK_MAX_REPLY (1024u * 1024u)

static int set_timeouts(int fd)
{
    const struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
        return -1;
    return 0;
}

static const char *varlink_socket_path(void)
{
    const char *value = secure_getenv("SYSTEMD_NSS_RESOLVE_VARLINK");
    if (!value || !*value)
        return VARLINK_SOCKET_PATH;
    if (strcmp(value, "0") == 0 || strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "false") == 0 || strcasecmp(value, "off") == 0) {
        errno = ENOENT;
        return NULL;
    }
    return value;
}

static int send_all_no_signal(int fd, const void *buffer, size_t length)
{
    const uint8_t *p = buffer;
    while (length > 0) {
        ssize_t written = send(fd, p, length, MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EPIPE;
            return -1;
        }
        p += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int json_escape(const char *input, char **ret)
{
    if (!input || !ret) {
        errno = EINVAL;
        return -1;
    }
    size_t length = strlen(input);
    if (length > 4096) {
        errno = EMSGSIZE;
        return -1;
    }
    size_t capacity = length * 6u + 1u;
    char *output = malloc(capacity);
    if (!output) {
        errno = ENOMEM;
        return -1;
    }
    size_t used = 0;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)input[i];
        if (byte == '"' || byte == '\\') {
            output[used++] = '\\';
            output[used++] = (char)byte;
        } else if (byte == '\b') {
            output[used++] = '\\';
            output[used++] = 'b';
        } else if (byte == '\f') {
            output[used++] = '\\';
            output[used++] = 'f';
        } else if (byte == '\n') {
            output[used++] = '\\';
            output[used++] = 'n';
        } else if (byte == '\r') {
            output[used++] = '\\';
            output[used++] = 'r';
        } else if (byte == '\t') {
            output[used++] = '\\';
            output[used++] = 't';
        } else if (byte < 0x20u) {
            output[used++] = '\\';
            output[used++] = 'u';
            output[used++] = '0';
            output[used++] = '0';
            output[used++] = hex[byte >> 4];
            output[used++] = hex[byte & 0x0fu];
        } else {
            output[used++] = (char)byte;
        }
    }
    output[used] = '\0';
    *ret = output;
    return 0;
}

static int varlink_call(const char *request, char **reply_out, size_t *reply_length_out)
{
    if (!request || !reply_out || !reply_length_out) {
        errno = EINVAL;
        return -1;
    }
    const char *path = varlink_socket_path();
    if (!path)
        return -1;
    size_t path_length = strlen(path);
    if (path_length == 0 || path_length >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (set_timeouts(fd) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_length + 1u);
    if (connect(fd, (const struct sockaddr *)&address, sizeof address) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    size_t request_length = strlen(request);
    if (send_all_no_signal(fd, request, request_length) < 0 ||
        send_all_no_signal(fd, "\0", 1) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    size_t capacity = 8192;
    size_t used = 0;
    char *reply = malloc(capacity + 1u);
    if (!reply) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    for (;;) {
        if (used == capacity) {
            if (capacity >= VARLINK_MAX_REPLY) {
                free(reply);
                close(fd);
                errno = EMSGSIZE;
                return -1;
            }
            size_t next = capacity * 2u;
            if (next > VARLINK_MAX_REPLY)
                next = VARLINK_MAX_REPLY;
            char *grown = realloc(reply, next + 1u);
            if (!grown) {
                int saved = errno;
                free(reply);
                close(fd);
                errno = saved;
                return -1;
            }
            reply = grown;
            capacity = next;
        }
        ssize_t received = recv(fd, reply + used, capacity - used, 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            free(reply);
            close(fd);
            errno = saved;
            return -1;
        }
        if (received == 0) {
            free(reply);
            close(fd);
            errno = ECONNRESET;
            return -1;
        }
        char *terminator = memchr(reply + used, '\0', (size_t)received);
        used += (size_t)received;
        if (terminator) {
            used = (size_t)(terminator - reply);
            break;
        }
    }
    close(fd);
    reply[used] = '\0';
    *reply_out = reply;
    *reply_length_out = used;
    return 0;
}

static const char *json_find_key(const char *start, const char *end, const char *key)
{
    size_t key_length = strlen(key);
    size_t pattern_length = key_length + 2u;
    if (!start || !end || start > end || pattern_length > (size_t)(end - start))
        return NULL;

    for (const char *cursor = start; cursor + pattern_length <= end; cursor++) {
        if (*cursor != '"' || cursor[pattern_length - 1u] != '"' ||
            memcmp(cursor + 1, key, key_length) != 0)
            continue;
        const char *value = cursor + pattern_length;
        while (value < end && (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n'))
            value++;
        if (value >= end || *value != ':')
            continue;
        value++;
        while (value < end && (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n'))
            value++;
        return value < end ? value : NULL;
    }
    return NULL;
}

static int hex_value(char byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F')
        return byte - 'A' + 10;
    return -1;
}

static int parse_json_string(const char *start, const char *end,
                             char *output, size_t capacity, const char **next)
{
    if (!start || start >= end || *start != '"' || !output || capacity == 0) {
        errno = EPROTO;
        return -1;
    }
    size_t used = 0;
    const char *cursor = start + 1;
    while (cursor < end) {
        unsigned char byte = (unsigned char)*cursor++;
        if (byte == '"') {
            output[used] = '\0';
            if (next)
                *next = cursor;
            return 0;
        }
        if (byte == '\\') {
            if (cursor >= end) {
                errno = EPROTO;
                return -1;
            }
            char escape = *cursor++;
            switch (escape) {
            case '"': byte = '"'; break;
            case '\\': byte = '\\'; break;
            case '/': byte = '/'; break;
            case 'b': byte = '\b'; break;
            case 'f': byte = '\f'; break;
            case 'n': byte = '\n'; break;
            case 'r': byte = '\r'; break;
            case 't': byte = '\t'; break;
            case 'u': {
                if (end - cursor < 4) {
                    errno = EPROTO;
                    return -1;
                }
                int a = hex_value(cursor[0]);
                int b = hex_value(cursor[1]);
                int c = hex_value(cursor[2]);
                int d = hex_value(cursor[3]);
                if (a < 0 || b < 0 || c < 0 || d < 0 || a != 0 || b != 0) {
                    errno = EPROTO;
                    return -1;
                }
                byte = (unsigned char)((c << 4) | d);
                cursor += 4;
                break;
            }
            default:
                errno = EPROTO;
                return -1;
            }
        } else if (byte < 0x20u) {
            errno = EPROTO;
            return -1;
        }
        if (used + 1u >= capacity) {
            errno = EMSGSIZE;
            return -1;
        }
        output[used++] = (char)byte;
    }
    errno = EPROTO;
    return -1;
}

static int parse_json_integer(const char *start, const char *end, long *value, const char **next)
{
    if (!start || start >= end || !value) {
        errno = EPROTO;
        return -1;
    }
    errno = 0;
    char *parsed_end = NULL;
    long parsed = strtol(start, &parsed_end, 10);
    if (errno != 0 || parsed_end == start || parsed_end > end) {
        errno = EPROTO;
        return -1;
    }
    *value = parsed;
    if (next)
        *next = parsed_end;
    return 0;
}

static int parse_byte_array(const char *start, const char *end,
                            uint8_t *bytes, size_t capacity, size_t *length)
{
    if (!start || start >= end || *start != '[' || !bytes || !length) {
        errno = EPROTO;
        return -1;
    }
    size_t used = 0;
    const char *cursor = start + 1;
    for (;;) {
        while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n'))
            cursor++;
        if (cursor >= end) {
            errno = EPROTO;
            return -1;
        }
        if (*cursor == ']') {
            *length = used;
            return 0;
        }
        long value = 0;
        if (parse_json_integer(cursor, end, &value, &cursor) < 0 || value < 0 || value > 255) {
            errno = EPROTO;
            return -1;
        }
        if (used >= capacity) {
            errno = EMSGSIZE;
            return -1;
        }
        bytes[used++] = (uint8_t)value;
        while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n'))
            cursor++;
        if (cursor >= end || (*cursor != ',' && *cursor != ']')) {
            errno = EPROTO;
            return -1;
        }
        if (*cursor == ']') {
            *length = used;
            return 0;
        }
        cursor++;
    }
}

static int varlink_error(const char *reply, size_t length)
{
    const char *end = reply + length;
    const char *value = json_find_key(reply, end, "error");
    if (!value)
        return 0;
    char identifier[256];
    if (parse_json_string(value, end, identifier, sizeof identifier, NULL) < 0)
        return -1;
    if (strstr(identifier, "NoSuch") || strstr(identifier, "NotFound"))
        errno = ESRCH;
    else if (strstr(identifier, "TimedOut") || strstr(identifier, "MaxAttempts"))
        errno = ETIMEDOUT;
    else if (strstr(identifier, "Network") || strstr(identifier, "NoSource"))
        errno = ENETUNREACH;
    else if (strstr(identifier, "InvalidParameter"))
        errno = EINVAL;
    else if (strstr(identifier, "DNSSec") || strstr(identifier, "DNSSEC"))
        errno = EACCES;
    else
        errno = EIO;
    return -1;
}

static int parse_varlink_addresses(const char *reply, size_t length,
                                   char out[][64], int max, int *n_out)
{
    if (varlink_error(reply, length) < 0)
        return -1;
    const char *end = reply + length;
    const char *cursor = json_find_key(reply, end, "addresses");
    if (!cursor || *cursor != '[') {
        errno = EPROTO;
        return -1;
    }
    *n_out = 0;
    while (cursor < end) {
        const char *family_value = json_find_key(cursor, end, "family");
        const char *address_value = json_find_key(cursor, end, "address");
        if (!family_value || !address_value)
            break;
        long family_number = 0;
        if (parse_json_integer(family_value, end, &family_number, NULL) < 0)
            return -1;
        uint8_t bytes[16];
        size_t byte_count = 0;
        if (parse_byte_array(address_value, end, bytes, sizeof bytes, &byte_count) < 0)
            return -1;
        int family = family_number == AF_INET ? AF_INET : family_number == AF_INET6 ? AF_INET6 : AF_UNSPEC;
        size_t expected = family == AF_INET ? 4u : family == AF_INET6 ? 16u : 0u;
        if (expected != 0 && byte_count == expected && *n_out < max) {
            if (!inet_ntop(family, bytes, out[*n_out], 64))
                return -1;
            (*n_out)++;
        }
        cursor = address_value + 1;
    }
    if (*n_out == 0) {
        errno = ENODATA;
        return -1;
    }
    return 0;
}

static int parse_varlink_names(const char *reply, size_t length,
                               char out[][256], int max, int *n_out)
{
    if (varlink_error(reply, length) < 0)
        return -1;
    const char *end = reply + length;
    const char *cursor = json_find_key(reply, end, "names");
    if (!cursor || *cursor != '[') {
        errno = EPROTO;
        return -1;
    }
    *n_out = 0;
    while (cursor < end && *n_out < max) {
        const char *name_value = json_find_key(cursor, end, "name");
        if (!name_value)
            break;
        const char *next = NULL;
        if (parse_json_string(name_value, end, out[*n_out], 256, &next) < 0)
            return -1;
        (*n_out)++;
        cursor = next;
    }
    if (*n_out == 0) {
        errno = ENODATA;
        return -1;
    }
    return 0;
}

static int varlink_resolve_hostname(const char *name, char out[][64], int max, int *n_out)
{
    char *escaped = NULL;
    if (json_escape(name, &escaped) < 0)
        return -1;
    size_t request_size = strlen(escaped) + 256u;
    char *request = malloc(request_size);
    if (!request) {
        free(escaped);
        errno = ENOMEM;
        return -1;
    }
    int written = snprintf(
        request,
        request_size,
        "{\"method\":\"io.systemd.Resolve.ResolveHostname\",\"parameters\":{\"ifindex\":0,\"name\":\"%s\",\"family\":0,\"flags\":0}}",
        escaped);
    free(escaped);
    if (written < 0 || (size_t)written >= request_size) {
        free(request);
        errno = EMSGSIZE;
        return -1;
    }
    char *reply = NULL;
    size_t reply_length = 0;
    int result = varlink_call(request, &reply, &reply_length);
    free(request);
    if (result == 0)
        result = parse_varlink_addresses(reply, reply_length, out, max, n_out);
    int saved = errno;
    free(reply);
    errno = saved;
    return result;
}

static int varlink_resolve_address(const void *address, socklen_t length, int family,
                                   char out[][256], int max, int *n_out)
{
    size_t expected = family == AF_INET ? sizeof(struct in_addr) : family == AF_INET6 ? sizeof(struct in6_addr) : 0u;
    if (!address || expected == 0 || length != expected) {
        errno = family == AF_INET || family == AF_INET6 ? EINVAL : EAFNOSUPPORT;
        return -1;
    }
    const uint8_t *bytes = address;
    char address_json[16u * 4u + 1u];
    size_t used = 0;
    for (size_t i = 0; i < expected; i++) {
        int written = snprintf(address_json + used, sizeof address_json - used,
                               "%s%u", i == 0 ? "" : ",", bytes[i]);
        if (written < 0 || (size_t)written >= sizeof address_json - used) {
            errno = EMSGSIZE;
            return -1;
        }
        used += (size_t)written;
    }
    char request[512];
    int written = snprintf(
        request,
        sizeof request,
        "{\"method\":\"io.systemd.Resolve.ResolveAddress\",\"parameters\":{\"ifindex\":0,\"family\":%d,\"address\":[%s],\"flags\":0}}",
        family,
        address_json);
    if (written < 0 || (size_t)written >= sizeof request) {
        errno = EMSGSIZE;
        return -1;
    }
    char *reply = NULL;
    size_t reply_length = 0;
    int result = varlink_call(request, &reply, &reply_length);
    if (result == 0)
        result = parse_varlink_names(reply, reply_length, out, max, n_out);
    int saved = errno;
    free(reply);
    errno = saved;
    return result;
}

static int varlink_fallback_allowed(int error)
{
    switch (error) {
    case ENOENT:
    case ECONNREFUSED:
    case ECONNRESET:
    case ENOTSOCK:
    case EPROTOTYPE:
    case EPIPE:
    case EPROTO:
    case ETIMEDOUT:
        return 1;
    default:
        return 0;
    }
}

int sr_varlink_resolve_hostname(const char *name, char out[][64], int max, int *n_out)
{
    if (varlink_resolve_hostname(name, out, max, n_out) == 0)
        return 0;
    int varlink_error_number = errno;
    if (!varlink_fallback_allowed(varlink_error_number))
        return -1;
    if (sr_stub_resolve_hostname(name, out, max, n_out) == 0)
        return 0;
    if (varlink_error_number != ENOENT && varlink_error_number != ECONNREFUSED)
        errno = varlink_error_number;
    return -1;
}

int sr_varlink_resolve_address(const void *address, socklen_t length, int family,
                               char out[][256], int max, int *n_out)
{
    if (varlink_resolve_address(address, length, family, out, max, n_out) == 0)
        return 0;
    int varlink_error_number = errno;
    if (!varlink_fallback_allowed(varlink_error_number))
        return -1;
    if (sr_stub_resolve_address(address, length, family, out, max, n_out) == 0)
        return 0;
    if (varlink_error_number != ENOENT && varlink_error_number != ECONNREFUSED)
        errno = varlink_error_number;
    return -1;
}
