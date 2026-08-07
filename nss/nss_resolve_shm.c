#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct sr_hdr {
    uint64_t magic;
    uint32_t version;
    uint32_t n_buckets;
    uint32_t arena_off;
    uint32_t arena_size;
    uint64_t write_gen;
    uint32_t arena_used;
    uint32_t pad;
};

struct sr_bucket {
    uint64_t gen;
    uint64_t hash;
    uint32_t off;
    uint32_t len;
    uint64_t expires_ms;
    uint32_t flags;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t rcode;
    uint8_t n_addrs;
    uint16_t pad;
};

static uint64_t hash_key(const uint8_t *o, size_t n, uint16_t t, uint16_t c)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= o[i];
        h *= 0x100000001b3ULL;
    }
    h ^= ((uint64_t)t) << 16;
    h *= 0x100000001b3ULL;
    h ^= c;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int sr_encode_name(const char *name, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!name || !out || !out_len || cap < 2)
        return -1;
    size_t off = 0;
    const char *p = name;
    if (strcmp(name, ".") == 0) {
        out[0] = 0;
        *out_len = 1;
        return 0;
    }
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab == 0 || lab > 63 || off + 1 + lab + 1 > cap)
            return -1;
        out[off++] = (uint8_t)lab;
        for (size_t i = 0; i < lab; i++) {
            unsigned char c = (unsigned char)p[i];
            if (c >= 'A' && c <= 'Z')
                c = (unsigned char)(c + 32);
            out[off++] = c;
        }
        if (!dot)
            break;
        p = dot + 1;
        if (!*p)
            break;
    }
    out[off++] = 0;
    *out_len = off;
    return 0;
}

int sr_shm_lookup(const uint8_t *owner, size_t owner_len,
                  uint16_t qtype, uint16_t qclass,
                  uint8_t *rcode_out,
                  struct sr_shm_addr *addrs, size_t *n_io,
                  int *secure_out)
{
    if (!owner || !rcode_out || !addrs || !n_io || owner_len == 0 || owner_len > 255)
        return -1;

    int fd = open(SR_SHM_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(struct sr_hdr)) {
        close(fd);
        return -1;
    }

    size_t map_len = (size_t)st.st_size;
    void *map = mmap(NULL, map_len, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED)
        return -1;

    const struct sr_hdr *h = (const struct sr_hdr *)map;
    if (h->magic != SR_SHM_MAGIC || h->version != 1 || h->n_buckets == 0) {
        munmap(map, map_len);
        return -1;
    }

    uint64_t hk = hash_key(owner, owner_len, qtype, qclass);
    size_t bi = (size_t)hk & ((size_t)h->n_buckets - 1);
    const struct sr_bucket *buckets =
        (const struct sr_bucket *)((const uint8_t *)map + sizeof(struct sr_hdr));

    int rc = -1;
    for (int attempt = 0; attempt < 8; attempt++) {
        const struct sr_bucket *b = &buckets[bi];
        uint64_t g1 = __atomic_load_n(&b->gen, __ATOMIC_ACQUIRE);
        if (g1 == 0)
            break;
        if (b->hash != hk || b->qtype != qtype || b->qclass != qclass)
            break;

        uint64_t now = now_ms();
        /* allow 30s stale if flag bit0 set */
        if (now > b->expires_ms + 30000ULL && !(b->flags & 1u))
            break;

        if ((uint64_t)b->off + b->len > h->arena_size)
            break;

        const uint8_t *slot = (const uint8_t *)map + h->arena_off + b->off;
        if (slot[0] != (uint8_t)owner_len)
            break;
        if (memcmp(slot + 1, owner, owner_len) != 0)
            break;

        size_t max = *n_io;
        size_t n = b->n_addrs;
        if (n > max)
            n = max;
        const uint8_t *p = slot + 1 + owner_len;
        size_t asz = sizeof(struct sr_shm_addr);
        for (size_t i = 0; i < n; i++) {
            memcpy(&addrs[i], p, asz);
            p += asz;
        }

        uint64_t g2 = __atomic_load_n(&b->gen, __ATOMIC_ACQUIRE);
        if (g1 != g2)
            continue;

        *n_io = n;
        *rcode_out = b->rcode;
        if (secure_out)
            *secure_out = (b->flags & 4u) ? 1 : 0;
        rc = 0;
        break;
    }

    munmap(map, map_len);
    return rc;
}
