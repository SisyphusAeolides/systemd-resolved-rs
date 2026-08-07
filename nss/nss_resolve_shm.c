/* nss/nss_resolve_shm.c */
#define _GNU_SOURCE
#include "nss_resolve_shm.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

struct hdr {
    uint64_t magic;
    uint32_t version;
    uint32_t n_buckets;
    uint32_t arena_off;
    uint32_t arena_size;
    uint64_t write_gen;
    uint32_t arena_used;
    uint32_t pad;
};

struct bucket {
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

static uint64_t hash_key(const uint8_t *o, size_t n, uint16_t t, uint16_t c) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= o[i]; h *= 0x100000001b3ULL; }
    h ^= ((uint64_t)t) << 16; h *= 0x100000001b3ULL;
    h ^= c;
    h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int sr_shm_lookup(const uint8_t *owner, size_t owner_len,
                  uint16_t qtype, uint16_t qclass,
                  uint8_t *rcode_out,
                  struct sr_shm_addr *addrs, size_t *n_io,
                  int *secure_out)
{
    int fd = open(SR_SHM_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_size < (off_t)sizeof(struct hdr)) {
        close(fd); return -1;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    const struct hdr *h = (const struct hdr *)map;
    if (h->magic != SR_SHM_MAGIC || h->version != 1) {
        munmap(map, (size_t)st.st_size); return -1;
    }
    uint64_t hk = hash_key(owner, owner_len, qtype, qclass);
    size_t bi = (size_t)hk & (h->n_buckets - 1);
    const struct bucket *buckets =
        (const struct bucket *)((const uint8_t *)map + sizeof(struct hdr));

    int rc = -1;
    for (int try = 0; try < 4; try++) {
        const struct bucket *b = &buckets[bi];
        uint64_t g1 = b->gen;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (!g1 || b->hash != hk || b->qtype != qtype || b->qclass != qclass)
            break;
        uint64_t now = now_ms();
        if (now > b->expires_ms + 30000ULL && !(b->flags & 1u))
            break;
        const uint8_t *slot = (const uint8_t *)map + h->arena_off + b->off;
        if (b->off + b->len > h->arena_size) break;
        if (slot[0] != (uint8_t)owner_len) break;
        if (memcmp(slot + 1, owner, owner_len) != 0) break;
        size_t max = *n_io;
        size_t n = b->n_addrs < max ? b->n_addrs : max;
        const uint8_t *p = slot + 1 + owner_len;
        for (size_t i = 0; i < n; i++) {
            memcpy(&addrs[i], p, sizeof(addrs[i]));
            p += sizeof(addrs[i]);
        }
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (b->gen != g1) continue;
        *n_io = n;
        *rcode_out = b->rcode;
        if (secure_out) *secure_out = (b->flags & 4u) ? 1 : 0;
        rc = 0;
        break;
    }
    munmap(map, (size_t)st.st_size);
    return rc;
}

int sr_encode_name(const char *name, uint8_t *out, size_t cap, size_t *out_len) {
    /* TODO: actual label encoding */
    (void)out;
    if (cap < strlen(name) + 2) return -1;
    /* Dummy implementation */
    *out_len = 0;
    return 0;
}
