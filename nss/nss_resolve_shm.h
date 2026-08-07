#ifndef NSS_RESOLVE_SHM_H
#define NSS_RESOLVE_SHM_H

#include <stdint.h>
#include <stddef.h>

#define SR_SHM_PATH "/dev/shm/systemd-resolved-rs-l1"
#define SR_SHM_MAGIC 0x52534C314E535301ULL

struct sr_shm_addr {
    uint8_t family; // 4 or 6
    uint8_t _pad;
    uint16_t scope_id;
    uint8_t addr[16];
};

int sr_shm_lookup(const uint8_t *owner, size_t owner_len,
                  uint16_t qtype, uint16_t qclass,
                  uint8_t *rcode_out,
                  struct sr_shm_addr *addrs, size_t *n_io,
                  int *secure_out);

int sr_encode_name(const char *name, uint8_t *out, size_t cap, size_t *out_len);

#endif
