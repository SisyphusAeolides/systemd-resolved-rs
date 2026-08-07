/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

int resolved_dnssec_digest(
    uint8_t digest_type,
    const void *data,
    size_t length,
    uint8_t *output,
    size_t capacity
) {
    const EVP_MD *digest;
    unsigned int output_length = 0;
    int expected;

    if (data == NULL || output == NULL) {
        return -EINVAL;
    }

    switch (digest_type) {
    case 1:
        digest = EVP_sha1();
        break;
    case 2:
        digest = EVP_sha256();
        break;
    case 4:
        digest = EVP_sha384();
        break;
    default:
        return -EOPNOTSUPP;
    }

    expected = EVP_MD_size(digest);
    if (expected <= 0 || capacity < (size_t)expected) {
        return -ENOBUFS;
    }
    if (EVP_Digest(data, length, output, &output_length, digest, NULL) != 1) {
        return -EIO;
    }
    if (output_length != (unsigned int)expected) {
        return -EIO;
    }
    return (int)output_length;
}
