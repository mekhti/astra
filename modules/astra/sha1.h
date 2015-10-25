#ifndef _ASTRA_SHA1_H_
#define _ASTRA_SHA1_H_ 1

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buffer[64];
} sha1_ctx_t;

#define SHA1_DIGEST_SIZE 20

void sha1_init(sha1_ctx_t *context);
void sha1_update(sha1_ctx_t *context, const uint8_t* data, size_t len);
void sha1_final(sha1_ctx_t *context, uint8_t digest[SHA1_DIGEST_SIZE]);

#endif /* _ASTRA_SHA1_H_ */
