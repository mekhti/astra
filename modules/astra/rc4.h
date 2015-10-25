#ifndef _ASTRA_RC4_H_
#define _ASTRA_RC4_H_ 1

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint8_t perm[256];
    uint8_t index1;
    uint8_t index2;
} rc4_ctx_t;

void rc4_init(rc4_ctx_t *state, const uint8_t *key, int keylen);
void rc4_crypt(rc4_ctx_t *state, uint8_t *dst, const uint8_t *buf, int buflen);

#endif /* _ASTRA_RC4_H_ */
