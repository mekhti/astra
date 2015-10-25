#ifndef _ASTRA_MODULE_DES_H_
#define _ASTRA_MODULE_DES_H_ 1

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    union
    {
        uint8_t cblock[8];
        uint32_t deslong[2];
    } ks[16];
} des_ctx_t;

void des_set_key(const uint8_t *key, des_ctx_t *schedule);
void triple_des_set_key(const uint8_t *key, const char *pass, size_t key_size,
    des_ctx_t *ks1, des_ctx_t *ks2);

void des_encrypt(const uint8_t *input, uint8_t *output, size_t length,
    des_ctx_t *ks1, des_ctx_t *ks2, des_ctx_t *ks3,
    uint8_t *ivec, int enc);

#endif /* _ASTRA_MODULE_DES_H_ */
