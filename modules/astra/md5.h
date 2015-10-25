#ifndef _ASTRA_MD5_H_
#define _ASTRA_MD5_H_ 1

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t state[4];  /* state (ABCD) */
    uint32_t count[2];  /* number of bits, modulo 2^64 (lsb first) */
    uint8_t buffer[64]; /* input buffer */
} md5_ctx_t;

#define MD5_DIGEST_SIZE 16

void md5_init(md5_ctx_t *context);
void md5_update(md5_ctx_t *context, const uint8_t *data, size_t len);
void md5_final(md5_ctx_t *context, uint8_t digest[MD5_DIGEST_SIZE]);

void md5_crypt(const char *pw, const char *salt, char passwd[36]);

#endif /* _ASTRA_MD5_H_ */
