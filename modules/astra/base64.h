#ifndef _ASTRA_BASE64_H_
#define _ASTRA_BASE64_H_ 1

#include <stddef.h>
#include <stdint.h>

void base64_encode(const uint8_t *in, size_t in_size, char **out, size_t *out_size);
void base64_decode(const char *in, size_t in_size, uint8_t **out, size_t *out_size);

#endif /* _ASTRA_BASE64_H_ */
