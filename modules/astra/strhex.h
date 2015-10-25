#ifndef _ASTRA_STRHEX_H_
#define _ASTRA_STRHEX_H_ 1

#include <stddef.h>
#include <stdint.h>

char * hex_to_str(char *str, const uint8_t *hex, int len);
uint8_t * str_to_hex(const char *str, uint8_t *hex, int len);

#endif /* _ASTRA_STRHEX_H_ */
