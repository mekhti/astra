#ifndef _ASTRA_CRC32_H_
#define _ASTRA_CRC32_H_ 1

#include <stddef.h>
#include <stdint.h>

#define CRC32_SIZE 4
uint32_t crc32b(const uint8_t *buffer, int size);

#endif /* _ASTRA_CRC32_H_ */
