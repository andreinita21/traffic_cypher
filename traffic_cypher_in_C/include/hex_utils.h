#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stddef.h>
#include <stdint.h>

/* Encode binary data to hex string. out must be at least len*2+1 bytes. */
void hex_encode(const uint8_t *data, size_t len, char *out);

/* Decode hex string to binary. out must be at least strlen(hex)/2 bytes.
   Returns number of bytes decoded, or -1 on error. */
int hex_decode(const char *hex, uint8_t *out, size_t out_max);

#endif
