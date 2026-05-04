#include "uuid_gen.h"
#include <stdio.h>
#include <stdint.h>

#ifdef __APPLE__
#include <Security/SecRandom.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

static void get_random_bytes(uint8_t *buf, size_t len) {
#ifdef __APPLE__
    SecRandomCopyBytes(kSecRandomDefault, len, buf);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, len);
        close(fd);
    }
#endif
}

void uuid_v4(char *buf) {
    uint8_t bytes[16];
    get_random_bytes(bytes, 16);

    /* Set version 4 */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    /* Set variant bits */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    snprintf(buf, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}
