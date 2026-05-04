#include "password_gen.h"

#include <string.h>
#include <math.h>
#include <ctype.h>
#include <openssl/rand.h>

void password_options_default(password_options_t *opts) {
    opts->length = 24;
    opts->uppercase = 1;
    opts->lowercase = 1;
    opts->digits = 1;
    opts->symbols = 1;
}

void password_generate(const password_options_t *opts, char *out) {
    char charset[128];
    int charset_len = 0;

    if (opts->lowercase) {
        const char *lc = "abcdefghjkmnpqrstuvwxyz";
        memcpy(charset + charset_len, lc, strlen(lc));
        charset_len += (int)strlen(lc);
    }
    if (opts->uppercase) {
        const char *uc = "ABCDEFGHJKMNPQRSTUVWXYZ";
        memcpy(charset + charset_len, uc, strlen(uc));
        charset_len += (int)strlen(uc);
    }
    if (opts->digits) {
        const char *dg = "23456789";
        memcpy(charset + charset_len, dg, strlen(dg));
        charset_len += (int)strlen(dg);
    }
    if (opts->symbols) {
        const char *sy = "!@#$%^&*-_=+";
        memcpy(charset + charset_len, sy, strlen(sy));
        charset_len += (int)strlen(sy);
    }
    if (charset_len == 0) {
        const char *lc = "abcdefghjkmnpqrstuvwxyz";
        memcpy(charset, lc, strlen(lc));
        charset_len = (int)strlen(lc);
    }

    uint8_t *rand_bytes = (uint8_t *)__builtin_alloca(opts->length);
    RAND_bytes(rand_bytes, (int)opts->length);

    for (size_t i = 0; i < opts->length; i++) {
        out[i] = charset[rand_bytes[i] % charset_len];
    }
    out[opts->length] = '\0';
}

password_strength_t password_calculate_strength(const char *password) {
    password_strength_t result;
    memset(&result, 0, sizeof(result));

    int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
    size_t len = strlen(password);

    for (size_t i = 0; i < len; i++) {
        char c = password[i];
        if (islower((unsigned char)c)) has_lower = 1;
        else if (isupper((unsigned char)c)) has_upper = 1;
        else if (isdigit((unsigned char)c)) has_digit = 1;
        else has_symbol = 1;
    }

    int cs = 0;
    if (has_lower) cs += 26;
    if (has_upper) cs += 26;
    if (has_digit) cs += 10;
    if (has_symbol) cs += 32;
    if (cs == 0) cs = 1;

    result.entropy_bits = (double)len * log2((double)cs);
    result.charset_size = cs;
    result.length = len;

    if (result.entropy_bits < 40.0) strcpy(result.level, "weak");
    else if (result.entropy_bits < 60.0) strcpy(result.level, "fair");
    else if (result.entropy_bits < 80.0) strcpy(result.level, "good");
    else strcpy(result.level, "strong");

    return result;
}

void generate_password_simple(size_t length, char *out) {
    password_options_t opts;
    password_options_default(&opts);
    opts.length = length;
    password_generate(&opts, out);
}
