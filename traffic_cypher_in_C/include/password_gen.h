#ifndef PASSWORD_GEN_H
#define PASSWORD_GEN_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t length;
    int    uppercase;
    int    lowercase;
    int    digits;
    int    symbols;
} password_options_t;

typedef struct {
    double  entropy_bits;
    char    level[16];     /* "weak", "fair", "good", "strong" */
    int     charset_size;
    size_t  length;
} password_strength_t;

/* Default password options */
void password_options_default(password_options_t *opts);

/* Generate a cryptographically random password. out must be at least opts->length+1 bytes. */
void password_generate(const password_options_t *opts, char *out);

/* Calculate password strength */
password_strength_t password_calculate_strength(const char *password);

/* Simple password generation (like vault's generate_password). out must be at least length+1. */
void generate_password_simple(size_t length, char *out);

#endif
