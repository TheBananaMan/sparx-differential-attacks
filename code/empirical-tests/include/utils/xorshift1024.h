/**
 * Written in 2014 by Sebastiano Vigna (vigna@acm.org)
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 * 
 * See <http://creativecommons.org/publicdomain/zero/1.0/>. 
 * 
 * This is a fast, top-quality generator. If 1024 bits of state are too
   much, try a xoroshiro128+ generator.

   Note that the three lowest bits of this generator are LSFRs, and thus
   they are slightly less random than the other bits. We suggest to use a
   sign test to extract a random Boolean value.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s.
 */

#pragma once

// ---------------------------------------------------------

#include <stdint.h>
#include <string.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// ---------------------------------------------------------

namespace utils {

// ---------------------------------------------------------

typedef struct {
    uint64_t s[16]; 
    int p;
} xorshift_prng_ctx_t;

// ---------------------------------------------------------

void get_random_from_dev_urandom(uint8_t* data, size_t num_bytes) {
    int gathered_bytes = open("/dev/urandom", O_RDONLY);
    size_t len = 0;

    while (len < num_bytes) {
        ssize_t num_gathered_bytes = read(
            gathered_bytes, 
            data + len, 
            num_bytes - len
        );

        if (num_gathered_bytes < 0) {
            puts("Error, unable to read stream");
            close(gathered_bytes);
            exit(EXIT_FAILURE);
        } else {
            len += num_gathered_bytes;
        }
    }

    close(gathered_bytes);
}

// ---------------------------------------------------------

void xorshift1024_init(xorshift_prng_ctx_t* ctx) {
    const size_t num_bytes = 16 * sizeof(uint64_t);
    get_random_from_dev_urandom((uint8_t*)(ctx->s), num_bytes);
    ctx->p = 0;
}

// ---------------------------------------------------------

uint64_t xorshift1024_next(xorshift_prng_ctx_t* ctx) {
    const uint64_t s0 = ctx->s[ctx->p];
    uint64_t s1 = ctx->s[ctx->p = (ctx->p + 1) & 15];
    s1 ^= s1 << 31; // a
    ctx->s[ctx->p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30); // b,c
    return ctx->s[ctx->p] * UINT64_C(1181783497276652981);
}

// ---------------------------------------------------------

void get_random(xorshift_prng_ctx_t *ctx, 
                uint8_t* data, 
                const size_t num_bytes) {
    const size_t wordsize = sizeof(uint64_t);
    const size_t num_words = num_bytes / wordsize;

    for (size_t i = 0; i < num_words; ++i) {
        const uint64_t word = xorshift1024_next(ctx);
        memcpy(data + i * wordsize, &word, wordsize);
    }

    const size_t num_bytes_remaining = num_bytes - num_words * wordsize;

    if (num_bytes_remaining > 0) {
        const uint64_t word = xorshift1024_next(ctx);
        memcpy(data, &word, num_bytes_remaining);
    }
}

// ---------------------------------------------------------

void get_random(uint8_t* data, 
                const size_t num_bytes) {
    xorshift_prng_ctx_t ctx;
    xorshift1024_init(&ctx);
    get_random(&ctx, data, num_bytes);
}

} // namespace utils
