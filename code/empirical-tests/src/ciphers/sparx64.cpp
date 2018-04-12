/**
 * Computes an <s>-step Boomerang for SPARX-64 for <k> random keys over <t> 
 * random texts, with start difference <alpha> and end difference <delta>.
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ciphers/sparx64.h"
#include "utils/printing.h"
#include "utils/convert.h"

using namespace utils;

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

#define ROTL16(x, n) (((x) << n) | ((x) >> (16 - (n))))
#define ROTR16(x, n) (((x) >> n) | ((x) << (16 - (n))))
#define SWAP(x, y) tmp = x; x = y; y = tmp

// SPARX versions
#define SPARX_64_128  0
#define SPARX_128_128 1
#define SPARX_128_256 2

#ifndef SPARX_VERSION
#define SPARX_VERSION SPARX_64_128
#endif

#if (SPARX_VERSION == SPARX_64_128)

static const size_t NUM_STEPS = 8;
static const size_t NUM_ROUNDS_PER_STEP = 3;
static const size_t NUM_BRANCHES = 2;

#define SPARX_L               L2
#define SPARX_L_INV           L2_inverse
#define SPARX_KEY_PERMUTATION K_perm_64_128

#elif (SPARX_VERSION == SPARX_128_128)

static const size_t NUM_STEPS = 8;
static const size_t NUM_ROUNDS_PER_STEP = 4;
static const size_t NUM_BRANCHES = 4;

#define SPARX_L               L4
#define SPARX_L_INV           L4_inverse
#define SPARX_KEY_PERMUTATION K_perm_128_128

#elif (SPARX_VERSION == SPARX_128_256)

static const size_t NUM_STEPS = 10;
static const size_t NUM_ROUNDS_PER_STEP = 4;
static const size_t NUM_BRANCHES = 4;

#define SPARX_L               L4
#define SPARX_L_INV           L4_inverse
#define SPARX_KEY_PERMUTATION K_perm_128_256

#endif

// ---------------------------------------------------------
// Utils
// ---------------------------------------------------------

static void xor_difference(uint16_t* target,
                           const uint16_t* p1, 
                           const uint16_t* p2) {
    uint32_t* t_  = (uint32_t*)target;
    uint32_t* p1_ = (uint32_t*)p1;
    uint32_t* p2_ = (uint32_t*)p2;

    t_[0] = p1_[0] ^ p2_[0];
    t_[1] = p1_[1] ^ p2_[1];
}

// ---------------------------------------------------------

static void print_difference(const uint16_t* state1, 
                             const uint16_t* state2, 
                             uint16_t* delta) {
    xor_difference(delta, state1, state2);
    print_hex(delta, SPARX64_NUM_STATE_WORDS);
}

// ---------------------------------------------------------
// Basic functions and their inverses
// ---------------------------------------------------------

static void A(uint16_t* l, uint16_t* r) {
    (*l) = ROTR16((*l), 7);
    (*l) += (*r);
    (*r) = ROTL16((*r), 2);
    (*r) ^= (*l);
}

// ---------------------------------------------------------

static void A_inverse(uint16_t* l, uint16_t* r)
{
    (*r) ^= (*l);
    (*r) = ROTR16((*r), 2);
    (*l) -= (*r);
    (*l) = ROTL16((*l), 7);
}

// ---------------------------------------------------------

static void L2(uint16_t* state) {
    uint16_t tmp = state[0] ^ state[1];
    tmp = ROTL16(tmp, 8);
    state[2] ^= state[0] ^ tmp;
    state[3] ^= state[1] ^ tmp;

    SWAP(state[0], state[2]);
    SWAP(state[1], state[3]);
}

// ---------------------------------------------------------

static void L2_inverse(uint16_t* state) {
    uint16_t tmp;

    SWAP(state[0], state[2]);
    SWAP(state[1], state[3]);

    tmp = state[0] ^ state[1];
    tmp = ROTL16(tmp, 8);
    state[2] ^= state[0] ^ tmp;
    state[3] ^= state[1] ^ tmp;
}

// ---------------------------------------------------------
// Key Schedule
// ---------------------------------------------------------

static void K_perm_64_128(uint16_t* key, const uint16_t round) {
    uint16_t tmp0;
    uint16_t tmp1;
    uint16_t i;

    // Misty-like transformation
    A(key+0, key+1);
    key[2] += key[0];
    key[3] += key[1];
    key[7] += round;

    // Branch rotation
    tmp0 = key[6];
    tmp1 = key[7];
    
    for (i = 7; i >= 2; i--) {
        key[i] = key[i-2];
    }

    key[0] = tmp0;
    key[1] = tmp1;
}

// ---------------------------------------------------------
// Takes a 128-bit master key and turns it into 2*(NUM_STEPS+1) subkeys
// of 96 bit.
// ---------------------------------------------------------

void sparx_key_schedule(sparx64_context_t* ctx, 
                        const uint16_t master_key[SPARX64_NUM_KEY_WORDS]) {

    uint16_t key[SPARX64_NUM_KEY_WORDS];
    memcpy((uint8_t*)key, (uint8_t*)master_key, SPARX64_KEY_LENGTH);

    const size_t NUM_ROUND_KEYS = NUM_BRANCHES * NUM_STEPS + 1;

    for (size_t c = 0; c < NUM_ROUND_KEYS; c++) {
        for (size_t i = 0 ; i < 2 * NUM_ROUNDS_PER_STEP; i++) {
            ctx->subkeys[c][i] = key[i];

#ifdef DEBUG
            printf("Branch/round: %2zu/%2zu ", c, i);
            print_hex(&(ctx->subkeys[c][i]), 1);
#endif
        }

        SPARX_KEY_PERMUTATION(key, c+1);
    }
}

// ---------------------------------------------------------

void sparx_key_schedule(sparx64_context_t* ctx, 
                        const uint8_t master_key[SPARX64_KEY_LENGTH]) {
    uint16_t key[SPARX64_NUM_KEY_WORDS];
    to_uint16(key, master_key, SPARX64_KEY_LENGTH);
    sparx_key_schedule(ctx, key);
}

// ---------------------------------------------------------
// Encryption and Decryption Logic
// ---------------------------------------------------------

static void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                                 uint16_t state[SPARX64_NUM_STATE_WORDS],
                                 const size_t from_round,
                                 const size_t to_round) {
    const size_t s = from_round/NUM_ROUNDS_PER_STEP;

#ifdef DEBUG
        puts("Plaintext");
        print_hex(state, 4);
#endif
    
    for (size_t b = 0; b < NUM_BRANCHES; ++b) {
        for (size_t r = from_round-1; r < to_round; ++r) {
            state[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
            state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
            A(state + 2 * b, state + 2 * b+1);

#ifdef DEBUG
            printf("Branch/round: %2zu/%2zu ", b, r);
            print_hex(state, 4);
#endif
        }
    }
}

// ---------------------------------------------------------

static void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                                 uint16_t state[SPARX64_NUM_STATE_WORDS],
                                 const size_t num_rounds) {
    sparx_encrypt_rounds(ctx, state, 1, num_rounds);
}

// ---------------------------------------------------------

static void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                                 uint16_t state[SPARX64_NUM_STATE_WORDS],
                                 const size_t from_round, 
                                 const size_t to_round) {
    const size_t s = from_round / NUM_ROUNDS_PER_STEP;
    
    for (size_t b = 0; b < NUM_BRANCHES; ++b) {
        for (size_t r = to_round-1; r >= from_round-1; --r) {
            A_inverse(state + 2 * b, state + 2 * b+1);
            state[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
            state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
        }
    }
}

// ---------------------------------------------------------

static void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                                 uint16_t state[SPARX64_NUM_STATE_WORDS],
                                 const size_t num_rounds) {
    const size_t s = 0;
    
    for (size_t b = 0; b < NUM_BRANCHES; ++b) {
        for (int r = num_rounds-1; r >= 0; --r) {
            A_inverse(state + 2 * b, state + 2 * b+1);
            state[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
            state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
        }
    }
}

// ---------------------------------------------------------

static void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                                uint16_t state[SPARX64_NUM_STATE_WORDS],
                                const size_t from_step,
                                const size_t to_step) {
    #ifdef DEBUG
        puts("Plaintext");
        print_hex(state, 4);
#endif
    
    for (size_t s = from_step-1; s < to_step; ++s) {
        for (size_t b = 0; b < NUM_BRANCHES; ++b) {
            for (size_t r = 0; r < NUM_ROUNDS_PER_STEP; ++r) {
                state[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
                state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
                A(state + 2 * b, state + 2 * b+1);

#ifdef DEBUG
                printf("Branch/round: %2zu/%2zu ", b, r);
                print_hex(state, 8);
#endif
            }
        }

        SPARX_L(state);

#ifdef DEBUG
        puts("After L");
        print_hex(state, 4);
#endif
    }

    if (to_step == SPARX64_NUM_STEPS) {
        for (size_t b = 0; b < NUM_BRANCHES; ++b) {
            state[2*b  ] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b  ];
            state[2*b+1] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b+1];
        }
    }
}

// ---------------------------------------------------------

static void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                                uint16_t state[SPARX64_NUM_STATE_WORDS], 
                                const size_t from_step,
                                const size_t to_step) {
    if (to_step == SPARX64_NUM_STEPS) {
        for (size_t b = 0; b < NUM_BRANCHES; ++b) {
            state[2*b  ] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b  ];
            state[2*b+1] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b+1];
        }
    }

    const int last_step = (int)from_step - 1;

    for (int s = to_step - 1; s >= last_step; --s) {
        SPARX_L_INV(state);

        for (size_t b = 0; b < NUM_BRANCHES; ++b) {
            for (int r = NUM_ROUNDS_PER_STEP - 1; r >= 0; --r) {
                A_inverse(state + 2 * b, state + 2 * b+1);
                state[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
                state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
            }
        }
    }
}

// ---------------------------------------------------------

static void internal_sparx_encrypt_steps_trail(
    const sparx64_context_t* ctx, 
    uint16_t state1[SPARX64_NUM_STATE_WORDS], 
    uint16_t state2[SPARX64_NUM_STATE_WORDS], 
    const size_t num_steps) {

    uint16_t delta[SPARX64_NUM_STATE_WORDS];
    print_difference(state1, state2, delta);
    
    for (size_t s = 0; s < num_steps; ++s) {
        for (size_t r = 0; r < NUM_ROUNDS_PER_STEP; ++r) {
            for (size_t b = 0; b < NUM_BRANCHES; ++b) {
                state1[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
                state1[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
                A(state1 + 2 * b, state1 + 2 * b+1);

                state2[2 * b]     ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
                state2[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
                A(state2 + 2 * b, state2 + 2 * b+1);
            }

            print_difference(state1, state2, delta);
        }

        SPARX_L(state1);
        SPARX_L(state2);

        print_difference(state1, state2, delta);
    }

    if (num_steps == SPARX64_NUM_STEPS) {
        for (size_t b = 0; b < NUM_BRANCHES; ++b) {
            state1[2*b  ] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b  ];
            state1[2*b+1] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b+1];

            state2[2*b  ] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b  ];
            state2[2*b+1] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2*b+1];
        }

        print_difference(state1, state2, delta);
    }
}

// ---------------------------------------------------------
// API
// ---------------------------------------------------------

void sparx_linear_layer(const uint8_t p[SPARX64_STATE_LENGTH], 
                        uint8_t c[SPARX64_STATE_LENGTH]) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, p, SPARX64_STATE_LENGTH);
    SPARX_L(state);
    to_uint8(c, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_invert_linear_layer(const uint8_t c[SPARX64_STATE_LENGTH], 
                               uint8_t p[SPARX64_STATE_LENGTH]) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, c, SPARX64_STATE_LENGTH);
    SPARX_L_INV(state);
    to_uint8(p, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                          uint16_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t num_rounds) {
    memcpy((uint8_t*)c, (uint8_t*)p, SPARX64_STATE_LENGTH);
    sparx_encrypt_rounds(ctx, c, 1, num_rounds);
}

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                          uint16_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t from_round, 
                          const size_t to_round) {
    memcpy((uint8_t*)c, (uint8_t*)p, SPARX64_STATE_LENGTH);
    sparx_encrypt_rounds(ctx, c, from_round, to_round);
}

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t from_round,
                          const size_t to_round) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, p, SPARX64_STATE_LENGTH);
    sparx_encrypt_rounds(ctx, state, from_round, to_round);
    to_uint8(c, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t num_rounds) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, p, SPARX64_STATE_LENGTH);
    sparx_encrypt_rounds(ctx, state, num_rounds);
    to_uint8(c, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_steps) {
    memcpy((uint8_t*)c, (uint8_t*)p, SPARX64_STATE_LENGTH);
    sparx_encrypt_steps(ctx, c, 1, num_steps);
}

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         const size_t from_step, 
                         const size_t to_step) {
    memcpy((uint8_t*)c, (uint8_t*)p, SPARX64_STATE_LENGTH);
    sparx_encrypt_steps(ctx, c, from_step, to_step);
}

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t p[SPARX64_STATE_LENGTH], 
                         uint8_t c[SPARX64_STATE_LENGTH], 
                         const size_t num_steps) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, p, SPARX64_STATE_LENGTH);
    sparx_encrypt_steps(ctx, state, 1, num_steps);
    to_uint8(c, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t p[SPARX64_STATE_LENGTH], 
                         uint8_t c[SPARX64_STATE_LENGTH], 
                         const size_t from_step, 
                         const size_t to_step) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, p, SPARX64_STATE_LENGTH);
    sparx_encrypt_steps(ctx, state, from_step, to_step);
    to_uint8(c, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          const size_t from_round,
                          const size_t to_round) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, c, SPARX64_STATE_LENGTH);
    sparx_decrypt_rounds(ctx, state, from_round, to_round);
    to_uint8(p, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                         const uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_rounds) {
    memcpy((uint8_t*)p, (uint8_t*)c, SPARX64_STATE_LENGTH);
    sparx_decrypt_rounds(ctx, p, num_rounds);
}

// ---------------------------------------------------------

void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                         const uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_steps) {
    memcpy((uint8_t*)p, (uint8_t*)c, SPARX64_STATE_LENGTH);
    sparx_decrypt_steps(ctx, p, 1, num_steps);
}

// ---------------------------------------------------------

void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          const size_t num_rounds) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, c, SPARX64_STATE_LENGTH);
    sparx_decrypt_rounds(ctx, state, num_rounds);
    to_uint8(p, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t c[SPARX64_NUM_STATE_WORDS], 
                         uint8_t p[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_steps) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, c, SPARX64_STATE_LENGTH);
    sparx_decrypt_steps(ctx, state, 1, num_steps);
    to_uint8(p, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t c[SPARX64_STATE_LENGTH], 
                         uint8_t p[SPARX64_STATE_LENGTH], 
                         const size_t from_step, 
                         const size_t to_step) {
    uint16_t state[SPARX64_NUM_STATE_WORDS];
    to_uint16(state, c, SPARX64_STATE_LENGTH);
    sparx_decrypt_steps(ctx, state, from_step, to_step);
    to_uint8(p, state, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

void sparx_encrypt(const sparx64_context_t* ctx, 
                   const uint16_t p[SPARX64_STATE_LENGTH], 
                   uint16_t c[SPARX64_STATE_LENGTH]) {
    sparx_encrypt_steps(ctx, p, c, NUM_STEPS);
}

// ---------------------------------------------------------

void sparx_encrypt(const sparx64_context_t* ctx, 
                   const uint8_t p[SPARX64_STATE_LENGTH], 
                   uint8_t c[SPARX64_STATE_LENGTH]) {
    sparx_encrypt_steps(ctx, p, c, NUM_STEPS);
}

// ---------------------------------------------------------

void sparx_decrypt(const sparx64_context_t* ctx, 
                   const uint16_t c[SPARX64_STATE_LENGTH], 
                   uint16_t p[SPARX64_STATE_LENGTH]) {
    sparx_decrypt_steps(ctx, c, p, NUM_STEPS);
}

// ---------------------------------------------------------

void sparx_decrypt(const sparx64_context_t* ctx, 
                   const uint8_t c[SPARX64_STATE_LENGTH], 
                   uint8_t p[SPARX64_STATE_LENGTH]) {
    sparx_decrypt_steps(ctx, c, p, NUM_STEPS);
}

// ---------------------------------------------------------

void sparx_encrypt_steps_trail(const sparx64_context_t* ctx, 
                               const uint16_t p1[SPARX64_NUM_STATE_WORDS], 
                               const uint16_t p2[SPARX64_NUM_STATE_WORDS], 
                               const size_t num_steps) {
    uint16_t state1[SPARX64_NUM_STATE_WORDS];
    uint16_t state2[SPARX64_NUM_STATE_WORDS];
    memcpy((uint8_t*)state1, (uint8_t*)p1, SPARX64_STATE_LENGTH);
    memcpy((uint8_t*)state2, (uint8_t*)p2, SPARX64_STATE_LENGTH);
    internal_sparx_encrypt_steps_trail(ctx, state1, state2, num_steps);
}

// ---------------------------------------------------------

void sparx_encrypt_steps_trail(const sparx64_context_t* ctx, 
                               const uint8_t p1[SPARX64_STATE_LENGTH], 
                               const uint8_t p2[SPARX64_STATE_LENGTH], 
                               const size_t num_steps) {
    uint16_t state1[SPARX64_NUM_STATE_WORDS];
    uint16_t state2[SPARX64_NUM_STATE_WORDS];
    to_uint16(state1, p1, SPARX64_STATE_LENGTH);
    to_uint16(state2, p2, SPARX64_STATE_LENGTH);
    internal_sparx_encrypt_steps_trail(ctx, state1, state2, num_steps);
}
