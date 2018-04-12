/**
 * Implementation of an extended API for the SPARX-64/128 cipher. 
 * 
 * Re-implementation of the cipher.
 * Reference under https://github.com/cryptolu/SPARX 
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#pragma once

#include <stdint.h>

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

#define SPARX64_KEY_LENGTH          16
#define SPARX64_STATE_LENGTH         8

#define SPARX64_NUM_STATE_WORDS      4
#define SPARX64_NUM_KEY_WORDS        8

// The key has four dwords, i.e., four 32-bit words
#define SPARX64_NUM_KEY_DWORDS       SPARX64_NUM_KEY_WORDS/2 
#define SPARX64_NUM_STEPS            8
#define SPARX64_NUM_ROUNDS_PER_STEP  3
#define SPARX64_NUM_BRANCHES         2

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef struct {
    uint16_t subkeys[17][2 * 3];
} sparx64_context_t;

// ---------------------------------------------------------
// API
// ---------------------------------------------------------

void sparx_key_schedule(sparx64_context_t* ctx, 
                        const uint16_t key[SPARX64_NUM_KEY_WORDS]);

// ---------------------------------------------------------

void sparx_key_schedule(sparx64_context_t* ctx, 
                        const uint8_t key[SPARX64_KEY_LENGTH]);

// ---------------------------------------------------------

void sparx_linear_layer(const uint8_t p[SPARX64_STATE_LENGTH], 
                        uint8_t c[SPARX64_STATE_LENGTH]);

// ---------------------------------------------------------

void sparx_invert_linear_layer(const uint8_t c[SPARX64_STATE_LENGTH], 
                               uint8_t p[SPARX64_STATE_LENGTH]);

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                          uint16_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t from_round, 
                          const size_t to_round);

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                          uint16_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t num_rounds);

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t from_round, 
                          const size_t to_round);

// ---------------------------------------------------------

void sparx_encrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t num_rounds);

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_steps);

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t p[SPARX64_STATE_LENGTH], 
                         uint8_t c[SPARX64_STATE_LENGTH], 
                         const size_t num_steps);

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint16_t p[SPARX64_STATE_LENGTH], 
                         uint16_t c[SPARX64_STATE_LENGTH], 
                         const size_t from_step, 
                         const size_t to_step);

// ---------------------------------------------------------

void sparx_encrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t p[SPARX64_STATE_LENGTH], 
                         uint8_t c[SPARX64_STATE_LENGTH], 
                         const size_t from_step, 
                         const size_t to_step);

// ---------------------------------------------------------

void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                         const uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_rounds);

// ---------------------------------------------------------

void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          const size_t from_round,
                          const size_t to_round);

// ---------------------------------------------------------

void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                         const uint16_t c[SPARX64_NUM_STATE_WORDS], 
                         uint16_t p[SPARX64_NUM_STATE_WORDS], 
                         const size_t num_steps);

// ---------------------------------------------------------

void sparx_decrypt_rounds(const sparx64_context_t* ctx, 
                          const uint8_t p[SPARX64_NUM_STATE_WORDS], 
                          uint8_t c[SPARX64_NUM_STATE_WORDS], 
                          const size_t num_rounds);

// ---------------------------------------------------------

void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t c[SPARX64_STATE_LENGTH], 
                         uint8_t p[SPARX64_STATE_LENGTH], 
                         const size_t num_steps);

// ---------------------------------------------------------

void sparx_decrypt_steps(const sparx64_context_t* ctx, 
                         const uint8_t c[SPARX64_STATE_LENGTH], 
                         uint8_t p[SPARX64_STATE_LENGTH], 
                         const size_t from_step, 
                         const size_t to_step);

// ---------------------------------------------------------

void sparx_encrypt(const sparx64_context_t* ctx, 
                   const uint16_t p[SPARX64_NUM_STATE_WORDS], 
                   uint16_t c[SPARX64_NUM_STATE_WORDS]);

// ---------------------------------------------------------

void sparx_encrypt(const sparx64_context_t* ctx, 
                   const uint8_t p[SPARX64_STATE_LENGTH], 
                   uint8_t c[SPARX64_STATE_LENGTH]);

// ---------------------------------------------------------

void sparx_decrypt(const sparx64_context_t* ctx, 
                   const uint16_t c[SPARX64_NUM_STATE_WORDS], 
                   uint16_t p[SPARX64_NUM_STATE_WORDS]);

// ---------------------------------------------------------

void sparx_decrypt(const sparx64_context_t* ctx, 
                   const uint8_t c[SPARX64_STATE_LENGTH], 
                   uint8_t p[SPARX64_STATE_LENGTH]);

// ---------------------------------------------------------

void sparx_encrypt_steps_trail(const sparx64_context_t* ctx, 
                               const uint16_t p1[SPARX64_NUM_STATE_WORDS], 
                               const uint16_t p2[SPARX64_NUM_STATE_WORDS], 
                               const size_t num_steps);

// ---------------------------------------------------------

void sparx_encrypt_steps_trail(const sparx64_context_t* ctx, 
                               const uint8_t p1[SPARX64_STATE_LENGTH], 
                               const uint8_t p2[SPARX64_STATE_LENGTH], 
                               const size_t num_steps);
