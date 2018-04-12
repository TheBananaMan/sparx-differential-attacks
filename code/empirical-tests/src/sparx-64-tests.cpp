/**
 * Tests the implementation of SPARX-64/128.
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "ciphers/sparx64.h"
#include "utils/convert.h"
#include "utils/printing.h"

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

static const uint16_t SPARX_64_128_KEY[] = {
    0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff
};

static const uint16_t SPARX_64_128_EXPANDED_KEYS[17][2 * 3] = {
    { 0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb },
    { 0xccdd, 0xef00, 0x4433, 0xccff, 0x8888, 0x3376 },
    { 0x8899, 0xaabd, 0xaa99, 0x169a, 0xeecc, 0xe399 },
    { 0x8888, 0x3379, 0xddce, 0x7738, 0x8867, 0x8dd2 },
    { 0xeecc, 0xe39d, 0x448a, 0x896e, 0x2258, 0x00a6 },
    { 0x8867, 0x8dd7, 0x7d7a, 0xf30d, 0xc204, 0x7c7b },
    { 0x2258, 0x00ac, 0x5ce7, 0x6bb9, 0xda61, 0x5ec6 },
    { 0xc204, 0x7c82, 0xb0f0, 0xb240, 0x0dd7, 0x1df9 },
    { 0xda61, 0x5ece, 0x8606, 0x740f, 0x36f6, 0x264f },
    { 0x0dd7, 0x1e02, 0x2282, 0x59bb, 0xa888, 0xcdca },
    { 0x36f6, 0x2659, 0xcc1d, 0xb415, 0xee9f, 0x0dd0 },
    { 0xa888, 0xcdd5, 0x12c6, 0x8ba2, 0xdee3, 0x3fb7 },
    { 0xee9f, 0x0ddc, 0xdf26, 0xe871, 0xf1ec, 0x7413 },
    { 0xdee3, 0x3fc4, 0x4db9, 0x7ac9, 0x2cdf, 0x633a },
    { 0xf1ec, 0x7421, 0x0781, 0xf891, 0x553a, 0x735a },
    { 0x2cdf, 0x6349, 0x4e04, 0x9e81, 0x5585, 0x9712 },
    { 0x553a, 0x736a, 0x21a2, 0xac87, 0x6fa6, 0x4b08 }
};

static const uint16_t SPARX_64_128_PLAINTEXT[] = {
    0x0123, 0x4567, 0x89ab, 0xcdef
};
static const uint16_t SPARX_64_128_CIPHERTEXT[] = {
    0x2bbe, 0xf152, 0x01f5, 0x5f98
};

// ---------------------------------------------------------
// Testing
// ---------------------------------------------------------

void initialize_test_vectors(uint16_t* plaintext, uint16_t* master_key) {
    memcpy(master_key, SPARX_64_128_KEY,       SPARX64_KEY_LENGTH);
    memcpy(plaintext,  SPARX_64_128_PLAINTEXT, SPARX64_STATE_LENGTH);
}

// ---------------------------------------------------------

bool check_test_vectors(const uint16_t* expected, const uint16_t* actual) {
    const bool correct = !memcmp(
        (uint8_t*)expected, (uint8_t*)actual, SPARX64_STATE_LENGTH
    );

    if (correct) {
        printf("Passed\n");
    } else { 
        utils::print_hex("Expected", expected, SPARX64_STATE_LENGTH);
        utils::print_hex("Actual  ", actual,   SPARX64_STATE_LENGTH);
    }

    return correct;
}

// ---------------------------------------------------------

static bool test_sparx_64() {
    uint16_t x[SPARX64_STATE_LENGTH];
    uint16_t c[SPARX64_STATE_LENGTH];
    uint16_t master_key[SPARX64_KEY_LENGTH];
    bool    all_tests_passed = 1;

    initialize_test_vectors(x, master_key);
    utils::print_hex("Master key", master_key, SPARX64_NUM_KEY_WORDS);

    sparx64_context_t ctx;
    sparx_key_schedule(&ctx, master_key);

    for (size_t i = 0; i < SPARX64_NUM_BRANCHES * SPARX64_NUM_STEPS + 1; i++) {
        printf("k^{%2zu}: ", i);
        utils::print_hex(ctx.subkeys[i], 2 * SPARX64_NUM_ROUNDS_PER_STEP);

        all_tests_passed &= !memcmp(ctx.subkeys[i], 
            SPARX_64_128_EXPANDED_KEYS[i], 
            2 * SPARX64_NUM_ROUNDS_PER_STEP
        );

        if (!all_tests_passed) {
            printf("Round key %zu incorrect\n", i);
        }
    }
    
    puts("");
    utils::print_hex("P", x, SPARX64_NUM_STATE_WORDS);
    
    sparx_encrypt(&ctx, x, c);
    utils::print_hex("C", c, SPARX64_NUM_STATE_WORDS);
    
    all_tests_passed &= check_test_vectors(SPARX_64_128_CIPHERTEXT, c);

    sparx_decrypt(&ctx, c, x);
    utils::print_hex("P", x, SPARX64_NUM_STATE_WORDS);

    all_tests_passed &= check_test_vectors(SPARX_64_128_PLAINTEXT, x);
    return all_tests_passed;
}

// ---------------------------------------------------------

int main() {
    const bool all_tests_passed = test_sparx_64();
    return !all_tests_passed;
}
