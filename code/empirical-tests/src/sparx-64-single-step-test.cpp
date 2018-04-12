/**
 * Encrypts <#pairs> of random texts with the given XOR difference <delta_l,
 * delta_r> with 1-step SPARX-64 under <#keys> random keys each, and counts and
 * outputs how many pairs have a zero difference on the left side after the
 * first step.
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ciphers/sparx64.h"
#include "utils/argparse.h"
#include "utils/printing.h"
#include "utils/xorshift1024.h"
#include "utils/xor.h"

using utils::xor_difference;
using utils::get_random;
using utils::print_hex;

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef struct {
    uint32_t delta_l = 0;
    uint32_t delta_r = 0;
    size_t   num_keys = 0;
    size_t   num_texts_per_key = 0;
    uint64_t num_collisions = 0;
    bool     use_rotated_differences = 0;
    size_t   num_steps = 1;
} experiment_ctx_t;

// ---------------------------------------------------------
// Helper functions
// ---------------------------------------------------------

static void print(const size_t num_collisions) {
    printf("%4lu\n", num_collisions);
}

// ---------------------------------------------------------

static bool have_target_difference(const uint8_t* c1, const uint8_t* c2) {
    const uint32_t* c1_ = (const uint32_t*)c1;
    const uint32_t* c2_ = (const uint32_t*)c2;
    const bool result = (c1_[0] == c2_[0]);

#ifdef DEBUG
    if (result) {
        uint8_t delta[8];
        for (int i = 0; i < 8; ++i) {
            delta[i] = c1[i] ^ c2[i];
        }

        print_hex("", delta, 8);
    }
#endif

    return result;
}

// ---------------------------------------------------------
// The actual experiment
// ---------------------------------------------------------

static void run_experiment(experiment_ctx_t* ctx) {
    uint8_t key[SPARX64_KEY_LENGTH];
    size_t num_collisions;
    ctx->num_collisions = 0;
    sparx64_context_t sparx_ctx;

    puts("Iterations #Collisions");

    for (size_t i = 0; i < ctx->num_keys; ++i) {
        get_random(key, SPARX64_KEY_LENGTH);
        sparx_key_schedule(&sparx_ctx, key);
        num_collisions = 0;

        // ---------------------------------------------------------
        // Fill pool of random bytes since opening/closing files
        // iteratively would slow down
        // ---------------------------------------------------------

        const size_t NUM_RANDOM_POOL_BYTES = 
            ctx->num_texts_per_key * SPARX64_STATE_LENGTH;

        uint8_t* random_bytes_pool = (uint8_t*)malloc(NUM_RANDOM_POOL_BYTES);
        get_random(random_bytes_pool, NUM_RANDOM_POOL_BYTES);

        uint8_t* p1; 
        uint8_t p2[SPARX64_STATE_LENGTH];
        uint8_t c1[SPARX64_STATE_LENGTH];
        uint8_t c2[SPARX64_STATE_LENGTH];
        memset(c1, 0, SPARX64_STATE_LENGTH);
        memset(c2, 0, SPARX64_STATE_LENGTH);

        for (size_t j = 0; j < ctx->num_texts_per_key; ++j) {
            p1 = random_bytes_pool + (j * SPARX64_STATE_LENGTH);
            xor_difference(p1, p2, ctx->delta_l, ctx->delta_r);

            sparx_encrypt_steps(&sparx_ctx, p1, c1, ctx->num_steps);
            sparx_encrypt_steps(&sparx_ctx, p2, c2, ctx->num_steps);

            if (have_target_difference(c1, c2)) {
                ++num_collisions;
            }
        }

        free(random_bytes_pool);
        ctx->num_collisions += num_collisions;
        print(num_collisions);
    }

    double average_num_collisions = (double)ctx->num_collisions / ctx->num_keys;
    printf("Avg #collisions: %4f\n", average_num_collisions);
}

// ---------------------------------------------------------
// Reading command-line arguments
// ---------------------------------------------------------

static void parse_args(experiment_ctx_t* ctx, int argc, const char** argv) {
    ArgumentParser parser;
    parser.appName("Single-Step-Test");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-l", "--delta_l", 1, false);
    parser.addArgument("-r", "--delta_r", 1, false);
    parser.addArgument("-t", "--num_texts", 1, false);

    try {
        parser.parse(argc, argv);

        ctx->num_keys = parser.retrieveAsInt("k");
        ctx->num_texts_per_key = parser.retrieveAsInt("t");
        ctx->delta_l = parser.retrieveUint32FromHexString("l");
        ctx->delta_r = parser.retrieveUint32FromHexString("r");
    } catch( ... ) { 
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys      %8zu\n", ctx->num_keys);
    printf("#Texts/Key %8zu\n", ctx->num_texts_per_key);

    print_hex("Delta L  ", (uint8_t*)&(ctx->delta_l), 4);
    print_hex("Delta R  ", (uint8_t*)&(ctx->delta_r), 4);
}

// ---------------------------------------------------------

int main(int argc, const char** argv) {
    experiment_ctx_t ctx;
    parse_args(&ctx, argc, argv);
    run_experiment(&ctx);
    return 0;
}
