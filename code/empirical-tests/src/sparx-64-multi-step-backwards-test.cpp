/**
 * Decrypts 2^(32) ciphertexts C with fixed right side 
 * after the inverted linear layer: 
 * S = (L xor j, R) after the final step
 * C = (R xor LLayer(L xor j), L xor j)
 * 
 * Iterates over all possible values j up to 2^(32) - 1.
 * Decrypts the ciphertexts through <s>-step SPARX-64 under a random key, 
 * stores the corresponding plaintexts and checks how many of the 
 * pairs fulfill the given input difference <delta l, delta r>.
 * Outputs the number of such pairs and repeats this experiment for <#keys> 
 * random keys.
 * 
 * @author eik list
 * @author ralph ankele
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "ciphers/sparx64.h"
#include "utils/argparse.h"
#include "utils/convert.h"
#include "utils/printing.h"
#include "utils/xorshift1024.h"
#include "utils/xor.h"

using utils::xor_difference;
using utils::get_random;
using utils::print_hex;
using utils::to_uint8;

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef struct {
    uint32_t delta_l = 0;
    uint32_t delta_r = 0;
    size_t   num_keys = 0;
    size_t   num_texts_per_key = 1L << 32;
    uint64_t num_collisions = 0;
    bool     use_rotated_differences = 0;
    size_t   num_steps = 1;
} experiment_ctx_t;

// ---------------------------------------------------------
// Helper functions
// ---------------------------------------------------------

static void linear_layer(uint8_t* input, uint8_t* output) {
    uint8_t lo = (input[0] ^ input[2]);
    uint8_t hi = (input[1] ^ input[3]);
    output[0] ^= hi;
    output[1] ^= lo;
    output[2] ^= hi;
    output[3] ^= lo;
}

// ---------------------------------------------------------

static void xor_bytes(uint8_t* inout, uint8_t* in, const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; ++i) {
        inout[i] ^= in[i];
    }
}

// ---------------------------------------------------------

static void print(const size_t num_collisions) {
    printf("%4lu\n", num_collisions);
}

// ---------------------------------------------------------

static bool check_difference(const uint64_t* c1,
                             const uint64_t* c2,
                             const uint32_t delta_l,
                             const uint32_t delta_r){
    const uint32_t* c1_l = (uint32_t*) (*c1 & 0xFFFFFFFF);
    const uint32_t* c1_h = (uint32_t*) ((*c1 >> 32) & 0xFFFFFFFF);
    const uint32_t* c2_l = (uint32_t*) (*c2 & 0xFFFFFFFF);
    const uint32_t* c2_h = (uint32_t*) ((*c2 >> 32) & 0xFFFFFFFF);
    return (((*c1_l ^ *c2_l) == delta_r) 
         && ((*c1_h ^ *c2_h) == delta_l));
}

// ---------------------------------------------------------

/**
 * Store an 8-byte array x into table.
 * Given some item x = [x0,x1,x2,x3,x4,x5,x6,x7], we use
 * [x0,...,x3] as key and [x4,...,x7] as value.
 */
static void store(std::vector<uint64_t>& table, 
                  const uint8_t entry[SPARX64_STATE_LENGTH]) {
    const uint64_t value = *((uint64_t*)entry);
    table.push_back(value);
}

// ---------------------------------------------------------
// Experiment
// ---------------------------------------------------------

static void run_experiment(experiment_ctx_t* ctx) {
    std::vector<uint64_t> table;
    std::vector<uint64_t> table_base;
    size_t num_collisions;
    
    uint8_t key[SPARX64_KEY_LENGTH];
    ctx->num_collisions = 0;
    sparx64_context_t sparx_ctx;

    //puts("Iterations #Collisions");

    for (size_t i = 0; i < ctx->num_keys; ++i) {
        get_random(key, SPARX64_KEY_LENGTH);
        sparx_key_schedule(&sparx_ctx, key);
        num_collisions = 0;

        // ---------------------------------------------------------
        // Get random base state (L^s, R^s)
        // R will be the same value after Step s for all texts.
        // The ciphertexts will go through the Feistel halves-swap 
        // and the final linear layer. For the j-th ciphertext, 
        // we have L^s_j = L^s xor j and R^s_j computed as:
        // C = (R^s_j = LLayer(L^s_j), L^s_j).
        // Since LLayer is linear, it holds that
        // R^s_j = LLayer(L^s) xor LLayer(j), 
        // So, we can precompute 
        // Cbase = (R^s = LLayer(L^s), L^s)
        // and have to compute only C = (R^s xor LLayer(j), L^s xor j)
        // for each ciphertext.
        // ---------------------------------------------------------
        
        uint8_t base_ciphertext[SPARX64_STATE_LENGTH]; 
        get_random(base_ciphertext, SPARX64_STATE_LENGTH);

        // The (start+4, start) includes the swap halves of the Feistel network.
        linear_layer(base_ciphertext+4, base_ciphertext);

        uint8_t ciphertext[SPARX64_STATE_LENGTH];
        uint8_t plaintext[SPARX64_STATE_LENGTH];
        uint8_t base_plaintext[SPARX64_STATE_LENGTH];

        // The index j as byte array
        uint8_t index[4];

        memset(plaintext, 0, SPARX64_STATE_LENGTH);
        memset(base_plaintext, 0, SPARX64_STATE_LENGTH);

        for (size_t j = 0; j < ctx->num_texts_per_key; ++j) {
            memcpy(ciphertext, base_ciphertext, SPARX64_STATE_LENGTH);
            to_uint8(index, j);
            xor_bytes(ciphertext, index, 4);
            linear_layer(index, ciphertext);

            sparx_decrypt_steps(&sparx_ctx, ciphertext, plaintext, ctx->num_steps);
            store(table, plaintext);
            sparx_decrypt_steps(&sparx_ctx, base_ciphertext, base_plaintext, ctx->num_steps);
            store(table_base, base_plaintext);
        }

        for (size_t j = 0; j < ctx->num_texts_per_key; ++j) {
            if (check_difference(&table[j], 
                                &table_base[j], 
                                ctx->delta_l, 
                                ctx->delta_r)) {
                num_collisions++;
            }
        }

        ctx->num_collisions += num_collisions;
        print(num_collisions);
        table.clear();
        table_base.clear();
    }

    double average_num_collisions = (double)ctx->num_collisions / ctx->num_keys;
    printf("Avg #collisions: %4f\n", average_num_collisions);
}

// ---------------------------------------------------------
// Reading command-line arguments
// ---------------------------------------------------------

static void parse_args(experiment_ctx_t* ctx, int argc, const char** argv) {
    ArgumentParser parser;
    parser.appName("Multi-Step-Test");
    parser.helpString("Computes differences for <k> random keys over <s> steps of SPARX-64/128 in decryption direction from a start difference (<delta_l>, <delta_r>).");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-l", "--delta_l", 1, false);
    parser.addArgument("-r", "--delta_r", 1, false);
    parser.addArgument("-s", "--num_steps", 1, false);

    try {
        parser.parse(argc, argv);

        ctx->num_keys = parser.retrieveAsInt("k");
        ctx->num_steps = parser.retrieveAsInt("s");
        ctx->delta_l = parser.retrieveUint32FromHexString("l");
        ctx->delta_r = parser.retrieveUint32FromHexString("r");
    } catch( ... ) { 
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys      %8zu\n", ctx->num_keys);
    printf("#Steps     %8zu\n", ctx->num_steps);

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
