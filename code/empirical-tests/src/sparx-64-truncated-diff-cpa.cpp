/**
 * Truncated-Differential Attack on n-Step SPARX-647128
 * 
 * @author Ralph Ankele, Eik List
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <thread> // NOLINT(build/c++11)
#include <vector>

#include "ciphers/sparx64.h"
#include "utils/argparse.h"
#include "utils/convert.h"
#include "utils/printing.h"
#include "utils/xorshift1024.h"
#include "utils/xor.h"

using utils::get_random;
using utils::print_hex;
using utils::to_uint16;
using utils::to_uint64;
using utils::xor_difference;
using utils::xorshift_prng_ctx_t;

// ---------------------------------------------------------
// Constants and defines
// ---------------------------------------------------------

#define NUM_THREADS 8
#define ROTL16(x, n) (((x) << n) | ((x) >> (16 - (n))))
#define ROTR16(x, n) (((x) >> n) | ((x) << (16 - (n))))
#define SWAP(x, y) tmp = x; x = y; y = tmp

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef struct {
    const uint8_t  alpha[SPARX64_STATE_LENGTH] = { 
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x60, 0x42, 0x05
    };
    // Only test the right half 
    const uint64_t delta_mask          = 0x00000000FFFFFFFFL;
    // The bits that are one in our mask must have the following difference:
    const uint64_t delta               = 0x0000000000000000L;
    const size_t   num_texts_per_key   = 1L << 32;
    const size_t   num_rounds_inverted = 2;
    const size_t   num_steps           = 5;
    size_t         num_keys            = 0;
    size_t         num_collisions      = 0;
} experiment_ctx_t;

// ---------------------------------------------------------
// Helper functions
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

static bool has_correct_difference(const uint64_t delta_c, 
                                   const uint64_t desired_delta, 
                                   const uint64_t delta_mask) {
    // Returns true if ciphertext difference is zero on right half, and 
    // false otherwise.
    return (delta_c & delta_mask) == desired_delta;
}

// ---------------------------------------------------------
// Experiment
// ---------------------------------------------------------

static void experiment_thread(experiment_ctx_t* ctx, 
                              const sparx64_context_t* sparx_ctx, 
                              std::atomic<size_t>& counter, 
                              const size_t from, 
                              const size_t to) {
    size_t num_collisions = 0;

    uint8_t internalstate1[SPARX64_STATE_LENGTH];
    uint8_t internalstate2[SPARX64_STATE_LENGTH];
    uint8_t plaintext1[SPARX64_STATE_LENGTH];
    uint8_t plaintext2[SPARX64_STATE_LENGTH];
    uint8_t ciphertext1[SPARX64_STATE_LENGTH];
    uint8_t ciphertext2[SPARX64_STATE_LENGTH];

    uint16_t ciphertext1_uint16[4];
    uint16_t ciphertext2_uint16[4];

    memset(internalstate1, 0, SPARX64_STATE_LENGTH);
    memset(internalstate2, 0, SPARX64_STATE_LENGTH);
    memset(plaintext1, 0, SPARX64_STATE_LENGTH);
    memset(plaintext2, 0, SPARX64_STATE_LENGTH);
    memset(ciphertext1, 0, SPARX64_STATE_LENGTH);
    memset(ciphertext2, 0, SPARX64_STATE_LENGTH);

    // use xorshift generator for random numbers
    xorshift_prng_ctx_t xorshift_ctx;
    xorshift1024_init(&xorshift_ctx);

    for (size_t j = from; j < to; ++j) {
        // Generate 2^32 random pairs
        const uint64_t random_word = xorshift1024_next(&xorshift_ctx);
        memcpy(internalstate1, &random_word, SPARX64_STATE_LENGTH);

        // XOR the difference to the second state
        xor_difference(internalstate2, internalstate1, ctx->alpha, SPARX64_STATE_LENGTH);

        // Calculate backwards (key recovery) to actual plaintext
        sparx_decrypt_rounds(sparx_ctx, internalstate1, plaintext1, ctx->num_rounds_inverted);
        sparx_decrypt_rounds(sparx_ctx, internalstate2, plaintext2, ctx->num_rounds_inverted);

        sparx_encrypt_steps(sparx_ctx, plaintext1, ciphertext1, ctx->num_steps);
        sparx_encrypt_steps(sparx_ctx, plaintext2, ciphertext2, ctx->num_steps);

        // Invert final linear layer
        to_uint16(ciphertext1_uint16, ciphertext1, SPARX64_STATE_LENGTH);
        to_uint16(ciphertext2_uint16, ciphertext2, SPARX64_STATE_LENGTH);

        L2_inverse(ciphertext1_uint16);
        L2_inverse(ciphertext2_uint16);

        const uint64_t ciphertext1_uint64 = to_uint64(ciphertext1_uint16);
        const uint64_t ciphertext2_uint64 = to_uint64(ciphertext2_uint16);
        const uint64_t delta_c_uint64 = ciphertext1_uint64 ^ ciphertext2_uint64;

        if (has_correct_difference(delta_c_uint64, ctx->delta, ctx->delta_mask)) {
            // Increase collision counter
            num_collisions++;
        }
    }
    
    counter += num_collisions;
}

// ---------------------------------------------------------------------

static void experiment_threading(experiment_ctx_t* ctx, 
                                 sparx64_context_t* sparx_ctx) {

    // ---------------------------------------------------------------------
    // For all key candidates
    // ---------------------------------------------------------------------

    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);
    std::atomic<std::size_t> num_collisions(0);

    const size_t offset = ctx->num_texts_per_key / NUM_THREADS;

    for (size_t i = 0; i < NUM_THREADS; ++i) {
        size_t from = i * offset;
        size_t to = (i+1) * offset;

        if (i+1 == NUM_THREADS) {
            to = ctx->num_texts_per_key;
        }

        threads.emplace_back(experiment_thread, 
            std::ref(ctx), 
            std::ref(sparx_ctx), 
            std::ref(num_collisions),
            from, 
            to
        );
    }

    for (auto& thread : threads) {
        thread.join();
    }

    printf("%zu\n", num_collisions.load());
    ctx->num_collisions += num_collisions.load();
}

// ---------------------------------------------------------------------

static void run_experiment(experiment_ctx_t* ctx) {

    // ---------------------------------------------------------
    // Initialize cipher context with random key
    // ---------------------------------------------------------

    uint8_t key[SPARX64_KEY_LENGTH];
    get_random(key, SPARX64_KEY_LENGTH);
    print_hex("key", key, SPARX64_KEY_LENGTH);

    sparx64_context_t sparx_ctx;
    sparx_key_schedule(&sparx_ctx, key);
    experiment_threading(ctx, &sparx_ctx);
}

// ---------------------------------------------------------

static void run_experiments(experiment_ctx_t* ctx) {
    for (size_t i = 0; i < ctx->num_keys; ++i) {
        run_experiment(ctx);
    }

    const double average_num_collisions = (double)ctx->num_collisions / ctx->num_keys;
    printf("Avg #pairs for truncated attack: %4f\n", average_num_collisions);
}

// ---------------------------------------------------------
// Reading command-line arguments
// ---------------------------------------------------------

static void parse_args(experiment_ctx_t* ctx, int argc, const char** argv) {
    ArgumentParser parser;
    parser.appName("Truncated-Differential-CPA");
    parser.addArgument("-k", "--num_keys", 1, false);

    try {
        parser.parse(argc, argv);

        ctx->num_keys = parser.retrieveAsInt("k");
    } catch( ... ) { 
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys      %8zu\n", ctx->num_keys);
    printf("#Pairs     %8zu\n", ctx->num_texts_per_key);
}

// ---------------------------------------------------------

int main(int argc, const char** argv) {
    experiment_ctx_t ctx;
    parse_args(&ctx, argc, argv);
    run_experiments(&ctx);
    return 0;
}
