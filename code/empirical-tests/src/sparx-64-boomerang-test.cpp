/**
 * Computes an <s>-step Boomerang for SPARX-64 for <k> random keys over <t> 
 * random texts, with start difference <alpha> and end difference <delta>.
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <atomic> 
#include <mutex>  // NOLINT(build/c++11)
#include <thread> // NOLINT(build/c++11)
#include <vector> 

#include "ciphers/sparx64.h"
#include "utils/argparse.h"
#include "utils/printing.h"
#include "utils/xorshift1024.h"
#include "utils/xor.h"

using utils::xorshift_prng_ctx_t;
using utils::xor_difference;
using utils::get_random;
using utils::print_hex;

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

#define NUM_THREADS 8

// ---------------------------------------------------------
// Types
// ---------------------------------------------------------

typedef struct {
    size_t  num_keys = 0;
    size_t  num_texts_per_key = 0L;
    size_t  num_steps = 5;
    uint8_t alpha[8];
    uint8_t delta[8];
} experiment_ctx_t;

// ---------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------

#ifdef DEBUG
static void do_print_quartet(const uint8_t* p, 
                             const uint8_t* p_, 
                             const uint8_t* q, 
                             const uint8_t* q_, 
                             std::mutex& mutex) {
    std::lock_guard<std::mutex> lock(mutex);
    puts("Quartet:");
    print_hex("p ", p,  SPARX64_STATE_LENGTH);
    print_hex("p'", p_, SPARX64_STATE_LENGTH);
    print_hex("q ", q,  SPARX64_STATE_LENGTH);
    print_hex("q'", q_, SPARX64_STATE_LENGTH);
}
#endif

// ---------------------------------------------------------
// Experiment
// ---------------------------------------------------------

static void experiment_thread(const experiment_ctx_t* ctx, 
                              sparx64_context_t* sparx_ctx,
#ifdef DEBUG
                              std::mutex& mutex, 
#endif
                              std::atomic<size_t>& counter, 
                              const size_t from, 
                              const size_t to) {
    uint8_t p[SPARX64_STATE_LENGTH];
    uint8_t p_[SPARX64_STATE_LENGTH];
    uint8_t q[SPARX64_STATE_LENGTH];
    uint8_t q_[SPARX64_STATE_LENGTH];
    uint8_t c[SPARX64_STATE_LENGTH];
    uint8_t c_[SPARX64_STATE_LENGTH];
    uint8_t d[SPARX64_STATE_LENGTH];
    uint8_t d_[SPARX64_STATE_LENGTH];
    uint8_t delta_q[SPARX64_STATE_LENGTH];

    xorshift_prng_ctx_t xorshift_ctx;
    xorshift1024_init(&xorshift_ctx);

    for (size_t i = from; i < to; ++i) {
        // P = random
        const uint64_t random_word = xorshift1024_next(&xorshift_ctx);
        memcpy(p, &random_word, SPARX64_STATE_LENGTH);

        // P' = P xor delta_p
        xor_difference(p_, p,  ctx->alpha, SPARX64_STATE_LENGTH);
        
        // Encrypt (P, P') -> (C, C')
        sparx_encrypt_steps(sparx_ctx, p,  c,  1, ctx->num_steps);
        sparx_encrypt_steps(sparx_ctx, p_, c_, 1, ctx->num_steps);

        // Delta-Shift (C, C') -> (D, D')
        xor_difference(d,  c,  ctx->delta, SPARX64_STATE_LENGTH);
        xor_difference(d_, c_, ctx->delta, SPARX64_STATE_LENGTH);

        sparx_decrypt_steps(sparx_ctx, d,  q,  ctx->num_steps);
        sparx_decrypt_steps(sparx_ctx, d_, q_, ctx->num_steps);
        xor_difference(delta_q, q,  q_, SPARX64_STATE_LENGTH);
        
        if (!memcmp(delta_q, ctx->alpha, SPARX64_STATE_LENGTH)) {
#ifdef DEBUG
            do_print_quartet(p, p_, q, q_, mutex);
#endif
            counter++;
        }
    }
}

// ---------------------------------------------------------------------

static void experiment_threading(const experiment_ctx_t* ctx, 
                                 sparx64_context_t* sparx_ctx) {

    // ---------------------------------------------------------------------
    // For all key candidates
    // ---------------------------------------------------------------------

#ifdef DEBUG
    std::mutex mutex;
#endif
    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);
    std::atomic<std::size_t> counter(0);

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
#ifdef DEBUG
            std::ref(mutex), 
#endif
            std::ref(counter),
            from, 
            to
        );
    }

    for (auto& thread : threads) {
        thread.join();
    }

    printf("Counter: %zu\n", counter.load());
}

// ---------------------------------------------------------------------

static void run_experiment(experiment_ctx_t* ctx) {
    // ---------------------------------------------------------
    // Initialize cipher context with random key
    // ---------------------------------------------------------

    uint8_t key[SPARX64_KEY_LENGTH];
    get_random(key, SPARX64_KEY_LENGTH);

#ifdef DEBUG
    print_hex("key", key, SPARX64_KEY_LENGTH);
#endif

    sparx64_context_t sparx_ctx;
    sparx_key_schedule(&sparx_ctx, key);

    experiment_threading(ctx, &sparx_ctx);
}

// ---------------------------------------------------------

static void run_experiments(experiment_ctx_t* ctx) {
    for (size_t i = 0; i < ctx->num_keys; ++i) {
        run_experiment(ctx);
    }
}

// ---------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------

static void parse_args(experiment_ctx_t* ctx, int argc, const char** argv) {
    ArgumentParser parser;
    parser.appName("Boomerang Test");
    parser.helpString("Computes an <s>-step Boomerang for SPARX-64 for <k> random keys over <t> random texts, with start difference <alpha> and end difference <delta>.");
    parser.addArgument("-k", "--num_keys", 1, false);
    parser.addArgument("-a", "--alpha", 1, false);
    parser.addArgument("-d", "--delta", 1, false);
    parser.addArgument("-s", "--num_steps", 1, false);
    parser.addArgument("-t", "--num_texts", 1, false);

    try {
        parser.parse(argc, argv);

        ctx->num_keys = parser.retrieveAsInt("k");
        ctx->num_steps = parser.retrieveAsInt("s");
        ctx->num_texts_per_key = parser.retrieveAsLong("t");

        parser.retrieveUint8ArrayFromHexString("a", ctx->alpha, 8);
        parser.retrieveUint8ArrayFromHexString("d", ctx->delta, 8);
    } catch( ... ) { 
        fprintf(stderr, "%s\n", parser.usage().c_str());
        exit(EXIT_FAILURE);
    }

    printf("#Keys      %8zu\n", ctx->num_keys);
    printf("#Texts/Key %8zu\n", ctx->num_texts_per_key);
    printf("#Steps     %8zu\n", ctx->num_steps);

    print_hex("Alpha", ctx->alpha, 8);
    print_hex("Delta", ctx->delta, 8);
}

// ---------------------------------------------------------

int main(int argc, const char** argv) {
    experiment_ctx_t ctx;
    parse_args(&ctx, argc, argv);
    run_experiments(&ctx);
    return 0;
}
