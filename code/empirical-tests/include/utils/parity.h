/**
 * Helper functions to evaluate the parity 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#pragma once

#include <cstdint>
#include <cstdlib>

namespace utils {

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

static const size_t NUM_PARITY_ENTRIES = 1 << 8;
static bool PARITY_TABLE[NUM_PARITY_ENTRIES];

// ---------------------------------------------------------

static bool precompute_parity(uint8_t value) {
    uint8_t mask = 1;
    bool parity = 0;

    for (size_t i = 0; i < 8; ++i) {
        parity ^= ((value & mask) != 0);
        mask <<= 1;
    }

    return parity;
}

// ---------------------------------------------------------

void precompute_parity_table() {
    for (size_t i = 0; i < NUM_PARITY_ENTRIES; ++i) {
        PARITY_TABLE[i] = precompute_parity(i);
    }
}

// ---------------------------------------------------------

bool get_parity(const uint8_t* value, 
                const uint8_t* mask, 
                const size_t num_bytes) {
    bool parity = 0;

    for (size_t i = 0; i < num_bytes; ++i) {
        parity ^= PARITY_TABLE[value[i] & mask[i]];
    }

    return parity;
}

// ---------------------------------------------------------

} // namespace utils
