/**
 * Given a byte array as mask of n bytes, this class will allow to generate a
 * series of n-byte values when calling next which iterate over all possible
 * values where the mask has 1 bits. 
 * 
 * Example: mask = [10000000,01000001] will generate 2**3 = 8 outputs, namely
 * [00000000,00000000], [00000000,00000001], 
 * [00000000,01000000], [00000000,01000001], 
 * [10000000,00000000], [10000000,00000001], 
 * [10000000,01000000], [10000000,01000001]
 * in this sequence, one at a time, when calling next().
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "utils/convert.h"
#include "utils/StateIterator.h"

// ---------------------------------------------------------

namespace utils {

// ---------------------------------------------------------
// Helper functions
// ---------------------------------------------------------

static size_t find_hamming_weight(const uint8_t* states_mask, 
                                  const size_t num_bytes) {
    size_t hamming_weight = 0;

    for (size_t i = 0; i < num_bytes; ++i) {
        uint8_t mask = 1;

        for (int j = 0; j < 8; ++j) {
            if ((states_mask[i] & mask) != 0) {
                hamming_weight++;
            }

            mask <<= 1;
        }
    }

    return hamming_weight;
}

// ---------------------------------------------------------

static void find_shift_indices(const uint8_t* states_mask, 
                               const size_t num_bytes, 
                               std::vector<uint8_t>& shift_indices) {
    size_t hamming_weight = 0;
    uint8_t bit_position;

    shift_indices.clear();

    for (int i = num_bytes-1; i >= 0; --i) {
        uint8_t mask = 1;

        for (int j = 0; j < 8; ++j) {
            if ((states_mask[i] & mask) != 0) {
                bit_position = (num_bytes-1-i) * 8 + j;
                shift_indices.push_back(bit_position);

#ifdef DEBUG
                printf("bit_position: %hhu\n", bit_position);
#endif
                hamming_weight++;
            }

            mask <<= 1;
        }
    }
}

// ---------------------------------------------------------
// Methods
// ---------------------------------------------------------

StateIterator::StateIterator(const uint8_t* states_mask, const size_t num_bytes) {
    this->states_mask = (uint8_t*)malloc(num_bytes);
    memcpy(this->states_mask, states_mask, num_bytes);

    num_state_bytes = num_bytes;
    num_active_bits = find_hamming_weight(states_mask, num_bytes);
    num_states = ((size_t)1L) << num_active_bits;

    find_shift_indices(states_mask, num_bytes, shift_indices);
    reset();
}

// ---------------------------------------------------------

StateIterator::~StateIterator() {
    free(states_mask);
}

// ---------------------------------------------------------

void StateIterator::reset() {
    current_state_index = 0;
}

// ---------------------------------------------------------

bool StateIterator::has_next() {
    return num_states > current_state_index;
}

// ---------------------------------------------------------

uint64_t StateIterator::internal_next_as_uint64() {
    uint64_t next_value = 0L;
    size_t mask = 1L;

    for (size_t i = 0; i < num_active_bits; ++i) {
        if ((current_state_index & mask) != 0) {
            next_value |= 1L << shift_indices[i];
        }
        
        mask <<= 1;
    }

    return next_value;
}

// ---------------------------------------------------------

uint64_t StateIterator::next_as_uint64() {
    const uint64_t next_value = internal_next_as_uint64();
    current_state_index++;
    return next_value;
}

// ---------------------------------------------------------

void StateIterator::next(uint8_t* state) {
    const uint64_t next_value = internal_next_as_uint64();
    current_state_index++;
    to_uint8(state, next_value, num_state_bytes);

#ifdef DEBUG
    printf(
        "index: %zu/%zu next_value: %08lx \n", 
        current_state_index, 
        num_states, 
        next_value
    );
#endif
}

} // namespace utils
