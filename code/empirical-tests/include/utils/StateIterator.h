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

#pragma once

#include <stdint.h>
#include <vector>

// ---------------------------------------------------------

namespace utils {

// ---------------------------------------------------------

/**
 * @author eik list
 * @last-modified 2017-03-03
 */
class StateIterator {
public:
    StateIterator(const uint8_t* states_mask, const size_t num_bytes);
    ~StateIterator();
    void     reset();
    bool     has_next();
    void     next(uint8_t* state);
    uint64_t next_as_uint64();
    size_t   get_num_states() const { return num_states; }
private:
    size_t   current_state_index = 0;
    size_t   num_states;
    size_t   num_state_bytes;
    size_t   num_active_bits;
    uint8_t* states_mask;
    std::vector<uint8_t> shift_indices;

    uint64_t internal_next_as_uint64();
};

// ---------------------------------------------------------

} // namespace utils
