/**
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include "utils/xor.h"

// ---------------------------------------------------------

namespace utils {

void xor_difference(uint8_t* p1, 
                    uint8_t* p2, 
                    uint32_t delta1, 
                    uint32_t delta2) {
    uint32_t* p1_ = (uint32_t*)p1;
    uint32_t* p2_ = (uint32_t*)p2;

    p2_[0] = p1_[0] ^ delta1;
    p2_[1] = p1_[1] ^ delta2;
}

// ---------------------------------------------------------

void xor_difference(uint8_t* target, 
                    const uint8_t* lhs, 
                    const uint8_t* rhs, 
                    const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; ++i) {
        target[i] = lhs[i] ^ rhs[i];
    }
}

} // namespace utils
