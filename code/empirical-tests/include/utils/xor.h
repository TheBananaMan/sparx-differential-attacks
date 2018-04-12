/**
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#pragma once

// ---------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>

// ---------------------------------------------------------

namespace utils {

void xor_difference(uint8_t* p1, 
                    uint8_t* p2, 
                    uint32_t delta1, 
                    uint32_t delta2);

// ---------------------------------------------------------

void xor_difference(uint8_t* target, 
                    const uint8_t* lhs, 
                    const uint8_t* rhs, 
                    const size_t num_bytes);

} // namespace utils

