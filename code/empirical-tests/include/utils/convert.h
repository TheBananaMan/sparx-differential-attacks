/**
 * Converting functions in Big-Endian manner, i.e. arrays
 * 
 * uint8_t  s8  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }
 * uint16_t s16 = { 0x0001, 0x0203, 0x0405, 0x0607 }
 * uint32_t s32 = { 0x00010203, 0x04050607 }
 * uint64_t s64 = { 0x0001020304050607L }
 * 
 * shall be converted s.t. they are equivalent. The leftmost/0-th
 * byte shall be the highest; the rightmost/7-th shall be the lowest.
 * 
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

void to_uint8(uint8_t* target, 
              const uint16_t* src, 
              const size_t num_bytes);

// ---------------------------------------------------------

void to_uint8(uint8_t target[4], const uint32_t src);

// ---------------------------------------------------------

void to_uint8(uint8_t target[8], const uint64_t src);

// ---------------------------------------------------------

void to_uint8(uint8_t* target, const uint64_t src, const size_t num_bytes);

// ---------------------------------------------------------

void to_uint16(uint16_t* target, 
               const uint8_t* src, 
               const size_t num_bytes);

// ---------------------------------------------------------

void to_uint16(uint16_t target[4], const uint64_t src);

// ---------------------------------------------------------

uint64_t to_uint64(const uint8_t src[8]);

// ---------------------------------------------------------

uint64_t to_uint64(const uint16_t src[4]);

// ---------------------------------------------------------

} // namespace utils
