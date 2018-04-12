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

#include "utils/convert.h"

#include <stdint.h>
#include <stdlib.h>

// ---------------------------------------------------------

namespace utils {

// ---------------------------------------------------------

void to_uint8(uint8_t* target, 
              const uint16_t* src, 
              const size_t num_bytes) {
    const size_t num_words = num_bytes / 2;

    for (size_t i = 0; i < num_words; ++i) {
        target[2*i]   = (src[i] >> 8) & 0xff;
        target[2*i+1] =  src[i]       & 0xff;
    }
}

// ---------------------------------------------------------

void to_uint8(uint8_t target[4], const uint32_t src) {
    target[0] = (src >> 24) & 0xFF;
    target[1] = (src >> 16) & 0xFF;
    target[2] = (src >>  8) & 0xFF;
    target[3] = (src      ) & 0xFF;
}

// ---------------------------------------------------------

void to_uint8(uint8_t target[8], const uint64_t src) {
    target[0] = (src >> 56) & 0xFF;
    target[1] = (src >> 48) & 0xFF;
    target[2] = (src >> 40) & 0xFF;
    target[3] = (src >> 32) & 0xFF;
    target[4] = (src >> 24) & 0xFF;
    target[5] = (src >> 16) & 0xFF;
    target[6] = (src >>  8) & 0xFF;
    target[7] = (src      ) & 0xFF;
}

// ---------------------------------------------------------

void to_uint8(uint8_t* target, const uint64_t src, const size_t num_bytes) {
    size_t shift = 0;

    for (int i = num_bytes-1; i >= 0; --i) {
        target[i] = (src >> shift) & 0xFF;
        shift += 8;
    }
}

// ---------------------------------------------------------

void to_uint16(uint16_t* target, 
               const uint8_t* src, 
               const size_t num_bytes) {
    const size_t num_words = num_bytes / 2;

    for (size_t i = 0; i < num_words; ++i) {
        target[i] = ((src[2*i]   & 0xff) << 8) 
                   | (src[2*i+1] & 0xff);
    }
}

// ---------------------------------------------------------

void to_uint16(uint16_t target[4], const uint64_t src) {
	target[0] = (src >> 48) & 0xFFFF;
	target[1] = (src >> 32) & 0xFFFF;
	target[2] = (src >> 16) & 0xFFFF;
	target[3] = (src      ) & 0xFFFF;
}

// ---------------------------------------------------------

uint64_t to_uint64(const uint8_t src[8]) {
    return ((uint64_t)src[0] << 56)
         | ((uint64_t)src[1] << 48)
         | ((uint64_t)src[2] << 40)
         | ((uint64_t)src[3] << 32)
         | ((uint64_t)src[4] << 24)
         | ((uint64_t)src[5] << 16)
         | ((uint64_t)src[6] <<  8)
         | ((uint64_t)src[7]      );
}

// ---------------------------------------------------------

uint64_t to_uint64(const uint16_t src[4]) {
	return ((uint64_t)src[0] << 48)
		 | ((uint64_t)src[1] << 32)
		 | ((uint64_t)src[2] << 16)
		 | ((uint64_t)src[3]      );
}

} // namespace utils
