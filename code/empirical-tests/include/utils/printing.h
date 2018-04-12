/**
 * Printing helper functions. 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */
 #pragma once

// ---------------------------------------------------------

#include <stdint.h>

// ---------------------------------------------------------

namespace utils {

// ---------------------------------------------------------

void print_hex(const char* label, 
               const uint8_t* array, 
               const size_t num_bytes);

void print_hex(const char* label, 
               const uint16_t* array, 
               const size_t num_words);

void print_hex(const uint8_t* array, 
               const size_t num_bytes);

void print_hex(const uint16_t* array, 
               const size_t num_words);

} // namespace utils
