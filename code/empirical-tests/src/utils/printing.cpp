/**
 * Printing helper functions.
 * 
 * @author eik list
 * @copyright see license.txt
 * @last-modified 2018-04
 */

#include <stdio.h>

#include "utils/printing.h"

namespace utils {

// ---------------------------------------------------------
// Printing Helper Functions
// ---------------------------------------------------------

void print_hex(const char* label, 
               const uint8_t* array, 
               const size_t num_bytes) {
    printf("%s: ", label);

    for (size_t i = 0; i < num_bytes; i++) {
        printf("%02x", array[i]);
    }

    puts("");
}

// ---------------------------------------------------------

void print_hex(const char* label, 
               const uint16_t* array, 
               const size_t num_words) {
    printf("%s: ", label);

    for (size_t i = 0; i < num_words; i++) {
        printf("%04x", array[i]);
    }
    
    puts("");
}

// ---------------------------------------------------------

void print_hex(const uint8_t* array, 
               const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++) {
        printf("%02x", array[i]);
    }

    puts("");
}

// ---------------------------------------------------------

void print_hex(const uint16_t* array, 
               const size_t num_words) {
    for (size_t i = 0; i < num_words; i++) {
        printf("%04x", array[i]);
    }
    
    puts("");
}

} // namespace utils
