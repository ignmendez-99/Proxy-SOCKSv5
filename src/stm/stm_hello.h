#ifndef STM_HELLO_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define STM_HELLO_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/selector.h"
#include "../parsers/hello_parser.h"


/** Represents the evolution of the Hello reading-->parsing-->writing **/
struct hello_stm {
    struct hello_parser hello_parser;

    buffer rb; // Exclusive internal buffers used for reading and writing Hello
    buffer wb; ////
    uint8_t *read_buffer_data; // Where 'rb' will read from
    uint8_t *write_buffer_data; // Where 'wb' will write to
    
    int method_selected;  // Authentication method selected by proxy
};


/**
 * Initialize the Hello reading state
 */
unsigned
hello_read_init(const unsigned state, struct selector_key *key);

/**
 * Reads the Hello from the FD.
 * If Hello is read completely, we jump to the WRITING_HELLO global state
 */
unsigned
hello_read(struct selector_key *key);

/** Writes the Hello response to the client */
unsigned
hello_write(struct selector_key *key);


#endif
