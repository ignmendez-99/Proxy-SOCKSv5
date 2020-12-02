#ifndef PROTO_HELLO_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define PROTO_HELLO_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/selector.h"
#include "../parsers/my_hello_parser.h"


/** Represents the evolution of the Hello reading-->parsing-->writing **/
struct my_hello_stm {
    struct my_hello_parser my_hello_parser;

    buffer rb; // Exclusive internal buffers used for reading and writing Hello
    buffer wb; ////
    uint8_t *read_buffer_data; // Where 'rb' will read from
    uint8_t *write_buffer_data; // Where 'wb' will write to
    
    uint8_t code;
};


/**
 * Initialize the Hello reading state
 */
unsigned
my_hello_read_init(const unsigned state, struct selector_key *key);

/**
 * Reads the Hello from the FD.
 * If Hello is read completely, we jump to the WRITING_HELLO global state
 */
unsigned
my_hello_read(struct selector_key *key);

unsigned
my_hello_write(struct selector_key *key);


#endif
