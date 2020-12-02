#ifndef MY_PROTO_REQUEST_H
#define MY_PROTO_REQUEST_H

#include "../utils/selector.h"
#include "../parsers/my_request_parser.h"

struct my_request_stm {
    struct my_request_parser my_request_parser;

    buffer rb; // Exclusive internal buffers used for reading and writing Request
    buffer wb; //
    uint8_t *read_buffer_data; // Where 'rb' will read from
    uint8_t *write_buffer_data; // Where 'wb' will write to

    
};

unsigned
my_request_read_init(const unsigned state, struct selector_key *key);

unsigned
my_request_read(struct selector_key *key);

unsigned
my_request_write(struct selector_key *key);

void
my_request_write_close(const unsigned state, struct selector_key *key);


#endif
