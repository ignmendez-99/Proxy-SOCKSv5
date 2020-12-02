#include <stdlib.h>
#include "hello_parser.h"


void
hello_parser_init(struct hello_parser *hp) {
    hp->state = hello_reading_version;
    hp->methods_remaining = 0;
    hp->methods_index = 0;
    hp->methods = NULL;
}

enum hello_state
consume_hello_buffer(buffer *b, struct hello_parser *hp) {
    enum hello_state state = hp->state;  // Le damos un valor por si no se entra en el while

    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = parse_single_hello_character(c, hp);
        if(state == hello_finished || state == hello_unsupported_version || state == hello_server_error) {
            break;   // stop reading
        }
    }

    return state;
}

enum hello_state
parse_single_hello_character(const uint8_t c, struct hello_parser *hp) {
    switch(hp->state) {

        case hello_reading_version:
            if(c == PROXY_SOCKS_HELLO_SUPPORTED_VERSION)
                hp->state = hello_reading_nmethods;
            else
                hp->state = hello_unsupported_version;
            break;
        
        case hello_reading_nmethods:
            if(c <= 0) {
                // zero methods were given
                hp->state = hello_server_error;
            } else {
                hp->methods_remaining = c; 
                hp->methods = calloc(c, sizeof(c));
                if(hp->methods == NULL) {
                    hp->state = hello_server_error;
                    return hp->state;
                }
                hp->state = hello_reading_methods;
            }
            break;
        
        case hello_reading_methods:
            hp->methods[hp->methods_index++] = c;
            if(hp->methods_index == hp->methods_remaining) {
                hp->state = hello_finished;
            }
            break;
        
        case hello_finished:
        case hello_unsupported_version:
        case hello_server_error:
            // return these states now
            break;
            
        default:
            // Impossible state!
            exit(EXIT_FAILURE);
    }
    return hp->state;
}

void
hello_marshall(buffer *b, const uint8_t method) {
    size_t space_left_to_write;
    uint8_t *where_to_write_next = buffer_write_ptr(b, &space_left_to_write);

    where_to_write_next[0] = PROXY_SOCKS_HELLO_SUPPORTED_VERSION;
    where_to_write_next[1] = method;
    buffer_write_adv(b, SPACE_NEEDED_FOR_HELLO_MARSHALL);
}
