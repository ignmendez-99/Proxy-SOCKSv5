#include <stdlib.h>
#include <stdio.h>   // used by print_current_hello_parser()
#include "my_hello_parser.h"


void 
my_hello_parser_init(struct my_hello_parser *hp) {
    hp->state = my_hello_reading_version;
    hp->user_chars_remaining = 0;
    hp->pass_chars_remaining = 0;
    hp->user = NULL;
    hp->password = NULL;
    hp->char_index = 0; 
}

enum my_hello_state
my_consume_hello_buffer(buffer *b, struct my_hello_parser *hp) {
    enum my_hello_state state = hp->state;  // Le damos un valor por si no se entra en el while

    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = my_parse_single_hello_character(c, hp);
        if(state == my_hello_finished || state == my_hello_unsupported_version || state == my_hello_server_error || state == my_hello_bad_length) {
            break;   // stop reading
        }
    }

    return state;
}

enum my_hello_state
my_parse_single_hello_character(const uint8_t c, struct my_hello_parser *hp) {
    switch(hp->state) {

        case my_hello_reading_version:
            if(c == PROTO_HELLO_SUPPORTED_VERSION)
                hp->state = my_hello_reading_nuser;
            else
                hp->state = my_hello_unsupported_version;
            break;
        
        case my_hello_reading_nuser:
            if(c <= 0) {
                // username length is 0
                hp->state = my_hello_bad_length;
            } else {
                hp->user_chars_remaining = c; 
                hp->user = calloc(c + 1, sizeof(c));
                if(hp->user == NULL) {
                    hp->state = my_hello_server_error;
                    return hp->state;
                }
                hp->state = my_hello_reading_user;
            }
            break;
        
        case my_hello_reading_user:
            hp->user[hp->char_index++] = c;
            if(hp->char_index == hp->user_chars_remaining) {
                hp->user[hp->char_index++] = '\0';
                hp->state = my_hello_reading_npass;
            }
            break;

        case my_hello_reading_npass:
            if(c <= 0) {
                // password length is 0
                hp->state = my_hello_bad_length;
            } else {
                hp->pass_chars_remaining = c;
                hp->char_index = 0;
                hp->password = calloc(c + 1, sizeof(c));
                if(hp->password == NULL) {
                    hp->state = my_hello_server_error;
                    return hp->state;
                }
                hp->state = my_hello_reading_pass;
            }
            break;

        case my_hello_reading_pass:
            hp->password[hp->char_index++] = c;
            if(hp->char_index == hp->pass_chars_remaining) {
                hp->password[hp->char_index++] = '\0';
                hp->state = my_hello_finished;
            }
            break;
        
        case my_hello_bad_length:
        case my_hello_finished:
        case my_hello_unsupported_version:
        case my_hello_server_error:
            // return these states now
            break;
            
        default:
            // Impossible state!
            exit(EXIT_FAILURE);
    }
    return hp->state;
}


void
my_hello_marshall(buffer *b, const uint8_t code) {
    size_t space_left_to_write;
    uint8_t *where_to_write_next = buffer_write_ptr(b, &space_left_to_write);

    where_to_write_next[0] = PROTO_HELLO_SUPPORTED_VERSION;
    where_to_write_next[1] = code;
    buffer_write_adv(b, SPACE_NEEDED_FOR_HELLO_MARSHALL);
}
