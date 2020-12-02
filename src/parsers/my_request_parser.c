#include <stdlib.h>
#include "my_request_parser.h"

// Prototypes
static void getReplyBasedOnState(struct my_request_parser *rp);


void
my_request_parser_init(struct my_request_parser *rp) {
    rp->state = my_request_reading_command;
    rp->command = -1;
    rp->nparams = -1;
    rp->lparam1 = -1;
    rp->param1 = NULL;
    rp->lparam2 = -1;
    rp->param2 = NULL;
    rp->index = 0;
}


enum my_request_state
my_consume_request_buffer(buffer *b, struct my_request_parser *rp) {
    enum my_request_state state = rp->state;  // Le damos un valor por si no se entra en el while

    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = my_parse_single_request_character(c, rp);
        if(state == my_request_finished) {
            // ejecutamos una vez más para generar el request_reply
            my_parse_single_request_character(c, rp);
            break;
        } else if(state == my_request_has_error) {
            break;   // stop reading
        }
    }
    return state;
}
    
enum my_request_state
my_parse_single_request_character(const uint8_t c, struct my_request_parser *rp) {
    switch(rp->state) {
        case my_request_reading_command:
            if(c == get_historical_n_of_connections || c == get_n_of_concurrent_connections ||
            c == get_n_of_bytes_transferred || c == set_buffer_size) {
                rp->state = my_request_reading_n_params;
                rp->command = c;
            } else {
                rp->state = my_request_has_error;
                getReplyBasedOnState(rp);
            }
            break;

        case my_request_reading_n_params:
            if( (rp->command == set_buffer_size && c != 1) || (rp->command != set_buffer_size && c != 0) ) {
                rp->state = my_request_has_error;
                getReplyBasedOnState(rp);
            } else if(rp->command == set_buffer_size && c == 1) {
                rp->state = my_request_reading_l_param;
                rp->nparams = c;
            } else {
                rp->state = my_request_finished;
                rp->nparams = c;
            }
            break;

        case my_request_reading_l_param:
            if(c <= 0) {
                rp->state = my_request_has_error;
                getReplyBasedOnState(rp);
            } else {
                rp->lparam1 = c;
                rp->param1 = calloc(c, sizeof(c));
                rp->state = my_request_reading_param;
            }
            break;

        case my_request_reading_param:
            rp->param1[rp->index++] = c;
            if(rp->index == rp->lparam1)
                rp->state = my_request_finished;
            break;

        case my_request_finished:
        case my_request_has_error:
            getReplyBasedOnState(rp);
            break;
        
        default:
            // Impossible state!
            exit(EXIT_FAILURE);
    }
    return rp->state;
}

static void getReplyBasedOnState(struct my_request_parser *rp) {

    switch(rp->state) {
        case my_request_has_error:
            rp->reply.code = INVALID_COMMAND; // Request invalido
            rp->reply.len = 32;
            rp->reply.data = "Invalid command id or parameters";
            break;

        case my_request_finished:
            rp->reply.code = rp->command;
            break;

        default:
            // Impossible
            exit(EXIT_FAILURE);
    }
}

int my_request_marshall(buffer *b, struct my_request_parser *rp) {
    size_t space_left_to_write;
    uint8_t *where_to_write = buffer_write_ptr(b, &space_left_to_write);

    uint16_t space_needed_for_request_marshall = 2 + rp->reply.len;
    if(space_left_to_write < space_needed_for_request_marshall) {
        return -1;
    }

    int i = 0;

    where_to_write[i++] = rp->reply.code; // Command
    where_to_write[i++] = rp->reply.len;  // Data length
    for (; i < rp->reply.len + 2; i++)
        where_to_write[i] = rp->reply.data[i - 2];
    
    buffer_write_adv(b, space_needed_for_request_marshall);
    return 0;
}
