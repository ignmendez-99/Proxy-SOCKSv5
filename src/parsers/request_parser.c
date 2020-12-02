#include <stdlib.h>
#include <stdio.h>   // used by print_current_request_parser()
#include "request_parser.h"

void
request_parser_init(struct request_parser *rp) {
    rp->state = request_reading_version;
    rp->address_index = 0;
    rp->address_type = -1;
    rp->destination_port = -1;  // must store negative value to represent "first time checking this value"
    rp->destination_address_length = -1;
    rp->destination_address = NULL;
}


enum request_state
consume_request_buffer(buffer *b, struct request_parser *rp) {
    enum request_state state = rp->state;  // Le damos un valor por si no se entra en el while

    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = parse_single_request_character(c, rp);
        if(state == request_finished) {
            // ejecutamos una vez más para generar el request_reply
            parse_single_request_character(c, rp);
            break;
        } else if(state == request_has_error) {
            break;   // stop reading
        }
    }

    return state;
}


enum request_state
parse_single_request_character(const uint8_t c, struct request_parser *rp) {
    switch(rp->state) {

        case request_reading_version:
            if(c == PROXY_SOCKS_REQUEST_SUPPORTED_VERSION)
                rp->state = request_reading_command;
            else {
                getReplyBasedOnState(rp);
                rp->state = request_has_error;
            }
            break;

        case request_reading_command:
            if(c == CONNECT_COMMAND)
                rp->state = request_reading_reserved;
            else {
                getReplyBasedOnState(rp);
                rp->state = request_has_error;
            }
            break;
        
        case request_reading_reserved:
            if(c == PROXY_SOCKS_REQUEST_RESERVED)
                rp->state = request_reading_address_type;
            else {
                getReplyBasedOnState(rp);
                rp->state = request_has_error;
            }
            break;
        
        case request_reading_address_type:
            if(c == REQUEST_THROUGH_IPV4) {
                rp->destination_address_length = 4;
                rp->destination_address = calloc(4 + 1, sizeof(c));  // +1 for \0
                if(rp->destination_address == NULL) {
                    rp->state = request_has_error;
                    getReplyBasedOnState(rp);
                }
            } else if(c == REQUEST_THROUGH_IPV6) {
                rp->destination_address_length = 16;
                rp->destination_address = calloc(16 + 1, sizeof(c)); // +1 for \0
                if(rp->destination_address == NULL) {
                    rp->state = request_has_error;
                    getReplyBasedOnState(rp);
                }
            } else if(c == REQUEST_THROUGH_FQDN) {
				rp->destination_address_length = 0;
            } else {
                getReplyBasedOnState(rp);
                rp->state = request_has_error;
                break;
            }
            
            rp->address_type = c;
            rp->state = request_reading_destination_address;
            break;

        case request_reading_destination_address:
            if(rp->address_index == 0 && rp->destination_address_length == 0) {
            	if(c == 0) {
					rp->destination_address[rp->address_index] = 0;
					rp->state = request_reading_destination_port;
					break;
				}
                // reading first byte from FQDN
                rp->destination_address_length = c;
                rp->destination_address = calloc(c + 1, sizeof(c)); // +1 for \0
                if(rp->destination_address == NULL) {
                    rp->state = request_has_error;
                    getReplyBasedOnState(rp);
                }
            } else {
                // Save the byte
                rp->destination_address[rp->address_index] = c;
				rp->address_index++;
                if(rp->address_index == rp->destination_address_length) {
                    // ya pusimos todos los bytes
                    rp->destination_address[rp->address_index] = '\0';
                    rp->state = request_reading_destination_port;
                }
            }
            break;
        
        case request_reading_destination_port:
            if(rp->destination_port == -1){ 
                // first time here
                rp->destination_port = c * 256;
            } else {
                rp->destination_port += c;
                rp->state = request_finished;
            }
            break;
        
        case request_finished:
        case request_has_error:
            getReplyBasedOnState(rp);
            break;
        
        default:
            // Impossible state!
            exit(EXIT_FAILURE);
    }
    return rp->state;
}

void getReplyBasedOnState(struct request_parser *rp) {

    switch(rp->state) {
        case request_reading_version:
        case request_reading_reserved:
        case request_has_error:
        case request_reading_destination_port:    // Not actually reached. Just to suppress warnings
        case request_reading_destination_address: // Not actually reached. Just to suppress warnings
            rp->reply = GENERAL_SOCKS_SERVER_FAILURE;
            break;
        
        case request_reading_command:
            rp->reply = COMMAND_NOT_SUPPORTED;
            break;

        case request_reading_address_type:
            rp->reply = ADDRESS_TYPE_NOT_SUPPORTED;
            break;

        case request_finished:
            rp->reply = SUCCEDED;
            break;

        default:
            // Impossible
            exit(EXIT_FAILURE);
    }
}


void
request_marshall(buffer *b, struct request_parser *rp) {
    size_t space_left_to_write;
    uint8_t *where_to_write = buffer_write_ptr(b, &space_left_to_write);

    uint16_t space_needed_for_request_marshall = 1 + 1 + 1 + 1+ IPv4_LENGTH + 2;

    int i = 0;

    where_to_write[i++] = PROXY_SOCKS_REQUEST_SUPPORTED_VERSION;
    where_to_write[i++] = rp->reply;
    where_to_write[i++] = 0x00;  // RSV

    where_to_write[i++] = REQUEST_THROUGH_IPV4;
    for(int j = i; j < IPv4_LENGTH + i; j++) {
        where_to_write[j] = 0x00;   // BIND.ADDR
    }
    i += IPv4_LENGTH;
    where_to_write[i++] = 0x00;  // BIND.PORT
    where_to_write[i]   = 0x00;  // BIND.PORT

    buffer_write_adv(b, space_needed_for_request_marshall);
}
