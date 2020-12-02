#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include "../myProtocol/my_proto_stm.h"
#include "../utils/params.h"
#include "my_protocol_server.h"

// Prototypes
static uint8_t authenticate_admin(uint8_t *user, uint8_t *password);


unsigned
my_hello_read_init(const unsigned state, struct selector_key *key) {
    struct my_hello_stm *hello_proto = &MY_PROTOCOL_ATTACHMENT(key)->my_hello_state;

    hello_proto->code = -1;  // Initial value

    // Initialize read buffer
    hello_proto->read_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(hello_proto->read_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&hello_proto->rb, get_buff_size(), hello_proto->read_buffer_data);

    // Initialize write buffer
    hello_proto->write_buffer_data = calloc(get_buff_size(), sizeof(uint8_t));
    if(hello_proto->write_buffer_data == NULL) {
        goto finally;
    }
    buffer_init(&hello_proto->wb, get_buff_size(), hello_proto->write_buffer_data);

    my_hello_parser_init(&hello_proto->my_hello_parser);
    return state;

finally:
    return MY_ERROR_GLOBAL_STATE;
}


unsigned
my_hello_read(struct selector_key *key) {
    struct my_hello_stm *hello_proto = &MY_PROTOCOL_ATTACHMENT(key)->my_hello_state;

    size_t nbytes;
    uint8_t *where_to_write = buffer_write_ptr(&hello_proto->rb, &nbytes);
    ssize_t ret = recv(key->fd, where_to_write, nbytes, 0);  // Non blocking !

    uint8_t returned_state = MY_READING_HELLO; // current state
    if(ret > 0) {
        buffer_write_adv(&hello_proto->rb, ret);
        enum my_hello_state state = my_consume_hello_buffer(&hello_proto->rb, &hello_proto->my_hello_parser);
        if(state == my_hello_finished || state == my_hello_server_error || state == my_hello_unsupported_version || state == my_hello_bad_length) {
            
            if (state == my_hello_server_error){
                hello_proto->code = INTERNAL_ERROR;
            }else if(state == my_hello_unsupported_version){
                hello_proto->code = VERSION_NOT_SUPPORTED;
            }else if (state == my_hello_bad_length){
                hello_proto->code = INVALID_USER;
            }else{
                //Authenticate user
                hello_proto->code = authenticate_admin(hello_proto->my_hello_parser.user, hello_proto->my_hello_parser.password);
//                hello_proto->code = authenticate_user(hello_proto->my_hello_parser.user, hello_proto->my_hello_parser.user_chars_remaining,
//                                        hello_proto->my_hello_parser.password, hello_proto->my_hello_parser.pass_chars_remaining);
            }
            
            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                goto finally;
            }
            // hello_marshall compone la respuesta, segundo campo deberia mandar el codigo de respuesta
            my_hello_marshall(&hello_proto->wb, hello_proto->code);

            // Success here
            returned_state = MY_WRITING_HELLO;

        } else {
            // El hello parser terminó, pero no llegó a un estado final. Tenemos que esperar a que llegue la parte
            // que falta del Hello
        }
    } else {
        goto finally;
    }
    return returned_state;

finally:
    return MY_ERROR_GLOBAL_STATE;
}

static uint8_t
authenticate_admin(uint8_t *user, uint8_t *password) {
    if(is_valid_admin(user, password))
        return VALID_USER;
    return INVALID_USER;
}


unsigned
my_hello_write(struct selector_key *key) {
    struct my_hello_stm *hello_proto = &MY_PROTOCOL_ATTACHMENT(key)->my_hello_state;

    size_t nbytes;
    uint8_t *where_to_read = buffer_read_ptr(&hello_proto->wb, &nbytes);
    ssize_t ret = send(key->fd, where_to_read, nbytes, MSG_NOSIGNAL);

    uint8_t returned_state = MY_WRITING_HELLO; // current state
    if(ret > 0) {
        buffer_read_adv(&hello_proto->wb, nbytes);
        if(!buffer_can_read(&hello_proto->wb)) {
            if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                goto finally;
            }
            if(hello_proto->code == VALID_USER){
                returned_state = MY_READING_REQUEST;
            }else
            {
                returned_state = MY_ERROR_GLOBAL_STATE;
            }
            
        } else {
            // Exit here, and keep waiting for future calls to this function to end reading buffer
        }
    } else {
        goto finally;
    }
    return returned_state;

finally:
    return MY_ERROR_GLOBAL_STATE;
}
