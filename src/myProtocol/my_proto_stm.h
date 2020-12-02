#ifndef MY_PROTOCOL_STM_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define MY_PROTOCOL_STM_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/stm.h"
#include "my_protocol_hello.h"
#include "my_protocol_request.h"


/** Maquina de estados que define cada posible estado de comunicacion entre cliente-servidor **/
enum my_proto_global_state {

    /**
     *  . _Initial state_
     *  .File Descriptor --> only reading from client
     *  .Jump to:
     *      .When finished reading && Hello was well-formed --> MY_WRITING_HELLO (will write a successful hello-reply)
     *      .When error || Hello was malformed  --> MY_ERROR_GLOBAL_STATE
     */
    MY_READING_HELLO,

    /**
     *  .File Descriptor --> only writing to client
     *  .Jump to:
     *      .When finished writing successful hello-reply --> MY_READING_REQUEST
     *      .When error --> MY_ERROR_GLOBAL_STATE
     */
    MY_WRITING_HELLO,

    /**
     *  .File Descriptor --> only reading from client
     *  .Jump to:
     *      .When finished reading Request && Request was well-formed --> MY_WRITING_REQUEST
     *      .When error || Request was malformed --> MY_ERROR_GLOBAL_STATE
     */
    MY_READING_REQUEST,

    /**
     *  . File Descriptor --> only writing to client
     *  . Jump to:
     *      . If Reply was sent successfully --> MY_CLOSE_CONNECTION
     *      . If error --> MY_ERROR_GLOBAL_STATE
     */
    MY_WRITING_REQUEST,

    /**
     *  Closes the client FD and unregister it from the selector.
     *  Frees all resources used for this SCTP connection.
     */
    MY_CLOSE_CONNECTION,

    /**
     *  Closes the client FD and unregister it from the selector.
     *  Frees all resources used for this SCTP connection.
     */
    MY_ERROR_GLOBAL_STATE
};


static const struct state_definition global_states_definition[] = {
    {
        .state          = MY_READING_HELLO,
        .on_arrival     = my_hello_read_init,
        .on_read_ready  = my_hello_read
    },{
        .state          = MY_WRITING_HELLO,
        .on_write_ready = my_hello_write
    },{
        .state          = MY_READING_REQUEST,
        .on_arrival     = my_request_read_init,
        .on_read_ready  = my_request_read
    },{
        .state          = MY_WRITING_REQUEST,
        .on_departure   = my_request_write_close,
        .on_write_ready = my_request_write
    },{
        .state          = MY_CLOSE_CONNECTION
    },{
        .state          = MY_ERROR_GLOBAL_STATE
    }
};


#endif
