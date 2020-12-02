#ifndef MY_PROTOCOL_SERVER_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define MY_PROTOCOL_SERVER_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/args.h"
#include "../utils/stm.h"
#include "my_protocol_hello.h"
#include "my_protocol_request.h"



struct my_protocol_struct {
    struct my_hello_stm my_hello_state;   // State of the hello for this connection
    struct my_request_stm my_request_state; // State of the request for this connection
    struct state_machine my_stm; // Gestor de máquinas de estado
};

// Util para obtener la estructura de mi protocolo dado una llave de selector
#define MY_PROTOCOL_ATTACHMENT(key) ( (struct my_protocol_struct*)(key)->data)


void my_protocol_passive_accept(struct selector_key *key);


void my_protocol_read(struct selector_key *key);


void my_protocol_write(struct selector_key *key);

void my_protocol_timeout(struct selector_key *key);


static const struct fd_handler my_protocol_active_handler = {
        .handle_read = my_protocol_read,
        .handle_write = my_protocol_write,
        .handle_timeout = my_protocol_timeout
};

#endif
