#ifndef STM_HELLO_AUTH_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define STM_HELLO_AUTH_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/selector.h"
#include "../parsers/my_hello_parser.h"

#define HELLO_AUTH_SUCCESS 0
#define HELLO_AUTH_FAIL 1



struct hello_auth_stm {
    struct my_hello_parser hello_auth_parser;

    buffer rb; // Exclusive internal buffers used for reading and writing Hello
    buffer wb; ////
    uint8_t *read_buffer_data; // Where 'rb' will read from
    uint8_t *write_buffer_data; // Where 'wb' will write to

    uint8_t reply;  // Authentication method selected by proxy
};


/** inicializa las variables necesarias para operar en este estado HELLO_READ_AUTH */
unsigned
hello_auth_read_init(const unsigned state, struct selector_key *key);

/** lee el pedido de autenticacion del cliente y lo procesa para ver si es posible autenticarlo */
unsigned
hello_auth_read(struct selector_key *key);

/** le escribe al cliente la respuesta a su pedido de autenticacion */
unsigned
hello_auth_write(struct selector_key *key);

#endif
