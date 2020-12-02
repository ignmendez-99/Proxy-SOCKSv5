#ifndef HELLO_PARSER_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define HELLO_PARSER_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include <stdint.h>
#include "../utils/buffer.h"

#define SPACE_NEEDED_FOR_HELLO_MARSHALL 2

#define PROXY_SOCKS_HELLO_SUPPORTED_VERSION 0x05

// SOCKSv5 METHODS
#define NO_AUTHENTICATION_REQUIRED        0x00
#define USERNAME_PASSWORD_AUTHENTICATION  0x02
#define NO_ACCEPTABLE_METHODS             0xFF



// Los posibles estados en los que se puede encontrar el parser de hello
enum hello_state {
    hello_reading_version,
    hello_reading_nmethods,
    hello_reading_methods,
    hello_finished,            // El mensaje de hello terminó
    hello_unsupported_version, // Error leyendo la versión
    hello_server_error         // Error general al parsear hello
};

struct hello_parser {
    enum hello_state state;
    uint8_t methods_remaining;
    uint8_t *methods;
    uint8_t methods_index;  // for advancing in the methods array
};


/** inicializa las variables del parser */
void
hello_parser_init(struct hello_parser *hp);


/**
 * Dado un buffer, lo consume (lee) hasta que no puede hacerlo más (ya sea porque el buffer no permite leer más,  
 * o porque se llegó al estado 'hello_finished')
 * Retorna el estado en que se encuentra el parser al terminar de consumir el buffer.
 */ 
enum hello_state
consume_hello_buffer(buffer *b, struct hello_parser *hp);


/**
 * Parsea un caracter del buffer.
 * Retorna el estado en que se encuentra el parser al terminar de parsear el caracter.
 */
enum hello_state
parse_single_hello_character(uint8_t c, struct hello_parser *hp);


/**
 * Deja en el buffer la respuesta al hello.
 * También acomoda el puntero Write del buffer para que apunte a donde comienza la respuesta dejada.
 * 
 */
void
hello_marshall(buffer *b, uint8_t method);


#endif
