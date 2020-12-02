#ifndef MY_HELLO_PARSER_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define MY_HELLO_PARSER_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/buffer.h"

#define SPACE_NEEDED_FOR_HELLO_MARSHALL 2

#define PROTO_HELLO_SUPPORTED_VERSION 0x01

// PROTOCOL CODES
#define VALID_USER                        0x00
#define INVALID_USER                      0x01
#define VERSION_NOT_SUPPORTED             0x02
#define INTERNAL_ERROR                    0x03




// Los posibles estados en los que se puede encontrar el parser de hello
enum my_hello_state {
    my_hello_reading_version,
    my_hello_reading_nuser,
    my_hello_reading_user,
    my_hello_reading_npass,
    my_hello_reading_pass,
    my_hello_bad_length,          // EL password o el username no tienen longitud
    my_hello_finished,            // El mensaje de hello terminó
    my_hello_unsupported_version, // Error leyendo la versión
    my_hello_server_error         // Error general al parsear hello
};

struct my_hello_parser {
    enum my_hello_state state;
    uint8_t user_chars_remaining;
    uint8_t *user;
    uint8_t pass_chars_remaining;
    uint8_t *password;
    uint8_t char_index;  // for advancing in the methods array
};


/** inicializa las variables del parser */
void
my_hello_parser_init(struct my_hello_parser *hp);


/**
 * Dado un buffer, lo consume (lee) hasta que no puede hacerlo más (ya sea porque el buffer no permite leer más,  
 * o porque se llegó al estado 'my_hello_finished')
 * Retorna el estado en que se encuentra el parser al terminar de consumir el buffer.
 */ 
enum my_hello_state
my_consume_hello_buffer(buffer *b, struct my_hello_parser *hp);


/**
 * Parsea un caracter del buffer.
 * Retorna el estado en que se encuentra el parser al terminar de parsear el caracter.
 */
enum my_hello_state
my_parse_single_hello_character(uint8_t c, struct my_hello_parser *hp);


/**
 * Deja en el buffer la respuesta al hello
 * También acomoda el puntero Write del buffer para que apunte a donde comienza la respuesta dejada.
 */
void
my_hello_marshall(buffer *b, uint8_t method);


#endif
