#ifndef MY_REQUEST_PARSER_H
#define MY_REQUEST_PARSER_H

#include "../utils/buffer.h"


// #define CONNECT_COMMAND 0x01

// #define IPv4_LENGTH 4
// #define IPv6_LENGTH 16

// #define REQUEST_PARSER_NO_ERROR 0x00

// // Address Types
// #define REQUEST_THROUGH_IPV4 0x01
// #define REQUEST_THROUGH_FQDN 0x03
// #define REQUEST_THROUGH_IPV6 0x04

#define INVALID_COMMAND 0xFF
#define INVALID_PARAM 0xFE


struct my_request_reply {
    uint8_t code;
    uint8_t len;
    const char *data;
};

// Los posibles estados en los que se puede encontrar el parser de request
enum my_request_state {
    my_request_reading_command,
    my_request_reading_n_params,
    my_request_reading_l_param,
    my_request_reading_param,
    my_request_finished,
    my_request_has_error
};

enum my_request_commands {
    get_historical_n_of_connections,
    get_n_of_concurrent_connections,
    get_n_of_bytes_transferred,
    set_buffer_size
};


struct my_request_parser {
    enum my_request_state state;

    uint8_t command;
    uint8_t nparams;
    uint8_t lparam1;
    uint8_t *param1;
    uint8_t lparam2;
    uint8_t *param2;
    uint8_t index;
    uint8_t index2;

    struct my_request_reply reply;
};


/** inicializa las variables del parser */
void
my_request_parser_init(struct my_request_parser *rp);


/**
 * Dado un buffer, lo consume (lee) hasta que no puede hacerlo más (ya sea porque el buffer no permite leer más, 
 * o porque se llegó al estado 'my_request_finished')
 * Retorna el estado en que se encuentra el parser al terminar de consumir el buffer.
 */ 
enum my_request_state
my_consume_request_buffer(buffer *b, struct my_request_parser *rp);


/**
 * Parsea un caracter del buffer.
 * Retorna el estado en que se encuentra el parser al terminar de parsear el caracter.
 * 
 * Si devuelve el estado "my_request_has_error", entonces dejará un struct request_reply* en el campo "request_reply" del request_parser
 * con un código y mensaje de error apropiado.  
 */
enum my_request_state
my_parse_single_request_character( uint8_t c, struct my_request_parser *rp);


/**
 * Deja en el buffer la respuesta al request y retorna 0
 * También acomoda el puntero Write del buffer para que apunte a donde comienza la respuesta dejada.
 * 
 * En caso de que en el buffer no haya suficiente espacio para escribir la respuesta, retorna -1
 */
int
my_request_marshall(buffer *b, struct my_request_parser *rp);


#endif
