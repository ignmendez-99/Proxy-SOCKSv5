#ifndef REQUEST_PARSER_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define REQUEST_PARSER_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include "../utils/buffer.h"
#include <stdint.h>

#define PROXY_SOCKS_REQUEST_SUPPORTED_VERSION 0x05
#define PROXY_SOCKS_REQUEST_RESERVED          0x00   // Fields marked RESERVED (RSV) must be set to X'00'.

#define CONNECT_COMMAND 0x01

#define IPv4_LENGTH 4
#define IPv6_LENGTH 16

// Socksv5 reply codes
#define SUCCEDED                          0x00
#define GENERAL_SOCKS_SERVER_FAILURE      0X01
#define CONNECTION_NOT_ALLOWED_BY_RULESET 0x02
#define NETWORK_UNREACHABLE               0x03
#define HOST_UNREACHABLE                  0x04
#define CONNECTION_REFUSED                0x05
#define TTL_EXPIRED                       0x06
#define COMMAND_NOT_SUPPORTED             0x07
#define ADDRESS_TYPE_NOT_SUPPORTED        0x08


// Address Types
#define REQUEST_THROUGH_IPV4 0x01
#define REQUEST_THROUGH_FQDN 0x03
#define REQUEST_THROUGH_IPV6 0x04


// Los posibles estados en los que se puede encontrar el parser de request
enum request_state {
    request_reading_version,
    request_reading_command,
    request_reading_reserved,
    request_reading_address_type,
    request_reading_destination_address,
    request_reading_destination_port,
    request_finished,
    request_has_error
};


struct request_parser {
    enum request_state state;
    int address_type;  // need to store a "-1" to indicate error

    uint8_t *destination_address;
    int destination_address_length;  // need to store a "-1" to indicate error
    ssize_t destination_port;   // must store negative value to represent "first time checking this value"
    uint8_t address_index;  // para ir metiendo los bytes de a uno en 'destination_address'

    uint8_t reply;
};


/** inicializa las variables del parser */
void
request_parser_init(struct request_parser *rp);


/**
 * Dado un buffer, lo consume (lee) hasta que no puede hacerlo más (ya sea porque el buffer no permite leer más, 
 * o porque se llegó al estado 'request_finished')
 * Retorna el estado en que se encuentra el parser al terminar de consumir el buffer.
 */ 
enum request_state
consume_request_buffer(buffer *b, struct request_parser *rp);


/**
 * Parsea un caracter del buffer.
 * Retorna el estado en que se encuentra el parser al terminar de parsear el caracter.
 * 
 * Si devuelve el estado "request_has_error", entonces dejará un struct request_reply* en el campo "request_reply" del request_parser
 * con un código y mensaje de error apropiado.  
 */
enum request_state
parse_single_request_character( uint8_t c, struct request_parser *rp);


/**
 * Deja en el buffer la respuesta al request.
 * También acomoda el puntero Write del buffer para que apunte a donde comienza la respuesta dejada.
 * 
 */
void
request_marshall(buffer *b, struct request_parser *rp);


/** Dependiendo del estado en que se encuentre el request_parser dado, dejará en su parámetro "reply" el número adecuado */
void
getReplyBasedOnState(struct request_parser *rp);


#endif
