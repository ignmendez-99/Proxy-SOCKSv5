#ifndef STM_REQUEST_H_68f9cbe0499150288c6b905552e201fb15e0b420
#define STM_REQUEST_H_68f9cbe0499150288c6b905552e201fb15e0b420

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "../utils/selector.h"
#include "../parsers/request_parser.h"

struct request_stm {
    struct request_parser request_parser;

    buffer rb; // Exclusive internal buffers used for reading and writing Request
    buffer wb; //
    uint8_t *read_buffer_data; // Where 'rb' will read from
    uint8_t *write_buffer_data; // Where 'wb' will write to

    struct sockaddr_in  origin_addr_ipv4;
    struct sockaddr_in6 origin_addr_ipv6;
    struct addrinfo     *origin_addrinfo;
};

/** inicializa las variables necesarias para operar en este estado READING_REQUEST */
unsigned
request_read_init(const unsigned state, struct selector_key *key);

/** lee el Request del cliente y lo procesa para ver si es válido o no */
unsigned
request_read(struct selector_key *key);

/** Escribe la respuesta al Request al cliente
 *  Si fue una respuesta de error, cierra la conexión.
 */
unsigned
request_write(struct selector_key *key);


#endif
